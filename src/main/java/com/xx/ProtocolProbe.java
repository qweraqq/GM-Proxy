package com.xx;

import io.netty.bootstrap.Bootstrap;
import io.netty.buffer.ByteBuf;
import io.netty.buffer.Unpooled;
import io.netty.channel.Channel;
import io.netty.channel.ChannelFutureListener;
import io.netty.channel.ChannelHandlerContext;
import io.netty.channel.ChannelInboundHandlerAdapter;
import io.netty.channel.ChannelInitializer;
import io.netty.channel.ChannelOption;
import io.netty.channel.EventLoop;
import io.netty.handler.timeout.ReadTimeoutException;
import io.netty.handler.timeout.ReadTimeoutHandler;
import io.netty.util.concurrent.Future;
import io.netty.util.concurrent.Promise;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.net.ssl.SNIHostName;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLEngineResult;
import javax.net.ssl.SSLParameters;
import java.nio.ByteBuffer;
import java.util.Collections;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.TimeUnit;

/**
 * Asks a target server which HTTPS protocol it is able to speak, by sending it
 * real ClientHello messages and looking at what comes back.
 *
 * <p>Two probes are run, in this order:
 * <ol>
 *   <li>a <b>standard TLS</b> ClientHello (TLS 1.2/1.3, RSA + ECDHE suites).
 *       A TLS ServerHello means the server is reachable by the non-GM client
 *       without our help -&gt; {@link UpstreamProtocol#TLS_CAPABLE}, we stop here.</li>
 *   <li>only if the first one was rejected, a <b>TLCP</b> ClientHello
 *       (version 0x0101, SM2/SM4/SM3 suites). A TLCP ServerHello means the
 *       server speaks nothing but 国密 -&gt; {@link UpstreamProtocol#GM_ONLY}.</li>
 * </ol>
 *
 * <p>Both probes are cut short right after the ServerHello: we never complete a
 * handshake, we never validate a certificate, and the socket is dropped
 * immediately. The cost is two TCP connections and one round trip per host:port,
 * once, and the answer is then cached.
 *
 * <p>Tunables (system properties):
 * <ul>
 *   <li>{@code -Dgmproxy.detect.enabled=false} - disable detection entirely</li>
 *   <li>{@code -Dgmproxy.detect.timeout.ms} - per-probe timeout (default 3000)</li>
 *   <li>{@code -Dgmproxy.detect.cache.ttl.ms} - cache lifetime (default 600000)</li>
 * </ul>
 */
public final class ProtocolProbe {

    private static final Logger LOGGER = LoggerFactory.getLogger(ProtocolProbe.class);

    private static final boolean ENABLED =
            !"false".equalsIgnoreCase(System.getProperty("gmproxy.detect.enabled", "true"));

    /** Read timeout of a single probe; a value &lt;= 0 would disable it and hang the CONNECT. */
    private static final int TIMEOUT_MS = Math.max(1, intProperty("gmproxy.detect.timeout.ms", 3000));
    private static final long CACHE_TTL_MS = longProperty("gmproxy.detect.cache.ttl.ms", 600_000L);

    /** Stop buffering a response that we still cannot make sense of. */
    private static final int MAX_SNIFF_BYTES = 512;

    private static final Map<String, CacheEntry> RESOLVED = new ConcurrentHashMap<>();
    private static final Map<String, Promise<UpstreamProtocol>> IN_FLIGHT = new ConcurrentHashMap<>();

    private static volatile SSLContext standardTlsContext;

    private ProtocolProbe() {
    }

    /**
     * Resolves the protocol of {@code host:port}, either from cache, from an
     * already running probe, or by starting a new one.
     *
     * <p>Listeners added to the returned future are <b>always</b> notified on the
     * event loop of {@code origin}, so the caller can touch its own pipeline
     * without any thread hopping - even when several connections to the same host
     * end up sharing one probe.
     *
     * @param origin the client channel; only used to borrow its event loop and
     *               channel implementation, it is never touched by the probe
     */
    @SuppressWarnings("try")
    public static Future<UpstreamProtocol> detect(String host, int port, Channel origin) {
        // EventLoop implements AutoCloseable only because ExecutorService has since
        // Java 19. It is owned by the proxy's worker group, never by us - wrapping
        // it in a try-with-resources would shut the whole worker group down.
        EventLoop loop = origin.eventLoop();
        String key = host + ":" + port;

        if (!ENABLED) {
            return loop.newSucceededFuture(UpstreamProtocol.UNKNOWN);
        }

        CacheEntry cached = RESOLVED.get(key);
        if (cached != null) {
            if (!cached.expired()) {
                return loop.newSucceededFuture(cached.protocol());
            }
            RESOLVED.remove(key);
        }

        // Several parallel CONNECTs to the same host must share one probe. That
        // probe lives on whoever got there first, so hand the caller a promise of
        // its own rather than one that would notify us from a foreign loop.
        Promise<UpstreamProtocol> pending = IN_FLIGHT.get(key);
        if (pending != null) {
            return onCallerLoop(pending, loop);
        }

        Promise<UpstreamProtocol> promise = loop.newPromise();
        IN_FLIGHT.put(key, promise);
        promise.addListener((Future<UpstreamProtocol> f) -> {
            IN_FLIGHT.remove(key);
            UpstreamProtocol result = f.isSuccess() ? f.getNow() : UpstreamProtocol.UNKNOWN;
            if (result.isDefinitive()) {
                RESOLVED.put(key, new CacheEntry(result, System.currentTimeMillis()));
            }
        });

        runProbeSequence(loop, host, port, origin.getClass(), promise);
        return promise;
    }

    /**
     * Mirrors a probe started by somebody else onto the caller's own event loop.
     * Netty notifies the listeners of a promise on the executor it was created
     * with, so a promise handed out by {@code callerLoop} is enough - no manual
     * {@code inEventLoop()} check needed at the call site.
     */
    private static Future<UpstreamProtocol> onCallerLoop(Future<UpstreamProtocol> source, EventLoop callerLoop) {
        Promise<UpstreamProtocol> forwarded = callerLoop.newPromise();
        source.addListener((Future<UpstreamProtocol> f) -> {
            if (f.isSuccess()) {
                forwarded.trySuccess(f.getNow());
            } else {
                forwarded.tryFailure(f.cause() != null ? f.cause() : new IllegalStateException("protocol probe failed"));
            }
        });
        return forwarded;
    }

    /** Drops a cached verdict, e.g. after a server was reconfigured. */
    @SuppressWarnings("unused")
    public static void invalidate(String host, int port) {
        RESOLVED.remove(host + ":" + port);
    }

    // ------------------------------------------------------------------
    // probe orchestration
    // ------------------------------------------------------------------

    private static void runProbeSequence(EventLoop loop, String host, int port,
                                        Class<? extends Channel> channelClass,
                                        Promise<UpstreamProtocol> promise) {
        long startedAt = System.currentTimeMillis();

        byte[] tlsHello = buildClientHello(host, port, false);
        if (tlsHello == null) {
            promise.trySuccess(UpstreamProtocol.UNKNOWN);
            return;
        }

        probeOnce(loop, host, port, channelClass, tlsHello, false)
                .addListener((Future<ProbeOutcome> f) -> {
                    ProbeOutcome standard = outcomeOf(f);
                    if (standard == ProbeOutcome.TLS_SERVER_HELLO) {
                        logVerdict(host, port, UpstreamProtocol.TLS_CAPABLE, startedAt);
                        promise.trySuccess(UpstreamProtocol.TLS_CAPABLE);
                        return;
                    }
                    // Not reachable with standard TLS - is it a GM server?
                    byte[] gmHello = buildClientHello(host, port, true);
                    if (gmHello == null) {
                        promise.trySuccess(UpstreamProtocol.UNKNOWN);
                        return;
                    }
                    probeOnce(loop, host, port, channelClass, gmHello, true)
                            .addListener((Future<ProbeOutcome> g) -> {
                                ProbeOutcome gm = outcomeOf(g);
                                UpstreamProtocol verdict = gm == ProbeOutcome.TLCP_SERVER_HELLO
                                        ? UpstreamProtocol.GM_ONLY
                                        : UpstreamProtocol.UNKNOWN;
                                logVerdict(host, port, verdict, startedAt);
                                promise.trySuccess(verdict);
                            });
                });
    }

    private static void logVerdict(String host, int port, UpstreamProtocol verdict, long startedAt) {
        LOGGER.info("PROTOCOL PROBE {}:{} -> {} ({} ms)", host, port, verdict,
                System.currentTimeMillis() - startedAt);
    }

    private static ProbeOutcome outcomeOf(Future<ProbeOutcome> f) {
        return f.isSuccess() ? f.getNow() : ProbeOutcome.NO_RESPONSE;
    }

    private static Future<ProbeOutcome> probeOnce(EventLoop loop, String host, int port,
                                                  Class<? extends Channel> channelClass,
                                                  byte[] clientHello, boolean gm) {
        Promise<ProbeOutcome> promise = loop.newPromise();

        Bootstrap bootstrap = new Bootstrap()
                .group(loop)
                .channel(channelClass)
                .option(ChannelOption.CONNECT_TIMEOUT_MILLIS, TIMEOUT_MS)
                .handler(new ChannelInitializer<>() {
                    @Override
                    protected void initChannel(Channel ch) {
                        // Kills the probe connection if the server never answers, and
                        // fires a ReadTimeoutException into the handler below.
                        ch.pipeline().addLast(new ReadTimeoutHandler(TIMEOUT_MS, TimeUnit.MILLISECONDS));
                        ch.pipeline().addLast(new ProbeHandler(promise, clientHello, host, port, gm));
                    }
                });

        bootstrap.connect(host, port).addListener((ChannelFutureListener) connect -> {
            if (!connect.isSuccess()) {
                LOGGER.debug("PROBE {}:{} ({}) connect failed: {}", host, port,
                        gm ? "TLCP" : "TLS", connect.cause() == null ? "unknown" : connect.cause().getMessage());
                promise.trySuccess(ProbeOutcome.NO_RESPONSE);
            }
        });

        return promise;
    }

    // ------------------------------------------------------------------
    // ClientHello generation
    // ------------------------------------------------------------------

    /**
     * Lets a real SSLEngine produce the ClientHello for us - far more reliable
     * than hand-writing the bytes, and it stays in sync with whatever the
     * runtime actually supports.
     */
    private static byte[] buildClientHello(String host, int port, boolean gm) {
        try {
            SSLEngine engine = (gm ? gmContext() : standardTlsContext()).createSSLEngine(host, port);
            engine.setUseClientMode(true);
            applySni(engine, host);
            engine.beginHandshake();

            ByteBuffer out = ByteBuffer.allocate(engine.getSession().getPacketBufferSize() + 64);
            ByteBuffer emptyInput = ByteBuffer.allocate(0);
            SSLEngineResult result = engine.wrap(emptyInput, out);
            while (result.getHandshakeStatus() == SSLEngineResult.HandshakeStatus.NEED_TASK) {
                Runnable task;
                while ((task = engine.getDelegatedTask()) != null) {
                    task.run();
                }
                result = engine.wrap(emptyInput, out);
            }

            out.flip();
            byte[] hello = new byte[out.remaining()];
            out.get(hello);
            if (hello.length == 0) {
                LOGGER.warn("PROBE could not build {} ClientHello for {}", gm ? "TLCP" : "TLS", host);
                return null;
            }
            return hello;
        } catch (Exception e) {
            LOGGER.warn("PROBE could not build {} ClientHello for {}: {}", gm ? "TLCP" : "TLS", host, e.getMessage());
            return null;
        }
    }

    private static void applySni(SSLEngine engine, String host) {
        try {
            SSLParameters params = engine.getSSLParameters();
            params.setServerNames(Collections.singletonList(new SNIHostName(host)));
            engine.setSSLParameters(params);
        } catch (Exception ignored) {
            // IP literals and illegal host names simply get no SNI extension.
        }
    }

    private static SSLContext standardTlsContext() throws Exception {
        if (standardTlsContext == null) {
            synchronized (ProtocolProbe.class) {
                if (standardTlsContext == null) {
                    SSLContext ctx = SSLContext.getInstance("TLS");
                    ctx.init(null, null, null);
                    standardTlsContext = ctx;
                }
            }
        }
        return standardTlsContext;
    }

    /**
     * Deliberately the very same TLCP context the MITM upstream uses: if the
     * probe says "GM only", the real upstream handshake is guaranteed to use
     * the same protocol version and cipher suites.
     */
    private static SSLContext gmContext() {
        return NettyTLSProxyNG.PROXY_CLIENT_SSL_CONTEXT;
    }

    // ------------------------------------------------------------------
    // response sniffer
    // ------------------------------------------------------------------

    private enum ProbeOutcome {
        TLS_SERVER_HELLO,
        TLCP_SERVER_HELLO,
        REJECTED,
        NO_RESPONSE
    }

    /**
     * Reads just enough of the answer to know which protocol the server picked,
     * then kills the connection - we never finish a handshake.
     */
    private static final class ProbeHandler extends ChannelInboundHandlerAdapter {

        private final Promise<ProbeOutcome> promise;
        private final byte[] clientHello;
        private final String host;
        private final int port;
        private final boolean gm;

        private ByteBuf accumulator;

        ProbeHandler(Promise<ProbeOutcome> promise, byte[] clientHello, String host, int port, boolean gm) {
            this.promise = promise;
            this.clientHello = clientHello;
            this.host = host;
            this.port = port;
            this.gm = gm;
        }

        @Override
        public void channelActive(ChannelHandlerContext ctx) {
            ctx.writeAndFlush(Unpooled.wrappedBuffer(clientHello));
        }

        @Override
        public void channelRead(ChannelHandlerContext ctx, Object msg) {
            ByteBuf in = (ByteBuf) msg;
            try {
                if (accumulator == null) {
                    accumulator = ctx.alloc().buffer(64);
                }
                accumulator.writeBytes(in);
                byte[] seen = new byte[accumulator.readableBytes()];
                accumulator.getBytes(0, seen);

                ProbeOutcome outcome = classify(seen);
                if (outcome != null) {
                    LOGGER.debug("PROBE {}:{} ({}) -> {}", host, port, label(), outcome);
                    promise.trySuccess(outcome);
                    ctx.close();
                } else if (seen.length >= MAX_SNIFF_BYTES) {
                    promise.trySuccess(ProbeOutcome.NO_RESPONSE);
                    ctx.close();
                }
            } finally {
                in.release();
            }
        }

        @Override
        public void channelInactive(ChannelHandlerContext ctx) {
            promise.trySuccess(ProbeOutcome.NO_RESPONSE);
        }

        @Override
        public void exceptionCaught(ChannelHandlerContext ctx, Throwable cause) {
            if (cause instanceof ReadTimeoutException) {
                LOGGER.debug("PROBE {}:{} ({}) timed out after {} ms", host, port, label(), TIMEOUT_MS);
            } else {
                LOGGER.debug("PROBE {}:{} ({}) failed: {}", host, port, label(), cause.getMessage());
            }
            promise.trySuccess(ProbeOutcome.NO_RESPONSE);
            ctx.close();
        }

        @Override
        public void handlerAdded(ChannelHandlerContext ctx) {
            accumulator = ctx.alloc().buffer(64);
        }

        @Override
        public void handlerRemoved(ChannelHandlerContext ctx) {
            if (accumulator != null && accumulator.refCnt() > 0) {
                accumulator.release();
            }
        }

        private String label() {
            return gm ? "TLCP" : "TLS";
        }

        /**
         * @return the outcome, or {@code null} when more bytes are needed.
         */
        private static ProbeOutcome classify(byte[] b) {
            if (b.length < 5) {
                return null;
            }
            int contentType = b[0] & 0xff;
            if (contentType == 0x15) { // Alert: this protocol is not welcome here
                return ProbeOutcome.REJECTED;
            }
            if (contentType != 0x16) { // Not a TLS record at all (plain HTTP, garbage, ...)
                return ProbeOutcome.NO_RESPONSE;
            }
            if (b.length < 11) { // record header (5) + handshake header (4) + version (2)
                return null;
            }
            if ((b[5] & 0xff) != 0x02) { // Anything but a ServerHello
                return ProbeOutcome.NO_RESPONSE;
            }
            int serverVersion = ((b[9] & 0xff) << 8) | (b[10] & 0xff);
            if (serverVersion == 0x0101) {
                return ProbeOutcome.TLCP_SERVER_HELLO;
            }
            if ((serverVersion >>> 8) == 0x03) { // SSLv3 TLS1.3 (legacy version 0x0303)
                return ProbeOutcome.TLS_SERVER_HELLO;
            }
            return ProbeOutcome.NO_RESPONSE;
        }
    }

    private record CacheEntry(UpstreamProtocol protocol, long createdAt) {

        boolean expired() {
                return CACHE_TTL_MS > 0 && System.currentTimeMillis() - createdAt > CACHE_TTL_MS;
            }
        }

    @SuppressWarnings("all")
    private static int intProperty(String name, int fallback) {
        String raw = System.getProperty(name);
        if (raw == null) {
            return fallback;
        }
        try {
            return Integer.parseInt(raw.trim());
        } catch (NumberFormatException e) {
            LOGGER.warn("Invalid int value for {}: '{}', falling back to {}", name, raw, fallback);
            return fallback;
        }
    }

    @SuppressWarnings("all")
    private static long longProperty(String name, long fallback) {
        String raw = System.getProperty(name);
        if (raw == null) {
            return fallback;
        }
        try {
            return Long.parseLong(raw.trim());
        } catch (NumberFormatException e) {
            LOGGER.warn("Invalid long value for {}: '{}', falling back to {}", name, raw, fallback);
            return fallback;
        }
    }
}
