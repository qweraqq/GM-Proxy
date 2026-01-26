package com.xx;

import com.tencent.kona.crypto.KonaCryptoProvider;
import com.tencent.kona.pkix.KonaPKIXProvider;
import com.tencent.kona.ssl.KonaSSLProvider;
import io.netty.bootstrap.Bootstrap;
import io.netty.bootstrap.ServerBootstrap;
import io.netty.buffer.PooledByteBufAllocator;
import io.netty.channel.*;
import io.netty.channel.nio.NioIoHandler;
import io.netty.channel.pool.*;
import io.netty.channel.socket.nio.NioServerSocketChannel;
import io.netty.channel.socket.nio.NioSocketChannel;
import io.netty.handler.codec.http.HttpClientCodec;
import io.netty.handler.ssl.SslHandler;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.TrustManager;
import java.net.InetSocketAddress;
import java.security.Security;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicBoolean;


public class NettyTLSProxyNG {
    private static final Logger LOGGER = LoggerFactory.getLogger(NettyTLSProxyNG.class);

    private static String BIND_HOST = "127.0.0.1";
    private static int BIND_PORT = 8081;

    // Client <---> Proxy
    public static SSLContext PROXY_CLIENT_SSL_CONTEXT;

    // Proxy <---> Server
    public static AbstractChannelPoolMap<AffinedPoolKey, SimpleChannelPool> UPSTREAM_POOL_MAP;
    public static final ConcurrentHashMap<String, SSLContext> PROXY_SERVER_SSL_CONTEXT = new ConcurrentHashMap<>();


    public static void main(String[] args) {
        parseArgs(args);
        try (
                EventLoopGroup bossGroup = new MultiThreadIoEventLoopGroup(1, NioIoHandler.newFactory());
                EventLoopGroup workerGroup = new MultiThreadIoEventLoopGroup(0, NioIoHandler.newFactory())
        ) {
            initGlobalSslContext();
            initPoolMap();
            ServerBootstrap b = new ServerBootstrap()
                    .group(bossGroup, workerGroup)
                    .channel(NioServerSocketChannel.class)
                    .option(ChannelOption.ALLOCATOR, PooledByteBufAllocator.DEFAULT)
                    .childOption(ChannelOption.SO_KEEPALIVE, true) // 开启TCP心跳
                    .childOption(ChannelOption.TCP_NODELAY, true)  // 关闭Nagle算法，降低延迟
                    .childOption(ChannelOption.ALLOCATOR, PooledByteBufAllocator.DEFAULT)
                    .childHandler(new FrontendInitializer());
            LOGGER.info("=== TLS MITM PROXY listening on {}:{} ===", BIND_HOST, BIND_PORT);
            b.bind(new InetSocketAddress(BIND_HOST, BIND_PORT)).sync().channel().closeFuture().sync();

        } catch (Exception e) {
            LOGGER.error("TLS MITM PROXY failed to start on {}:{} with error: {}", BIND_HOST, BIND_PORT, e.getMessage());
        }
    }

    private static void parseArgs(String[] args) {
        if (args.length > 0) BIND_HOST = args[0];
        if (args.length > 1) try {
            BIND_PORT = Integer.parseInt(args[1]);
        } catch (Exception ignored) {
        }
    }

    private static void initGlobalSslContext() throws Exception {
        Security.addProvider(new KonaCryptoProvider());
        Security.addProvider(new KonaPKIXProvider());
        Security.addProvider(new KonaSSLProvider());
        java.security.SecureRandom fastRandom = java.security.SecureRandom.getInstance("SHA1PRNG");
        fastRandom.setSeed(System.currentTimeMillis());
        // TLSv1.2, which represents only TLS 1.2 is supported.
        // TLSv1.3, which represents only TLS 1.3 is supported.
        // TLS, which represents TLS 1.3 and TLS 1.2 are supported.
        // TLCPv1.1, which represents only TLCP 1.1 is supported.
        // TLCP, which represents TLCP 1.1, TLS 1.3 and TLS 1.2 are supported.
        PROXY_CLIENT_SSL_CONTEXT = SSLContext.getInstance("TLCPv1.1", "KonaSSL");
        PROXY_CLIENT_SSL_CONTEXT.init(
                null,
                new TrustManager[]{new Utils.TrustAllManager()},
                fastRandom);

        // warmup for CLIENT_SSL_CONTEXT
        java.security.SecureRandom.getInstanceStrong().nextBytes(new byte[64]);
        SSLEngine engine = PROXY_CLIENT_SSL_CONTEXT.createSSLEngine();

        // warmup for SERVER_SSL_CONTEXT
        engine.setUseClientMode(true);
        engine.beginHandshake();
        for (String host : TrafficSelector.getHosts()) {
            LOGGER.info("Generating self-signed certificate for host {}", host);
            EccCertCache.getServerContext(host);
        }

    }


    private static void initPoolMap() {
        UPSTREAM_POOL_MAP = new AbstractChannelPoolMap<>() {
            @Override
            protected SimpleChannelPool newPool(AffinedPoolKey key) {
                // FORCE the Bootstrap to use the key's EventLoop
                // This ensures Inbound and Outbound traffic stay on the SAME thread.
                Bootstrap b = new Bootstrap()
                        .group(key.eventLoop())
                        .channel(NioSocketChannel.class)
                        .option(ChannelOption.TCP_NODELAY, true)
                        .option(ChannelOption.SO_KEEPALIVE, true) // Keep socket open!
                        .remoteAddress(key.address());


                return new FixedChannelPool(b, new AbstractChannelPoolHandler() {
                    @Override
                    public void channelCreated(Channel ch) {
                        // GM Handshake (Once per physical connection)
                        SSLEngine gmEngine = PROXY_CLIENT_SSL_CONTEXT.createSSLEngine(
                                key.address().getHostString(),
                                key.address().getPort());
                        gmEngine.setUseClientMode(true);
                        ch.pipeline().addLast("ssl", new SslHandler(gmEngine));

                        // HTTP Codec (Needed for Header Rewriting)
                        ch.pipeline().addLast("codec", new HttpClientCodec());

                        ch.attr(Magic.RELEASE_GUARD).set(new AtomicBoolean(true));
                        LOGGER.info("PROXY <---> Target-Server({}) channel {} created", key.address(), ch);
                    }

                    @Override
                    public void channelAcquired(Channel ch) {
                        // Mark as "Leased"
                        ch.attr(Magic.RELEASE_GUARD).get().set(false);

                        // Remove the "Idle Guard" (The Alarm)
                        // When the connection was sitting in the pool, it had a "PoolCleanerHandler"
                        // watching for garbage data. We must remove this, otherwise valid
                        // response data from the server would be detected as garbage and killed.
                        if (ch.pipeline().get(PoolCleanerHandler.class) != null) {
                            ch.pipeline().remove(PoolCleanerHandler.class);
                        }

                        if (ch.pipeline().get(DebugTraceHandler.class) != null)
                            ch.pipeline().remove(DebugTraceHandler.class);

                        // ch.pipeline().addAfter("codec", "logger", new DebugTraceHandler("UPSTREAM-" + ch.id().asShortText()));

                        // Wake up
                        ch.config().setAutoRead(true);
                        ch.flush();
                        LOGGER.info("PROXY <---> Target-Server({}) channel {} acquired", key.address(), ch);
                    }

                    @Override
                    public void channelReleased(Channel ch) {
                        // Ensure the socket is listening so the Cleaner can actually hear the garbage.
                        ch.config().setAutoRead(true);
                        LOGGER.info("PROXY <---> Target-Server({}) channel {} released", key.address(), ch);
                    }
                },
                        ChannelHealthChecker.ACTIVE,
                        FixedChannelPool.AcquireTimeoutAction.FAIL,
                        2000,
                        10,  // Lower limit per-thread (10 * Cores = Total Capacity)
                        200);
            }
        };
    }


}
