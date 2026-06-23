package com.xx;

import com.tencent.kona.crypto.KonaCryptoProvider;
import com.tencent.kona.pkix.KonaPKIXProvider;
import com.tencent.kona.ssl.KonaSSLProvider;
import io.netty.bootstrap.ServerBootstrap;
import io.netty.buffer.PooledByteBufAllocator;
import io.netty.channel.*;
import io.netty.channel.nio.NioIoHandler;
import io.netty.channel.pool.*;
import io.netty.channel.socket.SocketChannel;
import io.netty.channel.socket.nio.NioServerSocketChannel;
import io.netty.handler.codec.http.HttpObjectAggregator;
import io.netty.handler.codec.http.HttpServerCodec;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.TrustManager;
import java.net.InetSocketAddress;
import java.security.Security;
import java.util.concurrent.ConcurrentHashMap;


public class NettyTLSProxyNG {
    private static final Logger LOGGER = LoggerFactory.getLogger(NettyTLSProxyNG.class);

    private static String BIND_HOST = "127.0.0.1";
    private static int BIND_PORT = 8081;

    // Client <---> Proxy
    public static SSLContext PROXY_CLIENT_SSL_CONTEXT;

    // Proxy <---> Server
    public static final ConcurrentHashMap<String, SSLContext> PROXY_SERVER_SSL_CONTEXT = new ConcurrentHashMap<>();


    public static void main(String[] args) {
        parseArgs(args);
        try (
                EventLoopGroup bossGroup = new MultiThreadIoEventLoopGroup(1, NioIoHandler.newFactory());
                EventLoopGroup workerGroup = new MultiThreadIoEventLoopGroup(0, NioIoHandler.newFactory())
        ) {
            initGlobalSslContext();
            ServerBootstrap b = new ServerBootstrap()
                    .group(bossGroup, workerGroup)
                    .channel(NioServerSocketChannel.class)
                    .option(ChannelOption.ALLOCATOR, PooledByteBufAllocator.DEFAULT)
                    .childOption(ChannelOption.ALLOCATOR, PooledByteBufAllocator.DEFAULT)
                    .childHandler(new ChannelInitializer<SocketChannel>() {
                        @Override
                        protected void initChannel(SocketChannel ch) {
                            ChannelPipeline p = ch.pipeline();
                            p.addLast(new HttpServerCodec());
                            p.addLast(new HttpObjectAggregator(1 << 20));
                            p.addLast(new ConnectHandler());
                        }

                    });
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



}
