package com.xx;


import io.netty.bootstrap.Bootstrap;
import io.netty.channel.*;
import io.netty.handler.codec.http.*;
import io.netty.handler.ssl.SslHandler;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLEngine;
import java.net.InetSocketAddress;

import static com.xx.NettyTLSProxyNG.PROXY_SERVER_SSL_CONTEXT;

public class ConnectHandler extends SimpleChannelInboundHandler<FullHttpRequest> {
    private static final Logger LOGGER = LoggerFactory.getLogger(ConnectHandler.class);

    @Override
    protected void channelRead0(ChannelHandlerContext ctx, FullHttpRequest request) {
        if (HttpMethod.CONNECT.equals(request.method())) {
            // Parse the target host and port
            String host = request.uri().split(":")[0];
            int port = Integer.parseInt(request.uri().split(":")[1]);
            LOGGER.info("CLIENT ---> PROXY: CONNECT {}:{}", host, port);
            ctx.channel().config().setAutoRead(false);

            ctx.writeAndFlush(new DefaultFullHttpResponse(HttpVersion.HTTP_1_1, HttpResponseStatus.OK));
            LOGGER.info("PROXY ---> CLIENT: CONNECT {}:{} RESPONSE OK", host, port);

            ctx.pipeline().remove(HttpServerCodec.class);
            ctx.pipeline().remove(HttpObjectAggregator.class);
            ctx.pipeline().remove(ConnectHandler.this);

            if (TrafficSelector.isTarget(host, port)) {
                LOGGER.info("CLIENT <---> TLS MITM PROXY <---> Target-Sever({}:{})", host, port);
                startAffinedPooledHttpsMitm(ctx, host, port);
            } else {
                LOGGER.info("CLIENT <---> FAST PATH <---> Target-Sever({}:{})", host, port);
                startBlindTunnel(ctx, host, port);
            }
        }
    }

    private void startBlindTunnel(ChannelHandlerContext clientCtx, String host, int port) {
        Bootstrap b = new Bootstrap();
        b.group(clientCtx.channel().eventLoop())
                .channel(clientCtx.channel().getClass())
                .handler(new ChannelInitializer<>() {
                    @Override
                    protected void initChannel(Channel ch) {
                        // Intentionally empty init; we add handlers later
                    }
                });

        b.connect(host, port).addListener((ChannelFutureListener) f -> {
            if (f.isSuccess()) {
                Channel remoteChannel = f.channel();
                Channel clientChannel = clientCtx.channel();

                // Just bridge inbound channel & outbound channel for non-targets
                clientChannel.pipeline().addLast(new SimpleBlindRelayHandler(remoteChannel));
                remoteChannel.pipeline().addLast(new SimpleBlindRelayHandler(clientChannel));
                clientCtx.channel().config().setAutoRead(true);
            } else {
                clientCtx.close();
            }
        });
    }


    /*
     *
     *
     */
    private void startAffinedPooledHttpsMitm(ChannelHandlerContext clientCtx, String host, int port) {

        try {
            SSLContext serverContext = PROXY_SERVER_SSL_CONTEXT.computeIfAbsent(host, h -> {
                try {
                    return EccCertCache.getServerContext(h);
                } catch (Exception e) {
                    throw new RuntimeException(e);
                }
            });
            SSLEngine serverEngine = serverContext.createSSLEngine();
            serverEngine.setUseClientMode(false);
            clientCtx.pipeline().addFirst("ssl", new SslHandler(serverEngine));
            clientCtx.pipeline().addAfter("ssl", "codec", new HttpServerCodec());
            AffinedPoolKey key = new AffinedPoolKey(
                    clientCtx.channel().eventLoop(),
                    new InetSocketAddress(host, port));
            clientCtx.pipeline().addLast("smartRelay", new SmartClientToServerRelayHandler(key));
            // clientCtx.pipeline().addAfter("smartRelay", "client-logger", new DebugTraceHandler("CLIENT"));
            clientCtx.fireChannelActive();
        } catch (Exception e) {
            clientCtx.close();
        }


    }


}
