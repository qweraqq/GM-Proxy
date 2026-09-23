package com.xx;


import io.netty.bootstrap.Bootstrap;
import io.netty.channel.*;
import io.netty.handler.codec.http.*;
import io.netty.handler.ssl.SslHandler;
import io.netty.util.concurrent.Future;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLEngine;

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

            // Ask the server which HTTPS protocol it speaks before touching the
            // pipeline: a throwaway connection gets a standard-TLS ClientHello and,
            // only if that is rejected, a TLCP one. The answer is cached per
            // host:port. Inbound reads stay switched off meanwhile, so not a single
            // client byte is lost or forwarded before we know what to do with it.
            ProtocolProbe.detect(host, port, ctx.channel())
                    .addListener((Future<UpstreamProtocol> f) -> {
                        UpstreamProtocol protocol = f.isSuccess() ? f.getNow() : UpstreamProtocol.UNKNOWN;
                        if (protocol == UpstreamProtocol.UNKNOWN) {
                            LOGGER.warn("PROBE {}:{}: inconclusive, relaying - the server is either "
                                    + "unreachable or refused both ClientHellos", host, port);
                        }
                        assemble(ctx, host, port, protocol);
                    });
        } else {
            // --- PLAIN HTTP TRAFFIC ---
            String host = request.headers().get(HttpHeaderNames.HOST);
            int port = 80;

            if (host != null && host.contains(":")) {
                String[] parts = host.split(":");
                host = parts[0];
                port = Integer.parseInt(parts[1]);
            } else if (host == null) {
                // Fallback if Host header is missing
                java.net.URI uri = java.net.URI.create(request.uri());
                host = uri.getHost();
                port = uri.getPort() == -1 ? 80 : uri.getPort();
            }

            LOGGER.info("CLIENT ---> PROXY: HTTP {} {}:{}", request.method(), host, port);
            ctx.channel().config().setAutoRead(false);

            ctx.pipeline().remove(HttpServerCodec.class);
            ctx.pipeline().remove(HttpObjectAggregator.class);
            ctx.pipeline().remove(ConnectHandler.this);

            // Retain the request so SimpleChannelInboundHandler doesn't destroy it
            request.retain();

            // Forward it to the blind tunnel
            LOGGER.info("CLIENT <---> HTTP FAST PATH <---> Target-Sever({}:{})", host, port);
            startBlindTunnel(ctx, host, port, request);
        }
    }

    /**
     * MITM if and only if the server speaks nothing but 国密; everything else -
     * including an inconclusive probe - keeps the existing blind relay.
     *
     * <p>{@link ProtocolProbe#detect} notifies its listeners on the event loop of
     * the channel we handed it, so the pipeline can be modified right here.
     */
    private void assemble(ChannelHandlerContext ctx, String host, int port, UpstreamProtocol protocol) {
        if (!ctx.channel().isActive()) {
            LOGGER.info("Client is gone while probing {}:{}, aborting", host, port);
            return;
        }
        if (protocol == UpstreamProtocol.GM_ONLY) {
            LOGGER.info("CLIENT <---> TLS MITM PROXY <---> Target-Sever({}:{}) [{}]", host, port, protocol);
            startMitmTunnel(ctx, host, port);
        } else {
            LOGGER.info("CLIENT <---> TLS FAST PATH <---> Target-Sever({}:{}) [{}]", host, port, protocol);
            startBlindTunnel(ctx, host, port, null);
        }
    }

    private void startMitmTunnel(ChannelHandlerContext clientCtx, String host, int port) {
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
        clientCtx.pipeline().addLast("codec", new HttpServerCodec());
        clientCtx.pipeline().addLast( new ClientToServerHandler(host, port));
        clientCtx.channel().config().setAutoRead(true);

    }

    private void startBlindTunnel(ChannelHandlerContext clientCtx, String host, int port, FullHttpRequest initialRequest) {
        Bootstrap b = new Bootstrap();
        b.group(clientCtx.channel().eventLoop())
                .channel(clientCtx.channel().getClass())
                .handler(new ChannelInitializer<>() {
                    @Override
                    protected void initChannel(Channel ch) {
                        // If we have an initial HTTP request to send, we need an encoder temporarily
                        if (initialRequest != null) {
                            ch.pipeline().addLast(new HttpRequestEncoder());
                        }
                    }
                });

        b.connect(host, port).addListener((ChannelFutureListener) f -> {
            if (f.isSuccess()) {
                Channel remoteChannel = f.channel();
                Channel clientChannel = clientCtx.channel();

                // Just bridge inbound channel & outbound channel for non-targets
                clientChannel.pipeline().addLast(new SimpleBlindRelayHandler(remoteChannel));
                remoteChannel.pipeline().addLast(new SimpleBlindRelayHandler(clientChannel));

                if (initialRequest != null) {
                    // Send the swallowed HTTP request to the target
                    remoteChannel.writeAndFlush(initialRequest).addListener(writeF -> {
                        // Remove the encoder so it becomes a raw byte pipe
                        remoteChannel.pipeline().remove(HttpRequestEncoder.class);
                        clientCtx.channel().config().setAutoRead(true);
                    });
                } else {
                    // CONNECT mode: just open the floodgates
                    clientCtx.channel().config().setAutoRead(true);
                }

            } else {
                if (initialRequest != null) {
                    initialRequest.release();
                }
                clientCtx.close();
            }
        });
    }




    @Override
    public void exceptionCaught(ChannelHandlerContext ctx, Throwable cause) {
        // seems NOT matters
        // JUST make silent
    }

}
