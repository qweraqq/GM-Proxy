package com.xx;

import io.netty.bootstrap.Bootstrap;
import io.netty.channel.*;
import io.netty.handler.codec.http.HttpClientCodec;
import io.netty.handler.ssl.SslHandler;
import io.netty.util.ReferenceCountUtil;
import io.netty.util.concurrent.Future;
import io.netty.util.concurrent.Promise;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.net.ssl.SSLEngine;
import java.util.LinkedList;
import java.util.Queue;

import static com.xx.NettyTLSProxyNG.PROXY_CLIENT_SSL_CONTEXT;

public class ClientToServerHandler extends ChannelInboundHandlerAdapter {
    private static final Logger LOGGER = LoggerFactory.getLogger(ClientToServerHandler.class);
    private Promise<Channel> upstreamPromise;
    private final String host;
    private final int port;

    private final Queue<Object> pendingBuffer = new LinkedList<>();

    public ClientToServerHandler(String host, int port) {
        this.host = host;
        this.port = port;
    }

    @SuppressWarnings("resource")
    private Future<Channel> getOrAcquireUpstream(ChannelHandlerContext ctx) {
        if (upstreamPromise != null) {
            if (upstreamPromise.isDone()) {
                if (upstreamPromise.isSuccess() && upstreamPromise.getNow().isActive()) {
                    return upstreamPromise;
                } else {
                    upstreamPromise = null;
                }
            } else {
                return upstreamPromise;
            }
        }

        upstreamPromise = ctx.executor().newPromise();
        Bootstrap b = new Bootstrap()
                .group(ctx.channel().eventLoop())
                .channel(ctx.channel().getClass())
                .handler(new ChannelInitializer<>() {
                    @Override
                    protected void initChannel(Channel ch) {
                        SSLEngine gmEngine = PROXY_CLIENT_SSL_CONTEXT.createSSLEngine(
                                host,
                                port);
                        gmEngine.setUseClientMode(true);
                        ch.pipeline().addLast("ssl", new SslHandler(gmEngine));
                        ch.pipeline().addLast("codec", new HttpClientCodec());
                    }
                });
        b.connect(host, port).addListener((ChannelFutureListener) f -> {
            if (f.isSuccess()) {
                Channel remoteChannel = f.channel();
                Channel clientChannel = ctx.channel();

                remoteChannel.pipeline().addLast(new ServerToClientHandler(clientChannel));
                upstreamPromise.setSuccess(remoteChannel);
                while (!pendingBuffer.isEmpty()) {
                    remoteChannel.write(pendingBuffer.poll());
                }
                remoteChannel.flush();
                LOGGER.info("Client {} >>> CONNECT >>> Target Server {} ", clientChannel, remoteChannel);
                remoteChannel.config().setAutoRead(true);
                clientChannel.config().setAutoRead(true);

            } else {
                LOGGER.error("Failed to connect to remote server, client channel {}", ctx.channel());
                releasePendingBuffer(ctx);
                ctx.close();
            }
        });
        return upstreamPromise;
    }

    // Helper method to keep your memory safe
    private void safelyBufferMessage(ChannelHandlerContext ctx, Object msg) {
        if (pendingBuffer.size() >= 10) { // High-Water Mark
            LOGGER.warn("Buffer is full on {}, Force close it", ctx.channel());
            ReferenceCountUtil.release(msg);
            releasePendingBuffer(ctx);
            ctx.close(); // The client is sending too much while upstream is down
            return;
        }
        pendingBuffer.add(msg);
    }

    @Override
    public void channelInactive(ChannelHandlerContext ctx) {
        ctx.close();
        releasePendingBuffer(ctx);
        if (upstreamPromise != null) {
            if (upstreamPromise.isDone()) {
                if (upstreamPromise.isSuccess() && upstreamPromise.getNow().isActive()) {
                    Utils.closeOnFlush(upstreamPromise.getNow());
                }
            }
        }
        ctx.fireChannelInactive();
    }


    @Override
    public void channelRead(ChannelHandlerContext ctx, Object msg) {
        Future<Channel> future = getOrAcquireUpstream(ctx);

        if (future.isSuccess()) {
            // FAST PATH: Upstream is connected. Write and flush immediately.
            future.getNow().writeAndFlush(msg);
            LOGGER.info("Client {} >>> FORWARDING >>> Target Server {} ", ctx.channel(), future.getNow());
        } else if (future.isDone()) {
            // PENDING PATH: Connection is in flight.
            safelyBufferMessage(ctx, msg);
        } else {
            // The previous promise is dead. Calling this again forces a
            // brand-new connection attempt to flush our newly cached message.
            safelyBufferMessage(ctx, msg);
            getOrAcquireUpstream(ctx);
        }

    }


    private void releasePendingBuffer(ChannelHandlerContext ctx) {
        if (! pendingBuffer.isEmpty()) {
            LOGGER.info("Releasing pending buffer (size {}) on channel {}", pendingBuffer.size(), ctx.channel());
        }
        while (!pendingBuffer.isEmpty()) {
            ReferenceCountUtil.release(pendingBuffer.poll());
        }
    }


    @Override
    public void channelWritabilityChanged(ChannelHandlerContext ctx) throws Exception {
        super.channelWritabilityChanged(ctx);
        if (ctx.channel().isWritable()) {
            if (upstreamPromise != null) {
                if (upstreamPromise.isDone()) {
                    if (upstreamPromise.isSuccess() && upstreamPromise.getNow().isActive()) {
                        upstreamPromise.getNow().config().setAutoRead(true);
                    }
                }
            }
        }
        ctx.fireChannelWritabilityChanged();
    }

    @Override
    public void exceptionCaught(ChannelHandlerContext ctx, Throwable ignored) {
        LOGGER.info("Client to Server Channel Exception {}", ctx.channel());
        releasePendingBuffer(ctx);
        Utils.closeOnFlush(ctx.channel());
        if (upstreamPromise != null) {
            if (upstreamPromise.isDone()) {
                if (upstreamPromise.isSuccess() && upstreamPromise.getNow().isActive()) {
                    Utils.closeOnFlush(upstreamPromise.getNow());
                }
            }
        }

    }
}
