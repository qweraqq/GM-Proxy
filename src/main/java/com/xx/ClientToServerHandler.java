package com.xx;

import io.netty.bootstrap.Bootstrap;
import io.netty.buffer.Unpooled;
import io.netty.channel.*;
import io.netty.handler.codec.http.HttpClientCodec;
import io.netty.handler.ssl.SslHandler;
import io.netty.util.ReferenceCountUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.net.ssl.SSLEngine;
import java.util.LinkedList;
import java.util.Queue;
import java.util.concurrent.atomic.AtomicBoolean;

import static com.xx.NettyTLSProxyNG.PROXY_CLIENT_SSL_CONTEXT;

public class ClientToServerHandler extends ChannelInboundHandlerAdapter {
    private static final Logger LOGGER = LoggerFactory.getLogger(ClientToServerHandler.class);
    private Channel upstream;
    private final String host;
    private final int port;

    private final AtomicBoolean upstreamAcquired = new AtomicBoolean(false);
    private final Queue<Object> pendingBuffer = new LinkedList<>();

    public ClientToServerHandler(String host, int port) {
        this.host = host;
        this.port = port;
    }

    @Override
    public void channelInactive(ChannelHandlerContext ctx) {
        releasePendingBuffer(ctx);
        ctx.close();
        if (upstream != null && upstream.isActive()) {
            upstream.writeAndFlush(Unpooled.EMPTY_BUFFER).addListener(ChannelFutureListener.CLOSE);
        }
    }


    @Override
    public void channelRead(ChannelHandlerContext ctx, Object msg) {
        if (upstream != null && upstream.isActive()) {
            LOGGER.info("CLIENT {} >>> FORWARDING >>> Target-Server {} ", ctx.channel(), upstream);
            upstream.writeAndFlush(msg).addListener(ChannelFutureListener.FIRE_EXCEPTION_ON_FAILURE);
            // FLOW CONTROL
            if (!upstream.isWritable()) {
                ctx.channel().config().setAutoRead(false);
            }
        } else {
            // just record msg when upstream is not ready
            synchronized (pendingBuffer) {
                pendingBuffer.add(msg);
            }

            // upstream will be acquired only once
            if (upstreamAcquired.compareAndSet(false, true)) {
                acquireUpstream(ctx);
            }
        }
    }

    private void acquireUpstream(ChannelHandlerContext ctx) {
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
                this.upstream = remoteChannel;
                flushPendingBufferToUpstream(ctx);
                remoteChannel.config().setAutoRead(true);
                clientChannel.config().setAutoRead(true);
            } else {
                LOGGER.error("Failed to connect to remote server, client channel {}", ctx.channel());
                releasePendingBuffer(ctx);
                ctx.close();
            }
        });

    }

    private void flushPendingBufferToUpstream(ChannelHandlerContext ctx) {
        LOGGER.info("Pending size {}, upstream {}, upstream active {}", pendingBuffer.size(), upstream, upstream.isActive());
        if (upstream != null && upstream.isActive()) {
            synchronized (pendingBuffer) {
                while (!pendingBuffer.isEmpty()) {
                    upstream.writeAndFlush(pendingBuffer.poll()).addListener(ChannelFutureListener.FIRE_EXCEPTION_ON_FAILURE);
                    if (!upstream.isWritable()) {
                        ctx.channel().config().setAutoRead(false);
                    }
                }
            }
        } else {
            // upstream not ready? / upstream error ?
            // should not happen, just in case
            LOGGER.error("Flush pending buffer to upstream failed, upstream {}", upstream);
            releasePendingBuffer(ctx);
            ctx.close();
            if(upstream != null ) {
                upstream.close();
            }
        }
    }

    private void releasePendingBuffer(ChannelHandlerContext ctx) {
        synchronized (pendingBuffer) {
            LOGGER.info("Releasing pending buffer (size {}) on channel {}", pendingBuffer.size(), ctx.channel());
            while (!pendingBuffer.isEmpty()) {
                ReferenceCountUtil.release(pendingBuffer.poll());
            }
        }
    }


    @Override
    public void channelWritabilityChanged(ChannelHandlerContext ctx) throws Exception {
        super.channelWritabilityChanged(ctx);
        if (ctx.channel().isWritable() && upstream != null && upstream.isActive()) {
            upstream.config().setAutoRead(true);
        }
        ctx.fireChannelWritabilityChanged();
    }

    @Override
    public void exceptionCaught(ChannelHandlerContext ctx, Throwable cause) {
        LOGGER.info("Client to Server Channel Exception", cause);
        releasePendingBuffer(ctx);
        ctx.close();
        if(upstream != null ) {
            upstream.close();
        }

    }
}
