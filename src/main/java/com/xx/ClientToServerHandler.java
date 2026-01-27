package com.xx;

import io.netty.bootstrap.Bootstrap;
import io.netty.buffer.Unpooled;
import io.netty.channel.*;
import io.netty.handler.ssl.SslHandler;
import io.netty.util.ReferenceCountUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.net.ssl.SSLEngine;
import java.util.LinkedList;
import java.util.Queue;
import java.util.concurrent.locks.Lock;
import java.util.concurrent.locks.ReentrantLock;

import static com.xx.NettyTLSProxyNG.PROXY_CLIENT_SSL_CONTEXT;

public class ClientToServerHandler extends ChannelInboundHandlerAdapter {
    private static final Logger LOGGER = LoggerFactory.getLogger(ClientToServerHandler.class);
    private Channel upstream;
    private String host;
    private int port;

    private final Lock lock = new ReentrantLock();
    private volatile boolean isAcquiring = false;
    private final Queue<Object> pendingBuffer = new LinkedList<>();

    public ClientToServerHandler(String host, int port) {
        this.host = host;
        this.port = port;
    }


    /**
     * Calls {@link ChannelHandlerContext#fireChannelActive()} to forward
     * to the next {@link ChannelInboundHandler} in the {@link ChannelPipeline}.
     * <p>
     * Sub-classes may override this method to change behavior.
     *
     * @param ctx
     */
    @Override
    public void channelActive(ChannelHandlerContext ctx) throws Exception {
        super.channelActive(ctx);
    }

    /**
     * Calls {@link ChannelHandlerContext#fireChannelInactive()} to forward
     * to the next {@link ChannelInboundHandler} in the {@link ChannelPipeline}.
     * <p>
     * Sub-classes may override this method to change behavior.
     *
     * @param ctx
     */
    @Override
    public void channelInactive(ChannelHandlerContext ctx) throws Exception {
        releasePendingBuffer();
        ctx.close();
        if (upstream != null && upstream.isActive()) {
            upstream.writeAndFlush(Unpooled.EMPTY_BUFFER).addListener(ChannelFutureListener.CLOSE);
        }
    }

    /**
     * Calls {@link ChannelHandlerContext#fireChannelRead(Object)} to forward
     * to the next {@link ChannelInboundHandler} in the {@link ChannelPipeline}.
     * <p>
     * Sub-classes may override this method to change behavior.
     *
     * @param ctx
     * @param msg
     */
    @Override
    public void channelRead(ChannelHandlerContext ctx, Object msg) throws Exception {
        if (upstream != null && upstream.isActive()) {
            upstream.writeAndFlush(msg);
            // FLOW CONTROL
            if (!upstream.isWritable()) {
                ctx.channel().config().setAutoRead(false);
            }
        } else {
            // just record msg when upstream is not ready
            lock.lock();
            try {
                pendingBuffer.add(msg);
            } finally {
                lock.unlock();
            }

            if (! this.isAcquiring) {
                this.isAcquiring = true;
                acquireUpstream(ctx);
            }
        }
    }

    private void acquireUpstream(ChannelHandlerContext ctx) {
        Bootstrap b = new Bootstrap()
                .group(ctx.channel().eventLoop())
                .channel(ctx.channel().getClass())
                .option(ChannelOption.TCP_NODELAY, true)
                .option(ChannelOption.SO_KEEPALIVE, true)
                .handler(new ChannelInitializer<>() {
                    @Override
                    protected void initChannel(Channel ch) throws Exception {
                        SSLEngine gmEngine = PROXY_CLIENT_SSL_CONTEXT.createSSLEngine(
                                host,
                                port);
                        gmEngine.setUseClientMode(true);
                        ch.pipeline().addLast("ssl", new SslHandler(gmEngine));
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
                releasePendingBuffer();
                ctx.close();
            }
        });

    }

    private void flushPendingBufferToUpstream(ChannelHandlerContext ctx) {
        lock.lock();
        LOGGER.info("Pending size {}, upstream {}, upstream active {}", pendingBuffer.size(), upstream, upstream.isActive());
        try {
            if (upstream != null && upstream.isActive()) {
                for (Object m : pendingBuffer) {
                    upstream.writeAndFlush(m);
                    // FLOW CONTROL
                    if (!upstream.isWritable()) {
                        ctx.channel().config().setAutoRead(false);
                    }
                }
            }
            pendingBuffer.clear();
        } finally {
            lock.unlock();
        }
    }

    private void releasePendingBuffer() {
        lock.lock();
        try {
            for (Object msg : pendingBuffer) ReferenceCountUtil.release(msg);
            pendingBuffer.clear();
        } finally {
            lock.unlock();
        }
    }


    /**
     * Calls {@link ChannelHandlerContext#fireChannelWritabilityChanged()} to forward
     * to the next {@link ChannelInboundHandler} in the {@link ChannelPipeline}.
     * <p>
     * Sub-classes may override this method to change behavior.
     *
     * @param ctx
     */
    @Override
    public void channelWritabilityChanged(ChannelHandlerContext ctx) throws Exception {
        super.channelWritabilityChanged(ctx);
        if (ctx.channel().isWritable() && upstream != null && upstream.isActive()) {
            upstream.config().setAutoRead(true);
        }
        ctx.fireChannelWritabilityChanged();
    }

    /**
     * Calls {@link ChannelHandlerContext#fireExceptionCaught(Throwable)} to forward
     * to the next {@link ChannelHandler} in the {@link ChannelPipeline}.
     * <p>
     * Sub-classes may override this method to change behavior.
     *
     * @param ctx
     * @param cause
     */
    @Override
    public void exceptionCaught(ChannelHandlerContext ctx, Throwable cause) throws Exception {
        releasePendingBuffer();
        ctx.close();
        if(upstream != null ) {
            upstream.close();
        }

    }
}
