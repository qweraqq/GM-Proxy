package com.xx;

import io.netty.channel.*;
import io.netty.channel.pool.SimpleChannelPool;
import io.netty.util.ReferenceCountUtil;
import io.netty.util.concurrent.FutureListener;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.LinkedList;
import java.util.Queue;

import static com.xx.NettyTLSProxyNG.UPSTREAM_POOL_MAP;

public class SmartClientToServerRelayHandler extends ChannelInboundHandlerAdapter {
    Logger LOGGER = LoggerFactory.getLogger(SmartClientToServerRelayHandler.class);
    private final AffinedPoolKey poolKey;
    private Channel upstream;
    private final Queue<Object> pendingBuffer = new LinkedList<>();
    private boolean isAcquiring = false;

    public SmartClientToServerRelayHandler(AffinedPoolKey poolKey) {
        this.poolKey = poolKey;
    }

    @Override
    public void channelRead(ChannelHandlerContext ctx, Object msg) {
        // Upstream connected case -> just forward
        if (upstream != null && upstream.isActive()) {
            LOGGER.info("CLIENT {} >>> FORWARDING >>> Target-Server {} ", ctx.channel(), upstream);
            upstream.writeAndFlush(msg).addListener(ChannelFutureListener.FIRE_EXCEPTION_ON_FAILURE);
            // FLOW CONTROL
            if (!upstream.isWritable()) {
                ctx.channel().config().setAutoRead(false);
            }
            return;
        } else {
            this.upstream = null;
            this.isAcquiring = false;
        }

        LOGGER.info("PRXOY <---> Target-Server channel null:, Buffering msg & Acquiring new channel");

        // Scenario: Disconnected (Between requests).
        // 1. Buffer the message (Don't lose the "GET /")
        pendingBuffer.add(msg);

        // 2. Start Acquisition (if not already running)
        if (!isAcquiring) {
            isAcquiring = true;
            acquireUpstream(ctx);
        }
    }

    private void acquireUpstream(ChannelHandlerContext ctx) {
        SimpleChannelPool pool = UPSTREAM_POOL_MAP.get(poolKey);

        pool.acquire().addListener((FutureListener<Channel>) f -> {
            if (f.isSuccess()) {
                Channel newUpstream = f.getNow();
                this.upstream = newUpstream;
                this.isAcquiring = false;

                LOGGER.info("New PROXY <---> Target-Server channel acquired {}", newUpstream);
                // Setup Upstream Pipeline (The Bridge Back)
                setupUpstreamPipeline(ctx.channel(), newUpstream, pool);

                // FLUSH BUFFER
                for (Object msg : pendingBuffer) {
                    newUpstream.writeAndFlush(msg);
                }
                pendingBuffer.clear();

                // Resume AutoRead just in case
                ctx.channel().config().setAutoRead(true);
            } else {
                // Close everything if failed
                ctx.close();
                releaseBuffer();
            }
        });
    }

    // Helper: Configure the Upstream Channel (reading FROM Baidu)
    private void setupUpstreamPipeline(Channel client, Channel upstream, SimpleChannelPool pool) {
        upstream.attr(Magic.POOL_REF).set(pool);
        upstream.closeFuture().addListener(cf -> Utils.safeRelease(upstream));

        // Clean old handlers (Crucial for reuse)
        ChannelPipeline p = upstream.pipeline();
        if (p.get(HeaderRewriteHandler.class) != null) p.remove(HeaderRewriteHandler.class);
        if (p.get(ProxyToClientRelayHandler.class) != null) p.remove(ProxyToClientRelayHandler.class);

        // Add new handlers
        p.addLast(new HeaderRewriteHandler());

        // This handler reads FROM Remote and writes to Client
        p.addLast(new ProxyToClientRelayHandler(client));

        upstream.config().setAutoRead(true);
    }

    public void detachUpstream() {
        if (this.upstream != null) {
            LOGGER.info("CLIENT <---> PROXY channel STATE RESET: Detaching Upstream {} (Transaction Done)", this.upstream);
        }
        this.upstream = null;
        this.isAcquiring = false;
    }

    private void releaseBuffer() {
        for (Object msg : pendingBuffer) ReferenceCountUtil.release(msg);
        pendingBuffer.clear();
    }

    @Override
    public void channelWritabilityChanged(ChannelHandlerContext ctx) {
        if (ctx.channel().isWritable()) {
            if (upstream.isOpen()) {
                upstream.config().setAutoRead(true);
            }
        }
        ctx.fireChannelWritabilityChanged();
    }

    @Override
    public void channelInactive(ChannelHandlerContext ctx) {
        releaseBuffer();
        if (upstream != null) Utils.safeRelease(upstream);
    }

    @Override
    public void exceptionCaught(ChannelHandlerContext ctx, Throwable cause) {
        // Clear the Buffer (Prevent memory leak)
        while (!pendingBuffer.isEmpty()) {
            ReferenceCountUtil.release(pendingBuffer.poll());
        }
        if (this.upstream != null) {
            Utils.safeRelease(upstream);
        }
        ctx.close();
    }
}
