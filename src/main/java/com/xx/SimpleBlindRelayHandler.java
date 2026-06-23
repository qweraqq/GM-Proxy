package com.xx;

import io.netty.buffer.Unpooled;
import io.netty.channel.Channel;
import io.netty.channel.ChannelFutureListener;
import io.netty.channel.ChannelHandlerContext;
import io.netty.channel.ChannelInboundHandlerAdapter;
import io.netty.util.ReferenceCountUtil;

public final class SimpleBlindRelayHandler extends ChannelInboundHandlerAdapter {
    private final Channel peer;

    public SimpleBlindRelayHandler(Channel peer) {
        this.peer = peer;
    }

    @Override
    public void channelActive(ChannelHandlerContext ctx) {
        ctx.read();
    }

    @Override
    public void channelRead(ChannelHandlerContext ctx, Object msg) {
        if (peer.isActive()) {
            peer.writeAndFlush(msg).addListener(ChannelFutureListener.FIRE_EXCEPTION_ON_FAILURE);

            // FLOW CONTROL
            // If the peer's outbound buffer is full, STOP reading from this side.
            // This forces the TCP Window to close, telling the Client to slow down.
            if (!peer.isWritable()) {
                ctx.channel().config().setAutoRead(false);
            }
        } else {
            ReferenceCountUtil.release(msg);
            peer.close();
        }
    }

    @Override
    public void channelWritabilityChanged(ChannelHandlerContext ctx) {
        if (ctx.channel().isWritable()) {
            peer.config().setAutoRead(true);
        }
        ctx.fireChannelWritabilityChanged();
    }

    @Override
    public void channelInactive(ChannelHandlerContext ctx) {
        if (peer != null && peer.isActive()) {
            // peer.close();
            peer.writeAndFlush(Unpooled.EMPTY_BUFFER).addListener(ChannelFutureListener.CLOSE);
        }
    }

    @Override
    public void exceptionCaught(ChannelHandlerContext ctx, Throwable cause) {
        ctx.close();
        peer.close();
    }
}
