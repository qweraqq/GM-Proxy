package com.xx;

import io.netty.buffer.ByteBuf;
import io.netty.channel.ChannelDuplexHandler;
import io.netty.channel.ChannelHandlerContext;
import io.netty.channel.ChannelPromise;

@SuppressWarnings("all")
public class DebugTraceHandler extends ChannelDuplexHandler {
    private final String id;

    public DebugTraceHandler(String id) { this.id = id; }

    @Override
    public void channelRead(ChannelHandlerContext ctx, Object msg) throws Exception {
        String meta = "";
        int size = 0;
        if (msg instanceof ByteBuf) {
            size = ((ByteBuf) msg).readableBytes();
            // Print first 10 bytes to see if it's HTTP or Garbage
            byte[] peek = new byte[Math.min(size, 10)];
            ((ByteBuf) msg).getBytes(((ByteBuf) msg).readerIndex(), peek);
            meta = " [Prefix: " + new String(peek).replace("\r", "\\r").replace("\n", "\\n") + "]";
        } else {
            meta = " [" + msg.toString() + "]";
        }

        System.out.printf("[%s] READ  Thread:%s | AutoRead:%s | Type:%s | Size:%d%s%n",
                id, Thread.currentThread().getName(), ctx.channel().config().isAutoRead(),
                msg.getClass().getSimpleName(), size, meta);

        super.channelRead(ctx, msg);
    }

    @Override
    public void write(ChannelHandlerContext ctx, Object msg, ChannelPromise promise) throws Exception {
        int size = (msg instanceof ByteBuf) ? ((ByteBuf) msg).readableBytes() : 0;
        System.out.printf("[%s] WRITE Thread:%s | Type:%s | Size:%d%n",
                id, Thread.currentThread().getName(), msg.getClass().getSimpleName(), size);
        super.write(ctx, msg, promise);
    }

    @Override
    public void channelInactive(ChannelHandlerContext ctx) throws Exception {
        System.out.printf("[%s] INACTIVE (Disconnected)%n", id);
        super.channelInactive(ctx);
    }

    @Override
    public void exceptionCaught(ChannelHandlerContext ctx, Throwable cause) {
        System.out.printf("[%s] EXCEPTION: %s%n", id, cause.getMessage());
        ctx.close();
    }
}
