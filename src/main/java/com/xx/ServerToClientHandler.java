package com.xx;

import io.netty.channel.*;
import io.netty.handler.codec.http.*;
import io.netty.util.ReferenceCountUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class ServerToClientHandler extends ChannelInboundHandlerAdapter {
    private static final Logger LOGGER = LoggerFactory.getLogger(ServerToClientHandler.class);
    private final Channel client;

    public ServerToClientHandler(Channel client) {
        this.client = client;
    }


    @Override
    public void channelInactive(ChannelHandlerContext ctx) {
        ctx.fireChannelInactive();
    }

    @Override
    public void channelRead(ChannelHandlerContext ctx, Object msg) {
        if (client.isActive()) {
            LOGGER.info("Target-Server {} >>> FORWARDING >>> CLIENT {}", ctx.channel(), client);
            client.writeAndFlush(msg);
            if (!client.isWritable()) {
                ctx.channel().config().setAutoRead(false);
            }
//            if (msg instanceof LastHttpContent) {
//            }

        } else {
            LOGGER.error("Target-Server {} >>> FORWARD ERROR, NO active client", ctx.channel());
            // Just in case
            ReferenceCountUtil.release(msg);
        }
    }

    @Override
    public void channelWritabilityChanged(ChannelHandlerContext ctx) {
        if (ctx.channel().isWritable() && client!= null && client.isActive()) {
            client.config().setAutoRead(true);
        }
        ctx.fireChannelWritabilityChanged();
    }

    @Override
    public void exceptionCaught(ChannelHandlerContext ctx, Throwable ignored) {
        LOGGER.info("Server to Client Channel Exception {}", ctx.channel());
        ctx.close();
        Utils.closeOnFlush(client);
    }
}
