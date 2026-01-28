package com.xx;

import io.netty.channel.*;
import io.netty.handler.codec.http.*;
import io.netty.util.ReferenceCountUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class ServerToClientHandler extends ChannelInboundHandlerAdapter {
    private static final Logger LOGGER = LoggerFactory.getLogger(ServerToClientHandler.class);
    private final Channel client;
    private boolean responseComplete = false;

    public ServerToClientHandler(Channel client) {
        this.client = client;
    }


    @Override
    public void channelActive(ChannelHandlerContext ctx) {
        ctx.read();
    }

    @Override
    public void channelInactive(ChannelHandlerContext ctx) {
        if (!responseComplete && client != null && client.isActive()) {
            client.close();
        }
    }

    @Override
    public void channelRead(ChannelHandlerContext ctx, Object msg) {
        if (client.isActive()) {
            LOGGER.info("Target-Server {} >>> FORWARDING >>> CLIENT {} ", ctx.channel(), client);
//            if (msg instanceof HttpResponse resp) {
//
//                // Enforce deterministic framing
//                HttpHeaders h = resp.headers();
//                h.remove(HttpHeaderNames.PROXY_CONNECTION);
//                h.remove(HttpHeaderNames.TRANSFER_ENCODING);
//                h.remove(HttpHeaderNames.UPGRADE);
//
//                // Disable keep-alive to prevent truncation
//                // h.set(HttpHeaderNames.CONNECTION, HttpHeaderValues.CLOSE);
//            }
            client.writeAndFlush(msg).addListener(ChannelFutureListener.FIRE_EXCEPTION_ON_FAILURE);
            if (!client.isWritable()) {
                ctx.channel().config().setAutoRead(false);
            }

            if (msg instanceof LastHttpContent) {
                responseComplete = true;
            }
        } else {
            // Just in case
            ReferenceCountUtil.release(msg);
            client.close();
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
    public void exceptionCaught(ChannelHandlerContext ctx, Throwable cause) {
        LOGGER.info("Server to Client Channel Exception", cause);
        ctx.close();
        if(client != null) {
            client.close();
        }
    }
}
