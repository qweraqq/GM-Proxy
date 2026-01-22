package com.xx;

import io.netty.buffer.Unpooled;
import io.netty.channel.Channel;
import io.netty.channel.ChannelFutureListener;
import io.netty.channel.ChannelHandlerContext;
import io.netty.channel.ChannelInboundHandlerAdapter;
import io.netty.handler.codec.http.LastHttpContent;
import io.netty.util.ReferenceCountUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/*
 * Relay Target Server response to Client
 */
public class ProxyToClientRelayHandler extends ChannelInboundHandlerAdapter {
    private static final Logger LOGGER = LoggerFactory.getLogger(ProxyToClientRelayHandler.class);
    private final Channel client;


    public ProxyToClientRelayHandler(Channel client) {
        this.client = client;
    }

    /*
     * client ok -> write server response and close client channel
     * client error -> just release server response
     */
    @Override
    public void channelRead(ChannelHandlerContext ctx, Object msg) {
        if (client.isActive()) {
            // triggers exceptionCaught when write failed
            LOGGER.info("Target-Server {} >>> FORWARDING >>> CLIENT {} ", ctx.channel(), client);
            client.writeAndFlush(msg).addListener(ChannelFutureListener.FIRE_EXCEPTION_ON_FAILURE);
            if (msg instanceof LastHttpContent) {
                // Done. Release Upstream (Keep-Alive).
                LOGGER.info("Target-Server {} >>> FORWARDING >>> CLIENT {} DONE, releasing PROXY <---> Target-Server channel", ctx.channel(), client);
                ctx.pipeline().remove(this);
                Utils.safeRelease(ctx.channel());
                // 3. Notify Client to Reset State
                if (client.isActive()) {
                    SmartClientToServerRelayHandler handler = client.pipeline().get(SmartClientToServerRelayHandler.class);
                    if (handler != null) {
                        if (client.eventLoop().inEventLoop()) handler.detachUpstream();
                        else client.eventLoop().execute(handler::detachUpstream);
                    }
                }
            }

            // FLOW CONTROL
            if (!client.isWritable()) {
                ctx.channel().config().setAutoRead(false);
            }
        } else {
            ReferenceCountUtil.release(msg);
            Utils.safeRelease(ctx.channel());
            ctx.close();
        }
    }

    @Override
    public void channelWritabilityChanged(ChannelHandlerContext ctx) {
        if (ctx.channel().isWritable()) {
            if (client.isOpen()) {
                client.config().setAutoRead(true);
            }
        }
        ctx.fireChannelWritabilityChanged();
    }

    @Override
    public void channelInactive(ChannelHandlerContext ctx) {
        // Server dead -> Close client
        if (client.isActive()) {
            // Flush pending data, then close
            client.writeAndFlush(Unpooled.EMPTY_BUFFER).addListener(ChannelFutureListener.CLOSE);
        }
        Utils.safeRelease(ctx.channel());
    }

    @Override
    public void exceptionCaught(ChannelHandlerContext ctx, Throwable cause) {
        Utils.safeRelease(ctx.channel());
        client.close();
    }
}
