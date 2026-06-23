package com.xx;

import io.netty.buffer.Unpooled;
import io.netty.channel.Channel;
import io.netty.channel.ChannelFutureListener;
import javax.net.ssl.X509TrustManager;
import java.security.cert.X509Certificate;


public class Utils {


    static class TrustAllManager implements X509TrustManager {
        public void checkClientTrusted(X509Certificate[] chain, String authType) {
        }

        public void checkServerTrusted(X509Certificate[] chain, String authType) {
        }

        public X509Certificate[] getAcceptedIssuers() {
            return new X509Certificate[0];
        }
    }

    // Put this at the bottom of your Handler class
    static void closeOnFlush(Channel ch) {
        // Safety check: only close if the channel is actually still open/active
        if (ch != null && ch.isActive()) {
            ch.writeAndFlush(Unpooled.EMPTY_BUFFER)
                    .addListener(ChannelFutureListener.CLOSE);
        }
    }
}
