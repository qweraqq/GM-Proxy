package com.xx;

import io.netty.channel.Channel;
import io.netty.channel.pool.SimpleChannelPool;

import javax.net.ssl.X509TrustManager;
import java.security.cert.X509Certificate;
import java.util.concurrent.atomic.AtomicBoolean;


public class Utils {

    /*
     *  In a proxy, a connection can end in 3 different ways, often happening simultaneously:
     *   - Success: The server sends the last byte of data (LastHttpContent).
     *   - Failure: The client disconnects abruptly (channelInactive).
     *   - Error: An exception occurs (exceptionCaught).
     *
     *  safeRelease uses an Atomic Flag attached to the channel to ensure that the release logic runs exactly once,
     *              no matter how many times it is called
     *
     *
     */
    public static void safeRelease(Channel ch) {
        if (ch.eventLoop().inEventLoop()) {
            // We are already on the correct thread. Execute immediately.
            doRelease(ch);
        } else {
            // We are on a different thread (e.g., Client thread).
            // Schedule the task to run on the Channel's thread.
            ch.eventLoop().execute(() -> doRelease(ch));
        }
    }

    private static void doRelease(Channel ch) {
        // 2. Atomic Guard (Prevents Double-Release)
        AtomicBoolean guard = ch.attr(Magic.RELEASE_GUARD).get();
        if (guard != null && guard.compareAndSet(false, true)) {
            // System.out.println("Releasing Connection: " + ch + " on Thread: " + Thread.currentThread().getName());

            // Remove User-Specific Handlers
            if (ch.pipeline().get(HeaderRewriteHandler.class) != null) {
                ch.pipeline().remove(HeaderRewriteHandler.class);
            }
            if (ch.pipeline().get(ProxyToClientRelayHandler.class) != null) {
                ch.pipeline().remove(ProxyToClientRelayHandler.class);
            }

            // ADD CLEANER (The Safety Net)
            // Any bytes arriving after this point are garbage. Eat them.
            if (ch.pipeline().get(PoolCleanerHandler.class) == null) {
                ch.pipeline().addLast(new PoolCleanerHandler());
            }

            SimpleChannelPool pool = ch.attr(Magic.POOL_REF).get();
            if (pool != null) {
                try {
                    pool.release(ch);
                } catch (Exception e) {
                    // If release fails, close it to prevent leaks
                    ch.close();
                }
            }
        }
    }

    static class TrustAllManager implements X509TrustManager {
        public void checkClientTrusted(X509Certificate[] chain, String authType) {
        }

        public void checkServerTrusted(X509Certificate[] chain, String authType) {
        }

        public X509Certificate[] getAcceptedIssuers() {
            return new X509Certificate[0];
        }
    }
}
