package com.xx;

import io.netty.channel.pool.SimpleChannelPool;
import io.netty.util.AttributeKey;

import java.util.concurrent.atomic.AtomicBoolean;

public class Magic {
    public static final AttributeKey<SimpleChannelPool> POOL_REF = AttributeKey.valueOf("pool_ref");

    // Attribute to track if the channel is currently released to prevent double-free
    public static final AttributeKey<AtomicBoolean> RELEASE_GUARD = AttributeKey.valueOf("release_guard");

}
