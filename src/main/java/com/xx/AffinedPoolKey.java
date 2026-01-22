package com.xx;

import io.netty.channel.EventLoop;

import java.net.InetSocketAddress;
import java.util.Objects;

public record AffinedPoolKey(EventLoop eventLoop, InetSocketAddress address) {

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        AffinedPoolKey that = (AffinedPoolKey) o;
        // Identity equality for EventLoop is sufficient and fast
        return eventLoop == that.eventLoop && Objects.equals(address, that.address);
    }

    @Override
    public int hashCode() {
        return 31 * System.identityHashCode(eventLoop) + address.hashCode();
    }
}
