package com.xx;

/**
 * Result of asking a target server "which HTTPS protocol can you speak?".
 *
 * <p>The proxy only needs one bit of information: is the upstream <em>only</em>
 * capable of speaking the Chinese national cryptography protocol (TLCP / 国密)?
 * Only in that case the non-GM client cannot talk to it directly and the proxy
 * has to terminate TLS on both sides (MITM mode). In every other case the
 * existing blind relay is both faster and safer.
 */
public enum UpstreamProtocol {

    /** Server answered our standard-TLS ClientHello with an alert / nothing, but happily
     *  answered our TLCP ClientHello with a TLCP ServerHello (version 0x0101). */
    GM_ONLY(true, true),

    /** Server answered our standard-TLS ClientHello with a TLS ServerHello. It may also
     *  speak TLCP, but a non-GM client can reach it on its own, so relaying is enough. */
    TLS_CAPABLE(false, true),

    /** Could not tell (connect failure, timeout, plain-HTTP port, both probes rejected...). */
    UNKNOWN(false, false);

    private final boolean gmOnly;
    private final boolean definitive;

    UpstreamProtocol(boolean gmOnly, boolean definitive) {
        this.gmOnly = gmOnly;
        this.definitive = definitive;
    }

    /** True when the only HTTPS protocol the server offers is the GM/TLCP one. */
    @SuppressWarnings("unused")
    public boolean isGmOnly() {
        return gmOnly;
    }

    /** True when the probe actually learned something; only definitive results are cached. */
    public boolean isDefinitive() {
        return definitive;
    }
}
