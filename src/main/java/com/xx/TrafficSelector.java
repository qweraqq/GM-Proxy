package com.xx;

import java.util.HashSet;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

public class TrafficSelector {

    // Store specific "Host:Port" rules
    private static final Set<String> EXACT_HOST_PORT_RULES = ConcurrentHashMap.newKeySet();

    // Store Host-only rules (matches any port for this host)
    private static final Set<String> HOST_ONLY_RULES = ConcurrentHashMap.newKeySet();

    // Store Suffix rules (e.g., ".cn")
    private static final Set<String> SUFFIX_RULES = ConcurrentHashMap.newKeySet();

    static {
        // --- Default Configuration ---

        // Rule 1: Specific Host and Port
        addRule("www.bing.com", 443);
        addRule("www.baidu.com", 443);
        addRule("www.taobao.com", 443);

        // Rule 2: All ports for this host
        addRule("gm-only-server.com");

        // Rule 3: Suffix Match (Optional - be careful with this)
        // addSuffixRule(".gov.cn");
    }

    /**
     * Determines if the traffic requires MITM based on Host and Port.
     */
    public static boolean isTarget(String host, int port) {
        // 1. Check Exact "Host:Port" match
        String hostPortKey = host + ":" + port;
        if (EXACT_HOST_PORT_RULES.contains(hostPortKey)) {
            return true;
        }

        // 2. Check Host match (Any port)
        if (HOST_ONLY_RULES.contains(host)) {
            return true;
        }

        // 3. Check Suffix match (e.g., ends with .gov.cn)
        if (!SUFFIX_RULES.isEmpty()) {
            for (String suffix : SUFFIX_RULES) {
                if (host.endsWith(suffix)) {
                    return true;
                }
            }
        }

        return false;
    }

    public static Set<String> getHosts(){
        Set<String> result = new HashSet<>();
        for(String host : EXACT_HOST_PORT_RULES){
            result.add(host.split(":")[0]);
        }
        result.addAll(HOST_ONLY_RULES);
        return result;
    }

    // --- Configuration Methods ---

    public static void addRule(String host, int port) {
        EXACT_HOST_PORT_RULES.add(host + ":" + port);
    }

    public static void addRule(String host) {
        HOST_ONLY_RULES.add(host);
    }

    @SuppressWarnings("unused")
    public static void addSuffixRule(String suffix) {
        SUFFIX_RULES.add(suffix);
    }

    @SuppressWarnings("unused")
    public static void clearRules() {
        EXACT_HOST_PORT_RULES.clear();
        HOST_ONLY_RULES.clear();
        SUFFIX_RULES.clear();
    }
}