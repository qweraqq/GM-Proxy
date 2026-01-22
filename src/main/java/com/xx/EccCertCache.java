package com.xx;

import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

import javax.net.ssl.*;
import javax.security.auth.x500.X500Principal;
import java.math.BigInteger;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.security.spec.ECGenParameterSpec;
import java.util.Date;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

public class EccCertCache {

    private static final Map<String, SSLContext> cache = new ConcurrentHashMap<>();
    private static KeyPair caKeyPair;
    private static X509Certificate caCert;

    static {
        try {
            init();
        } catch (Exception e) {
            throw new RuntimeException("Failed to initialize CertCache", e);
        }
    }

    public static void init() throws Exception {
        // Ensure BC is registered for Cert Generation duties
        if (Security.getProvider("BC") == null) {
            Security.addProvider(new BouncyCastleProvider());
        }

        // --- FIX START ---
        // Use DEFAULT provider (SunEC) for keys, NOT Bouncy Castle.
        // This ensures the PrivateKey is a standard Java object compatible with all SSL Engines.
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC");
        kpg.initialize(new ECGenParameterSpec("secp256r1")); // "secp256r1" is the standard name for prime256v1
        caKeyPair = kpg.generateKeyPair();
        // --- FIX END ---

        X500Principal caSubject = new X500Principal("CN=NettyGmProxy, O=Proxy, C=CN");

        caCert = generateCert(
                caKeyPair.getPublic(),
                caKeyPair.getPrivate(),
                caSubject,
                caSubject,
                true
        );
    }

    public static SSLContext getServerContext(String host) {
        return cache.computeIfAbsent(host, h -> {
            try {
                // --- FIX START ---
                // Use DEFAULT provider for Leaf Keys as well
                KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC");
                kpg.initialize(new ECGenParameterSpec("secp256r1"));
                KeyPair hostKey = kpg.generateKeyPair();
                // --- FIX END ---

                X500Principal hostSubject = new X500Principal("CN=" + h + ", O=Proxy");

                X509Certificate hostCert = generateCert(
                        hostKey.getPublic(),
                        caKeyPair.getPrivate(),
                        hostSubject,
                        caCert.getSubjectX500Principal(),
                        false
                );

                KeyStore ks = KeyStore.getInstance("PKCS12");
                ks.load(null, null);
                ks.setKeyEntry("host", hostKey.getPrivate(), "password".toCharArray(), new Certificate[]{hostCert, caCert});

                KeyManagerFactory kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
                kmf.init(ks, "password".toCharArray());

                // Using TLSv1.3 or TLSv1.2 automatically
                SSLContext ctx = SSLContext.getInstance("TLS");
                ctx.init(kmf.getKeyManagers(), null, null);

                // enabling Session Caching on your ServerContext
                ctx.getServerSessionContext().setSessionCacheSize(1000);
                ctx.getServerSessionContext().setSessionTimeout(300);

                return ctx;

            } catch (Exception e) {
                throw new RuntimeException("Failed to generate cert for " + h, e);
            }
        });
    }

    private static X509Certificate generateCert(PublicKey publicKey, PrivateKey signingKey,
                                                X500Principal subject, X500Principal issuer,
                                                boolean isCa) throws Exception {
        long now = System.currentTimeMillis();
        BigInteger serial = new BigInteger(64, new SecureRandom());

        JcaX509v3CertificateBuilder builder = new JcaX509v3CertificateBuilder(
                issuer,
                serial,
                new Date(now),
                new Date(now + 31536000000L),
                subject,
                publicKey
        );

        builder.addExtension(org.bouncycastle.asn1.x509.Extension.basicConstraints, true,
                new org.bouncycastle.asn1.x509.BasicConstraints(isCa));

        // We use BC to SIGN the certificate, which is fine.
        // It can handle the standard Java PrivateKey we passed in.
        ContentSigner signer = new JcaContentSignerBuilder("SHA256withECDSA")
                .setProvider("BC")
                .build(signingKey);

        return new JcaX509CertificateConverter()
                .setProvider("BC")
                .getCertificate(builder.build(signer));
    }
}