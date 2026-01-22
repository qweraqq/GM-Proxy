plugins {
    id("java")
    id("application")
}

group = "com.xx"
version = "1.0-SNAPSHOT"

repositories {
    mavenCentral()
}

java {
    toolchain {
        languageVersion.set(JavaLanguageVersion.of(21))
    }
}

application {
    mainClass.set("com.xx.NettyGmProxy")
}

dependencies {
    implementation("io.netty:netty-all:4.2.9.Final")
    implementation("io.netty:netty-transport-native-epoll:4.2.9.Final")
    implementation("org.bouncycastle:bcpkix-jdk18on:1.83")
    implementation("org.bouncycastle:bcprov-jdk18on:1.83")
    implementation("com.tencent.kona:kona-crypto:1.0.19")
    implementation("com.tencent.kona:kona-pkix:1.0.19")
    implementation("com.tencent.kona:kona-ssl:1.0.19")
    implementation("com.tencent.kona:kona-provider:1.0.19")
    implementation("org.slf4j:slf4j-api:2.0.17")
    implementation("org.slf4j:slf4j-simple:2.0.17")
}

tasks.named<Jar>("jar") {
    // 1. Resolve conflicts (common in uber jars) by excluding duplicates
    duplicatesStrategy = DuplicatesStrategy.EXCLUDE

    manifest {
        attributes(
            "Main-Class" to "com.xx.NettyTLSProxyNG",
            "Implementation-Title" to "TLS-MITM-Proxy",
            "Implementation-Version" to project.version
        )
    }

    // 2. Include the compile output (your code)
    from(sourceSets.main.get().output)

    // 3. Unzip and include all runtime dependencies
    from(configurations.runtimeClasspath.get().map { if (it.isDirectory) it else zipTree(it) }) {
        // CRITICAL: Exclude signature files.
        // If these are copied, the jar will be invalid because the original signatures
        // won't match your new uber jar.
        exclude("META-INF/*.SF")
        exclude("META-INF/*.DSA")
        exclude("META-INF/*.RSA")
    }
}