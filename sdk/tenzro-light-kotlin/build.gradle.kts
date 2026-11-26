// The Tenzro light client for the JVM and Android: the Kotlin bindings of
// sdk/tenzro-ffi, generated from the built library, over JNA. The tests load
// the host's build of the library and replay the shared fixture.
//
// Preview: the surface may change before it is stable.

plugins {
    kotlin("jvm") version "2.4.21"
}

group = "com.tenzro"
version = "0.2.2"

repositories {
    mavenCentral()
}

val workspace = rootDir.resolve("../..").canonicalFile
val libDir = (System.getenv("CARGO_TARGET_DIR")?.let(::File) ?: workspace.resolve("target")).resolve("release")
val generated = layout.buildDirectory.dir("generated/uniffi")

dependencies {
    implementation("net.java.dev.jna:jna:5.17.0")
    testImplementation(kotlin("test"))
    testImplementation("org.json:json:20250517")
}

// Builds the library for this host and writes its Kotlin bindings.
val bindings = tasks.register<Exec>("bindings") {
    workingDir = workspace
    outputs.dir(generated)
    commandLine(
        "sh", "-c",
        "cargo build --locked --release -p tenzro-ffi && " +
            "cargo run --locked --release -p tenzro-ffi --features bindgen --bin uniffi-bindgen -- " +
            "generate --library '${libDir.resolve("libtenzro_ffi.so")}' --language kotlin --no-format " +
            "--out-dir '${generated.get().asFile}'",
    )
}

sourceSets["main"].kotlin.srcDir(bindings)

tasks.test {
    useJUnitPlatform()
    systemProperty("jna.library.path", libDir.path)
    systemProperty("tenzro.fixture", workspace.resolve("sdk/fixtures/light-client/fixture.json").path)
}
