fn main() {
    if let Ok(dir) = std::env::var("DEP_LLAMA_BACKENDS_DIR") {
        println!("cargo:rustc-env=GGML_BACKENDS_DIR={}", dir);
    }
    // Re-export the rpc-server binary path (set by llama-cpp-sys-2 under the
    // `rpc` feature) as a compile-time env so dependents can embed it.
    if let Ok(bin) = std::env::var("DEP_LLAMA_RPC_SERVER_BIN") {
        println!("cargo:rustc-env=LLAMA_RPC_SERVER_BIN={}", bin);
        println!("cargo:rpc_server_bin={}", bin);
    }
}

