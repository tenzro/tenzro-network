#include "llama.cpp/include/llama.h"
#include "llama.cpp/ggml/include/gguf.h"

#ifdef LLAMA_RS_BUILD_COMMON
#include "wrapper_common.h"
#include "wrapper_oai.h"
#endif

// The ggml RPC backend declarations (`ggml_backend_rpc_add_server`,
// `ggml_backend_rpc_get_device_memory`, …) are only built when the `rpc`
// feature compiles `GGML_RPC=ON`. Include the header in the bindgen pass only
// then, so a non-rpc build does not emit dangling bindings for symbols absent
// from the link line. The functions match the `ggml_.*` allowlist already in
// build.rs, so no extra allowlist entry is needed.
#ifdef LLAMA_RS_BUILD_RPC
#include "llama.cpp/ggml/include/ggml-rpc.h"
#endif
