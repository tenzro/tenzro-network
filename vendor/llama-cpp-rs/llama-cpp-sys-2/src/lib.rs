//! See [llama-cpp-2](https://crates.io/crates/llama-cpp-2) for a documented and safe API.

#![allow(non_upper_case_globals)]
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]
#![allow(unpredictable_function_pointer_comparisons)]
// `bindings.rs` is bindgen-generated: bindgen still emits `mem::transmute`
// where a plain cast would do for bitfield accessors. That is the generator's
// output, not something we can change without pinning a newer bindgen (which
// would churn the whole binding surface), so silence the lint at the include.
#![allow(unknown_lints)]
#![allow(unnecessary_transmutes)]

include!(concat!(env!("OUT_DIR"), "/bindings.rs"));
