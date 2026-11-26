//! The light node as `libtenzro_android_node.so`, for the Kotlin
//! `com.tenzro.node.NodeNative` the library's foreground service calls. The
//! Keystore bridge (`com.tenzro.keystore.KeystoreBridge`) is in the same
//! library, from the device-key crate.

#![cfg(target_os = "android")]

use jni::JNIEnv;
use jni::objects::{JClass, JObjectArray, JString};
use jni::sys::jstring;

/// `NodeNative.runNode(args)`: runs the node until it stops. Returns null
/// when it stopped as asked, else the reason it ended.
#[unsafe(no_mangle)]
pub extern "system" fn Java_com_tenzro_node_NodeNative_runNode(
    mut env: JNIEnv,
    _class: JClass,
    args: JObjectArray,
) -> jstring {
    let ended = match strings(&mut env, &args) {
        Ok(args) => tenzro_node::embedded::run(args).err(),
        Err(e) => Some(format!("reading the node's arguments: {e}")),
    };
    match ended {
        None => std::ptr::null_mut(),
        Some(reason) => env
            .new_string(reason)
            .map(JString::into_raw)
            .unwrap_or(std::ptr::null_mut()),
    }
}

/// `NodeNative.stopNode()`: asks the running node to stop.
#[unsafe(no_mangle)]
pub extern "system" fn Java_com_tenzro_node_NodeNative_stopNode(_env: JNIEnv, _class: JClass) {
    tenzro_node::embedded::request_stop();
}

fn strings(env: &mut JNIEnv, args: &JObjectArray) -> jni::errors::Result<Vec<String>> {
    let n = env.get_array_length(args)?;
    let mut out = Vec::with_capacity(n as usize);
    for i in 0..n {
        let s = JString::from(env.get_object_array_element(args, i)?);
        out.push(env.get_string(&s)?.into());
    }
    Ok(out)
}
