package com.tenzro.keystore

/**
 * Connects the node's native library to the Keystore. Call [install] once,
 * from a Java thread (the foreground service's `onCreate`, for instance),
 * after `System.loadLibrary` has loaded the node: the native side keeps the
 * VM and [AndroidKeystoreKey]'s class, which a native thread cannot look up
 * through its own class loader. Until then the node finds no hardware key.
 */
object KeystoreBridge {
    /** True when the native side holds the VM and the key class. */
    @JvmStatic
    external fun install(): Boolean
}
