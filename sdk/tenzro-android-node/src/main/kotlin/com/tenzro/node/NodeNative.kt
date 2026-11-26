package com.tenzro.node

/** The node's native library: `libtenzro_android_node.so`. */
internal object NodeNative {
    init {
        System.loadLibrary("tenzro_android_node")
    }

    /** Loads the library (this object's initializer does), and with it the Keystore bridge's native side. */
    @JvmStatic
    fun load() = Unit

    /**
     * Runs the node with [args] (its command line after the program name)
     * until it stops. Returns null when it stopped as asked, else the reason
     * it ended. Blocks: call it on a thread of its own.
     */
    @JvmStatic
    external fun runNode(args: Array<String>): String?

    /** Asks the running node to stop; [runNode] then returns. */
    @JvmStatic
    external fun stopNode()
}
