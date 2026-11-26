package com.tenzro.node

/** The node's command line, built from the app's directory and the operator's extra arguments. */
object NodeArgs {
    /**
     * `--data-dir <dataDir> --roles light`, then [extra]. The node follows the
     * chain as a light node: other roles are decided per device class after
     * measurement. [extra] may not set the data directory or the roles.
     */
    fun of(dataDir: String, extra: Array<String>): Array<String> {
        require(extra.none { it == "--data-dir" || it.startsWith("--data-dir=") || it == "--roles" || it.startsWith("--roles=") }) {
            "the data directory and the roles are set by the app"
        }
        require(extra.none { it.contains('\u0000') }) { "an argument holds no NUL" }
        return arrayOf("--data-dir", dataDir, "--roles", "light") + extra
    }

    internal fun join(args: Array<String>): String = args.joinToString("\u0000")
}
