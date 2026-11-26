package com.tenzro.node

import android.content.Context

/**
 * What the operator chose, kept across restarts: whether the node runs, and
 * the extra arguments it runs with. The boot receiver reads it.
 */
object NodeSettings {
    /** The shared preferences file. */
    const val PREFS = "com.tenzro.node"

    /** Whether the operator left the node on: the boot receiver starts it only then. */
    const val KEY_RUN = "run_node"

    /** The extra node arguments, joined by NUL. */
    const val KEY_ARGS = "node_args"

    fun runs(context: Context): Boolean = prefs(context).getBoolean(KEY_RUN, false)

    fun extraArgs(context: Context): Array<String> =
        prefs(context).getString(KEY_ARGS, "")!!.split('\u0000').filter { it.isNotEmpty() }.toTypedArray()

    internal fun save(context: Context, runs: Boolean, extraArgs: Array<String>? = null) {
        prefs(context).edit().apply {
            putBoolean(KEY_RUN, runs)
            if (extraArgs != null) putString(KEY_ARGS, NodeArgs.join(extraArgs))
        }.apply()
    }

    private fun prefs(context: Context) = context.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
}
