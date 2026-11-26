package com.tenzro.node

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent

/** Starts the node after a reboot, when the operator left it on. */
class BootReceiver : BroadcastReceiver() {
    override fun onReceive(context: Context, intent: Intent) {
        if (intent.action == Intent.ACTION_BOOT_COMPLETED && NodeSettings.runs(context)) {
            NodeService.start(context, NodeSettings.extraArgs(context))
        }
    }
}
