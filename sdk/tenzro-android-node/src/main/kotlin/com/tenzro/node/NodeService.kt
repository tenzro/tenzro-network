package com.tenzro.node

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.Service
import android.content.Context
import android.content.Intent
import android.content.pm.ServiceInfo
import android.os.Build
import android.os.IBinder
import android.util.Log
import com.tenzro.keystore.KeystoreBridge
import java.io.File

/**
 * The node, run in this app's process by a foreground service. [start] and
 * [stop] are the app's controls; they also record the choice, so the node
 * comes back after a reboot only when the operator left it on.
 */
class NodeService : Service() {
    companion object {
        private const val TAG = "TenzroNode"
        private const val CHANNEL = "tenzro_node"
        private const val NOTIFICATION_ID = 0x7e2

        /** Starts the node with [extraArgs] after its own, and keeps it on across reboots. */
        @JvmStatic
        @JvmOverloads
        fun start(context: Context, extraArgs: Array<String> = emptyArray()) {
            NodeArgs.of(dataDir(context).path, extraArgs)
            NodeSettings.save(context, runs = true, extraArgs = extraArgs)
            context.startForegroundService(Intent(context, NodeService::class.java))
        }

        /** Stops the node and leaves it off across reboots. */
        @JvmStatic
        fun stop(context: Context) {
            NodeSettings.save(context, runs = false)
            context.stopService(Intent(context, NodeService::class.java))
        }

        /** The node's data directory: the app's own, never shared. */
        @JvmStatic
        fun dataDir(context: Context): File = File(context.filesDir, "node")
    }

    private var thread: Thread? = null

    override fun onBind(intent: Intent?): IBinder? = null

    override fun onCreate() {
        super.onCreate()
        val manager = getSystemService(NotificationManager::class.java)
        manager.createNotificationChannel(
            NotificationChannel(CHANNEL, "Tenzro node", NotificationManager.IMPORTANCE_LOW)
        )
        val notification = Notification.Builder(this, CHANNEL)
            .setContentTitle("Tenzro node")
            .setContentText("Following the chain")
            .setSmallIcon(android.R.drawable.stat_notify_sync)
            .setOngoing(true)
            .build()
        if (Build.VERSION.SDK_INT >= 34) {
            startForeground(NOTIFICATION_ID, notification, ServiceInfo.FOREGROUND_SERVICE_TYPE_SPECIAL_USE)
        } else {
            startForeground(NOTIFICATION_ID, notification)
        }
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        if (thread?.isAlive != true) {
            val dir = dataDir(this).apply { mkdirs() }
            val args = NodeArgs.of(dir.path, NodeSettings.extraArgs(this))
            thread = Thread({
                // Loading the node also loads the Keystore bridge: hand it this VM first.
                NodeNative.load()
                if (!KeystoreBridge.install()) Log.w(TAG, "the Keystore bridge did not install; the node has no hardware key")
                val ended = NodeNative.runNode(args)
                if (ended == null) Log.i(TAG, "node stopped") else Log.e(TAG, "node ended: $ended")
                stopSelf()
            }, "tenzro-node").apply { start() }
        }
        return START_STICKY
    }

    override fun onDestroy() {
        NodeNative.stopNode()
        thread?.join(30_000)
        super.onDestroy()
    }
}
