package com.cyberspy.app.monitoring

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.util.Log

/**
 * BootReceiver — Restarts monitoring services after device reboot.
 */
class BootReceiver : BroadcastReceiver() {
    override fun onReceive(context: Context, intent: Intent) {
        if (intent.action == Intent.ACTION_BOOT_COMPLETED) {
            Log.i("BootReceiver", "Device rebooted — starting CyberSpy monitoring")
            val serviceIntent = Intent(context, MonitoringForegroundService::class.java)
            context.startForegroundService(serviceIntent)
        }
    }
}
