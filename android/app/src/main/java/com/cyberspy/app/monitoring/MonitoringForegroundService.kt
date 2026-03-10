package com.cyberspy.app.monitoring

import android.app.*
import android.content.Intent
import android.os.IBinder
import android.util.Log
import androidx.core.app.NotificationCompat
import com.cyberspy.app.ui.MainActivity

/**
 * MonitoringForegroundService — Keeps the monitoring engine alive.
 */
class MonitoringForegroundService : Service() {

    companion object {
        private const val CHANNEL_ID = "monitoring_channel"
        private const val NOTIFICATION_ID = 1
    }

    override fun onCreate() {
        super.onCreate()
        createNotificationChannel()
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        val notification = NotificationCompat.Builder(this, CHANNEL_ID)
            .setContentTitle("CyberSpy Monitoring Active")
            .setContentText("Protecting your device in the background")
            .setSmallIcon(android.R.drawable.ic_lock_idle_lock)
            .setContentIntent(PendingIntent.getActivity(this, 0, Intent(this, MainActivity::class.java), PendingIntent.FLAG_IMMUTABLE))
            .build()

        startForeground(NOTIFICATION_ID, notification)
        
        // Start actual monitoring logic here
        Log.i("MonitoringService", "Background monitoring started")
        
        return START_STICKY
    }

    override fun onBind(intent: Intent?): IBinder? = null

    private fun createNotificationChannel() {
        val channel = NotificationChannel(
            CHANNEL_ID,
            "Device Monitoring",
            NotificationManager.IMPORTANCE_LOW
        )
        val manager = getSystemService(NotificationManager::class.java)
        manager.createNotificationChannel(channel)
    }
}
