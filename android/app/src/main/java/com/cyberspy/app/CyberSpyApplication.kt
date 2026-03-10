package com.cyberspy.app

import android.app.Application
import android.util.Log

/**
 * CyberSpy Application class.
 *
 * Initializes core services on app startup:
 * - StorageFragmentManager (shard locations)
 * - MonitoringEngine (data collection)
 * - ThreatDetector (AI pipeline)
 */
class CyberSpyApplication : Application() {

    companion object {
        private const val TAG = "CyberSpyApp"
        lateinit var instance: CyberSpyApplication
            private set
    }

    override fun onCreate() {
        super.onCreate()
        instance = this

        Log.i(TAG, "CyberSpy initialized — monitoring engine ready")
        Log.i(TAG, "  Device: ${android.os.Build.MANUFACTURER} ${android.os.Build.MODEL}")
        Log.i(TAG, "  Android: ${android.os.Build.VERSION.RELEASE} (API ${android.os.Build.VERSION.SDK_INT})")

        // In production, start monitoring WorkManager tasks here:
        // MonitoringScheduler.schedulePeriodicMonitoring(this)
    }
}
