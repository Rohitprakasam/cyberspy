package com.cyberspy.app.monitoring

import android.app.usage.UsageStatsManager
import android.content.Context
import android.net.TrafficStats
import android.os.Build
import android.util.Log
import com.google.gson.Gson
import com.google.gson.annotations.SerializedName
import java.io.BufferedReader
import java.io.InputStreamReader
import java.text.SimpleDateFormat
import java.util.*

/**
 * MonitoringEngine — Continuous device activity data collection.
 *
 * Captures 5 data streams:
 * 1. Network traffic statistics
 * 2. App usage / activity
 * 3. System logs (logcat security events)
 * 4. Running processes
 * 5. Device state (battery, connectivity, screen)
 *
 * All data is returned as structured JSON for storage + AI analysis.
 */
class MonitoringEngine(private val context: Context) {

    companion object {
        private const val TAG = "MonitoringEngine"
    }

    private val gson = Gson()
    private val dateFormat = SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss.SSS'Z'", Locale.US).apply {
        timeZone = TimeZone.getTimeZone("UTC")
    }

    // =========================================================
    //  DATA CLASSES
    // =========================================================

    data class DeviceSnapshot(
        @SerializedName("timestamp") val timestamp: String,
        @SerializedName("network") val network: NetworkSnapshot,
        @SerializedName("apps") val apps: List<AppActivity>,
        @SerializedName("systemLogs") val systemLogs: List<SystemLogEntry>,
        @SerializedName("processes") val processes: List<ProcessInfo>,
        @SerializedName("deviceState") val deviceState: DeviceState,
    )

    data class NetworkSnapshot(
        @SerializedName("totalRxBytes") val totalRxBytes: Long,
        @SerializedName("totalTxBytes") val totalTxBytes: Long,
        @SerializedName("mobileRxBytes") val mobileRxBytes: Long,
        @SerializedName("mobileTxBytes") val mobileTxBytes: Long,
        @SerializedName("activeConnections") val activeConnections: List<String>,
    )

    data class AppActivity(
        @SerializedName("packageName") val packageName: String,
        @SerializedName("lastUsed") val lastUsed: String,
        @SerializedName("totalForegroundMs") val totalForegroundMs: Long,
        @SerializedName("isSystemApp") val isSystemApp: Boolean,
    )

    data class SystemLogEntry(
        @SerializedName("timestamp") val timestamp: String,
        @SerializedName("level") val level: String,  // W, E, F
        @SerializedName("tag") val tag: String,
        @SerializedName("message") val message: String,
    )

    data class ProcessInfo(
        @SerializedName("name") val name: String,
        @SerializedName("pid") val pid: Int,
        @SerializedName("uid") val uid: Int,
    )

    data class DeviceState(
        @SerializedName("isScreenOn") val isScreenOn: Boolean,
        @SerializedName("batteryLevel") val batteryLevel: Int,
        @SerializedName("isCharging") val isCharging: Boolean,
        @SerializedName("androidVersion") val androidVersion: String,
        @SerializedName("deviceModel") val deviceModel: String,
    )

    // =========================================================
    //  SNAPSHOT CAPTURE
    // =========================================================

    /**
     * Capture a complete device snapshot.
     * Returns structured JSON string ready for storage and AI analysis.
     */
    fun captureSnapshot(): String {
        val snapshot = DeviceSnapshot(
            timestamp = dateFormat.format(Date()),
            network = captureNetworkStats(),
            apps = captureAppActivity(),
            systemLogs = captureSecurityLogs(),
            processes = captureRunningProcesses(),
            deviceState = captureDeviceState(),
        )
        return gson.toJson(snapshot)
    }

    // =========================================================
    //  NETWORK TRAFFIC
    // =========================================================

    private fun captureNetworkStats(): NetworkSnapshot {
        val activeConnections = captureActiveConnections()
        return NetworkSnapshot(
            totalRxBytes = TrafficStats.getTotalRxBytes(),
            totalTxBytes = TrafficStats.getTotalTxBytes(),
            mobileRxBytes = TrafficStats.getMobileRxBytes(),
            mobileTxBytes = TrafficStats.getMobileTxBytes(),
            activeConnections = activeConnections,
        )
    }

    private fun captureActiveConnections(): List<String> {
        val connections = mutableListOf<String>()
        try {
            // Read /proc/net/tcp and /proc/net/tcp6 for active connections
            listOf("/proc/net/tcp", "/proc/net/tcp6").forEach { path ->
                val file = java.io.File(path)
                if (file.exists()) {
                    file.readLines().drop(1).forEach { line ->
                        val parts = line.trim().split("\\s+".toRegex())
                        if (parts.size >= 4) {
                            val remoteAddr = parseHexIpPort(parts[2])
                            if (remoteAddr.isNotEmpty() && !remoteAddr.startsWith("0.0.0.0")) {
                                connections.add(remoteAddr)
                            }
                        }
                    }
                }
            }
        } catch (e: Exception) {
            Log.w(TAG, "Could not read /proc/net/tcp: ${e.message}")
        }
        return connections.distinct().take(50)  // cap at 50
    }

    private fun parseHexIpPort(hexAddr: String): String {
        return try {
            val parts = hexAddr.split(":")
            val hexIp = parts[0]
            val port = parts[1].toInt(16)
            val ipBytes = hexIp.chunked(2).map { it.toInt(16) }
            // /proc/net/tcp uses little-endian for IPv4
            "${ipBytes[3]}.${ipBytes[2]}.${ipBytes[1]}.${ipBytes[0]}:$port"
        } catch (e: Exception) {
            ""
        }
    }

    // =========================================================
    //  APP ACTIVITY
    // =========================================================

    private fun captureAppActivity(): List<AppActivity> {
        val usageStatsManager = context.getSystemService(Context.USAGE_STATS_SERVICE) as? UsageStatsManager
            ?: return emptyList()

        val endTime = System.currentTimeMillis()
        val startTime = endTime - (5 * 60 * 1000) // last 5 minutes

        return try {
            usageStatsManager.queryUsageStats(
                UsageStatsManager.INTERVAL_BEST, startTime, endTime
            ).filter { it.totalTimeInForeground > 0 }
                .sortedByDescending { it.lastTimeUsed }
                .take(20)
                .map { stats ->
                    AppActivity(
                        packageName = stats.packageName,
                        lastUsed = dateFormat.format(Date(stats.lastTimeUsed)),
                        totalForegroundMs = stats.totalTimeInForeground,
                        isSystemApp = isSystemPackage(stats.packageName),
                    )
                }
        } catch (e: SecurityException) {
            Log.w(TAG, "Usage stats permission not granted")
            emptyList()
        }
    }

    private fun isSystemPackage(packageName: String): Boolean {
        return try {
            val info = context.packageManager.getApplicationInfo(packageName, 0)
            (info.flags and android.content.pm.ApplicationInfo.FLAG_SYSTEM) != 0
        } catch (e: Exception) {
            false
        }
    }

    // =========================================================
    //  SYSTEM SECURITY LOGS
    // =========================================================

    private fun captureSecurityLogs(): List<SystemLogEntry> {
        val logs = mutableListOf<SystemLogEntry>()
        try {
            // Capture logcat entries with security-relevant tags
            val process = Runtime.getRuntime().exec(
                arrayOf("logcat", "-d", "-v", "time", "-t", "100",
                    "*:W")  // Warnings and above
            )
            val reader = BufferedReader(InputStreamReader(process.inputStream))

            val securityTags = setOf(
                "SecurityException", "SELinux", "PackageManager",
                "InstallReceiver", "VpnService", "Permission",
                "CertInstaller", "KeyStore", "Netd", "FirewallController"
            )

            reader.forEachLine { line ->
                val matchesSecurityTag = securityTags.any { tag ->
                    line.contains(tag, ignoreCase = true)
                }
                if (matchesSecurityTag && logs.size < 50) {
                    val entry = parseLogcatLine(line)
                    if (entry != null) logs.add(entry)
                }
            }
            process.waitFor()
        } catch (e: Exception) {
            Log.w(TAG, "Could not capture logcat: ${e.message}")
        }
        return logs
    }

    private fun parseLogcatLine(line: String): SystemLogEntry? {
        // Format: "MM-DD HH:MM:SS.mmm level/tag(pid): message"
        return try {
            val level = when {
                line.contains(" W/") || line.contains(" W ") -> "WARNING"
                line.contains(" E/") || line.contains(" E ") -> "ERROR"
                line.contains(" F/") || line.contains(" F ") -> "FATAL"
                else -> "INFO"
            }
            SystemLogEntry(
                timestamp = dateFormat.format(Date()),
                level = level,
                tag = extractTag(line),
                message = line.take(200),  // truncate long messages
            )
        } catch (e: Exception) {
            null
        }
    }

    private fun extractTag(line: String): String {
        val regex = """\s[VDIWEF]/(\S+)""".toRegex()
        return regex.find(line)?.groupValues?.getOrNull(1) ?: "unknown"
    }

    // =========================================================
    //  RUNNING PROCESSES
    // =========================================================

    private fun captureRunningProcesses(): List<ProcessInfo> {
        val processes = mutableListOf<ProcessInfo>()
        try {
            val procDir = java.io.File("/proc")
            procDir.listFiles()?.forEach { dir ->
                val pid = dir.name.toIntOrNull() ?: return@forEach
                val cmdlineFile = java.io.File(dir, "cmdline")
                if (cmdlineFile.exists()) {
                    val name = cmdlineFile.readText().trim('\u0000').ifEmpty { return@forEach }
                    val statusFile = java.io.File(dir, "status")
                    val uid = if (statusFile.exists()) {
                        statusFile.readLines().find { it.startsWith("Uid:") }
                            ?.split("\t")?.getOrNull(1)?.trim()?.toIntOrNull() ?: -1
                    } else -1

                    processes.add(ProcessInfo(name = name, pid = pid, uid = uid))
                }
            }
        } catch (e: Exception) {
            Log.w(TAG, "Process enumeration limited: ${e.message}")
        }
        return processes.take(50)
    }

    // =========================================================
    //  DEVICE STATE
    // =========================================================

    private fun captureDeviceState(): DeviceState {
        val batteryManager = context.getSystemService(Context.BATTERY_SERVICE)
            as? android.os.BatteryManager

        return DeviceState(
            isScreenOn = isScreenOn(),
            batteryLevel = batteryManager?.getIntProperty(
                android.os.BatteryManager.BATTERY_PROPERTY_CAPACITY
            ) ?: -1,
            isCharging = batteryManager?.isCharging ?: false,
            androidVersion = Build.VERSION.RELEASE,
            deviceModel = "${Build.MANUFACTURER} ${Build.MODEL}",
        )
    }

    private fun isScreenOn(): Boolean {
        val powerManager = context.getSystemService(Context.POWER_SERVICE)
            as? android.os.PowerManager
        return powerManager?.isInteractive ?: true
    }
}
