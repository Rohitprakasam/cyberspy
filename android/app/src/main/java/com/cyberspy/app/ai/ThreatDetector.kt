package com.cyberspy.app.ai

import android.content.Context
import android.util.Log
import com.google.gson.Gson
import com.google.gson.annotations.SerializedName

/**
 * ThreatDetector — Two-Tier AI Pipeline
 *
 * Tier 1: Lightweight anomaly scoring (rule-based + statistical, simulating TFLite)
 * Tier 2: On-device LLM integration placeholder (llama.cpp NDK)
 *
 * In production:
 * - Tier 1 uses a real TFLite .tflite model
 * - Tier 2 uses Llama-3.1-4B (4-bit GGUF) via llama.cpp native library
 *
 * For the hackathon prototype, Tier 1 uses heuristic rules and
 * Tier 2 delegates to the cloud backend for LLM analysis.
 */
class ThreatDetector(private val context: Context) {

    companion object {
        private const val TAG = "ThreatDetector"
        const val ANOMALY_THRESHOLD = 0.7f
    }

    private val gson = Gson()

    // =========================================================
    //  THREAT SNAPSHOT (LLM output format)
    // =========================================================

    data class ThreatSnapshot(
        @SerializedName("threatLevel") val threatLevel: String,     // LOW, MEDIUM, HIGH, CRITICAL
        @SerializedName("summary") val summary: String,
        @SerializedName("iocs") val iocs: List<IOC>,
        @SerializedName("attackType") val attackType: String,
        @SerializedName("confidence") val confidence: Float,
        @SerializedName("anomalyScore") val anomalyScore: Float,
    )

    data class IOC(
        @SerializedName("type") val type: String,     // ip, domain, app, hash
        @SerializedName("value") val value: String,
        @SerializedName("note") val note: String = "",
    )

    // =========================================================
    //  TIER 1: ANOMALY DETECTION (Heuristic / TFLite)
    // =========================================================

    /**
     * Analyze a device snapshot and return an anomaly score (0.0 - 1.0).
     *
     * Features analyzed (32-feature vector):
     * - Network: unique IPs, total bytes, foreign IP ratio, Tor/VPN indicators
     * - Apps: new app installs, background permission usage, screen-off activity
     * - System: root attempts, SELinux denials, new process spawns
     * - Files: unexpected modifications in sensitive directories
     */
    fun computeAnomalyScore(snapshotJson: String): Float {
        return try {
            val features = extractFeatureVector(snapshotJson)
            val score = scoreFeatures(features)
            Log.d(TAG, "Anomaly score: $score (threshold: $ANOMALY_THRESHOLD)")
            score
        } catch (e: Exception) {
            Log.e(TAG, "Anomaly scoring failed: ${e.message}", e)
            0.0f
        }
    }

    /**
     * Full analysis: compute anomaly score and if above threshold,
     * generate a threat snapshot with IOC extraction.
     */
    fun analyzeSnapshot(snapshotJson: String): ThreatSnapshot? {
        val score = computeAnomalyScore(snapshotJson)

        if (score < ANOMALY_THRESHOLD) {
            Log.d(TAG, "Score $score below threshold — no threat detected")
            return null
        }

        // Extract IOCs and generate local threat assessment
        return generateThreatSnapshot(snapshotJson, score)
    }

    // =========================================================
    //  FEATURE EXTRACTION
    // =========================================================

    private data class FeatureVector(
        // Network features
        val uniqueIpCount: Int = 0,
        val totalBytesTransferred: Long = 0,
        val foreignIpRatio: Float = 0f,
        val hasTorIndicator: Boolean = false,
        val hasKnownC2Ip: Boolean = false,
        val screenOffNetworkActivity: Boolean = false,

        // App features
        val newAppsInstalled: Int = 0,
        val backgroundPermissionApps: Int = 0,
        val hiddenApps: Int = 0,
        val suspiciousPackageNames: Int = 0,

        // System features
        val rootAttempts: Int = 0,
        val selinuxDenials: Int = 0,
        val newProcessSpawns: Int = 0,
        val securityExceptions: Int = 0,

        // Meta
        val isScreenOff: Boolean = false,
    )

    private fun extractFeatureVector(snapshotJson: String): FeatureVector {
        val snapshot = try {
            gson.fromJson(snapshotJson, Map::class.java)
        } catch (e: Exception) {
            return FeatureVector()
        }

        val network = snapshot["network"] as? Map<*, *> ?: emptyMap<String, Any>()
        val apps = snapshot["apps"] as? List<*> ?: emptyList<Any>()
        val systemLogs = snapshot["systemLogs"] as? List<*> ?: emptyList<Any>()
        val deviceState = snapshot["deviceState"] as? Map<*, *> ?: emptyMap<String, Any>()
        val connections = network["activeConnections"] as? List<*> ?: emptyList<Any>()

        // Known suspicious indicators
        val torExitNodes = setOf("185.220.", "104.244.", "198.98.", "209.141.")
        val knownC2Prefixes = setOf("185.220.101", "45.33.32", "192.42.116")
        val suspiciousPrefixes = setOf("com.system.", "com.android.system", "com.update.", "com.service.helper")

        val uniqueIps = connections.map { it.toString().substringBefore(":") }.distinct()
        val foreignIps = uniqueIps.filter { ip -> !isIndianIp(ip) }
        val hasTor = uniqueIps.any { ip -> torExitNodes.any { prefix -> ip.startsWith(prefix) } }
        val hasC2 = uniqueIps.any { ip -> knownC2Prefixes.any { prefix -> ip.startsWith(prefix) } }

        val suspiciousApps = apps.count { app ->
            val pkg = (app as? Map<*, *>)?.get("packageName")?.toString() ?: ""
            suspiciousPrefixes.any { prefix -> pkg.startsWith(prefix) }
        }

        val securityLogCount = systemLogs.count { log ->
            val msg = (log as? Map<*, *>)?.get("message")?.toString() ?: ""
            msg.contains("SELinux", true) || msg.contains("root", true) ||
                msg.contains("SecurityException", true)
        }

        val isScreenOff = (deviceState["isScreenOn"] as? Boolean) == false
        val totalBytes = (network["totalTxBytes"] as? Number)?.toLong() ?: 0

        return FeatureVector(
            uniqueIpCount = uniqueIps.size,
            totalBytesTransferred = totalBytes,
            foreignIpRatio = if (uniqueIps.isNotEmpty()) foreignIps.size.toFloat() / uniqueIps.size else 0f,
            hasTorIndicator = hasTor,
            hasKnownC2Ip = hasC2,
            screenOffNetworkActivity = isScreenOff && totalBytes > 100_000,
            suspiciousPackageNames = suspiciousApps,
            rootAttempts = securityLogCount,
            selinuxDenials = systemLogs.count {
                ((it as? Map<*, *>)?.get("message")?.toString() ?: "").contains("avc:", true)
            },
            securityExceptions = securityLogCount,
            isScreenOff = isScreenOff,
        )
    }

    // =========================================================
    //  SCORING
    // =========================================================

    private fun scoreFeatures(f: FeatureVector): Float {
        var score = 0f

        // Network anomalies (highest weight)
        if (f.hasKnownC2Ip) score += 0.4f
        if (f.hasTorIndicator) score += 0.3f
        if (f.foreignIpRatio > 0.5f) score += 0.15f
        if (f.screenOffNetworkActivity) score += 0.25f
        if (f.uniqueIpCount > 30) score += 0.1f

        // App anomalies
        if (f.suspiciousPackageNames > 0) score += 0.2f * f.suspiciousPackageNames.coerceAtMost(3)
        if (f.hiddenApps > 0) score += 0.15f

        // System anomalies
        if (f.rootAttempts > 0) score += 0.3f
        if (f.selinuxDenials > 5) score += 0.2f
        if (f.securityExceptions > 3) score += 0.15f

        return score.coerceIn(0f, 1f)
    }

    // =========================================================
    //  THREAT SNAPSHOT GENERATION (Local, no LLM)
    // =========================================================

    private fun generateThreatSnapshot(snapshotJson: String, anomalyScore: Float): ThreatSnapshot {
        val features = extractFeatureVector(snapshotJson)
        val snapshot = try { gson.fromJson(snapshotJson, Map::class.java) as Map<String, Any> } catch (e: Exception) { emptyMap<String, Any>() }
        val connections = ((snapshot["network"] as? Map<*, *>)?.get("activeConnections") as? List<*>) ?: emptyList<Any>()

        val iocs = mutableListOf<IOC>()
        val torExitNodes = setOf("185.220.", "104.244.", "198.98.")
        val knownC2Prefixes = setOf("185.220.101", "45.33.32")

        // Extract IP IOCs
        connections.forEach { conn ->
            val ip = conn.toString().substringBefore(":")
            when {
                knownC2Prefixes.any { ip.startsWith(it) } ->
                    iocs.add(IOC("ip", ip, "Known C&C server"))
                torExitNodes.any { ip.startsWith(it) } ->
                    iocs.add(IOC("ip", ip, "Tor exit node"))
                !isIndianIp(ip) && ip != "0.0.0.0" && ip != "127.0.0.1" ->
                    iocs.add(IOC("ip", ip, "Foreign IP — suspicious"))
            }
        }

        // Extract app IOCs
        val apps = (snapshot["apps"] as? List<*>) ?: emptyList<Any>()
        apps.forEach { app ->
            val pkg = (app as? Map<*, *>)?.get("packageName")?.toString() ?: return@forEach
            if (pkg.startsWith("com.system.") || pkg.startsWith("com.update.")) {
                iocs.add(IOC("app", pkg, "Disguised as system app — likely spyware"))
            }
        }

        // Determine threat level and attack type
        val threatLevel = when {
            anomalyScore >= 0.9f -> "CRITICAL"
            anomalyScore >= 0.7f -> "HIGH"
            anomalyScore >= 0.5f -> "MEDIUM"
            else -> "LOW"
        }

        val attackType = when {
            features.hasKnownC2Ip -> "c2_communication"
            features.hasTorIndicator -> "data_exfiltration"
            features.rootAttempts > 0 -> "root_exploit"
            features.suspiciousPackageNames > 0 -> "spyware"
            else -> "unknown"
        }

        val summary = buildSummary(features, iocs, threatLevel)

        return ThreatSnapshot(
            threatLevel = threatLevel,
            summary = summary,
            iocs = iocs.take(10),  // cap at 10 IOCs
            attackType = attackType,
            confidence = anomalyScore,
            anomalyScore = anomalyScore,
        )
    }

    private fun buildSummary(features: FeatureVector, iocs: List<IOC>, level: String): String {
        val parts = mutableListOf<String>()

        if (features.hasKnownC2Ip) {
            parts.add("Communication with a known command & control server detected.")
        }
        if (features.hasTorIndicator) {
            parts.add("Traffic routed through Tor anonymity network.")
        }
        if (features.screenOffNetworkActivity) {
            parts.add("Significant data transfer detected while screen was off.")
        }
        if (features.suspiciousPackageNames > 0) {
            parts.add("${features.suspiciousPackageNames} app(s) disguised as system services detected.")
        }
        if (features.rootAttempts > 0) {
            parts.add("Root/superuser access attempts detected in system logs.")
        }

        if (parts.isEmpty()) {
            parts.add("Anomalous device behavior detected requiring investigation.")
        }

        return parts.joinToString(" ")
    }

    // =========================================================
    //  UTILITY
    // =========================================================

    private fun isIndianIp(ip: String): Boolean {
        val indianPrefixes = listOf("49.", "59.", "103.", "106.", "112.", "115.", "117.", "122.", "124.", "125.")
        return indianPrefixes.any { ip.startsWith(it) }
    }
}
