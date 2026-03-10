package com.cyberspy.app.ui

import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.navigation.compose.NavHost
import androidx.navigation.compose.composable
import androidx.navigation.compose.rememberNavController
import com.cyberspy.app.ui.theme.CyberSpyTheme
import kotlinx.coroutines.launch
import okhttp3.MediaType.Companion.toMediaTypeOrNull
import okhttp3.RequestBody.Companion.toRequestBody

class MainActivity : ComponentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        enableEdgeToEdge()
        setContent {
            CyberSpyTheme {
                val navController = rememberNavController()
                NavHost(navController = navController, startDestination = "dashboard") {
                    composable("dashboard") {
                        CyberSpyDashboard(onOpenSettings = { navController.navigate("settings") })
                    }
                    composable("settings") {
                        SettingsScreen(onBack = { navController.popBackStack() })
                    }
                }
            }
        }
    }
}

// ============================================================
//  COLOR PALETTE
// ============================================================

private val CyberDark = Color(0xFF080E1C)
private val CyberSurface = Color(0xFF0F1628)
private val CyberBorder = Color(0xFF1E2D45)
private val CyberCyan = Color(0xFF00D4FF)
private val CyberGreen = Color(0xFF00FF88)
private val CyberPurple = Color(0xFF7B2FFF)
private val CyberRed = Color(0xFFFF3366)
private val CyberYellow = Color(0xFFFFB800)
private val CyberTextPrimary = Color(0xFFE0E8F0)
private val CyberTextSecondary = Color(0xFF7B8FA8)

// ============================================================
//  DASHBOARD
// ============================================================

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun CyberSpyDashboard(onOpenSettings: () -> Unit = {}) {
    val context = androidx.compose.ui.platform.LocalContext.current
    val scope = rememberCoroutineScope()

    // State
    var isMonitoring by remember { mutableStateOf(true) }
    var threatLevel by remember { mutableStateOf("SECURE") }
    var shardCount by remember { mutableStateOf(247) }
    var alertCount by remember { mutableStateOf(3) }
    
    var showReportDialog by remember { mutableStateOf(false) }
    var isSubmitting by remember { mutableStateOf(false) }
    var submissionResult by remember { mutableStateOf<String?>(null) }

    Scaffold(
        containerColor = CyberDark,
        topBar = {
            TopAppBar(
                title = {
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        Text(
                            "CYBER",
                            color = CyberCyan,
                            fontWeight = FontWeight.Bold,
                            fontSize = 20.sp
                        )
                        Text(
                            "SPY",
                            color = CyberTextPrimary,
                            fontWeight = FontWeight.Bold,
                            fontSize = 20.sp
                        )
                    }
                },
                actions = {
                    IconButton(onClick = onOpenSettings) {
                        Icon(Icons.Default.Settings, "Settings", tint = CyberTextSecondary)
                    }
                },
                colors = TopAppBarDefaults.topAppBarColors(containerColor = CyberDark)
            )
        }

    ) { padding ->
        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(padding)
                .padding(horizontal = 16.dp)
                .verticalScroll(rememberScrollState()),
            horizontalAlignment = Alignment.CenterHorizontally,
        ) {
            Spacer(modifier = Modifier.height(8.dp))

            // --- Monitoring Status ---
            MonitoringStatusCard(isMonitoring) { isMonitoring = !isMonitoring }

            Spacer(modifier = Modifier.height(16.dp))

            // --- Stats Row ---
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.spacedBy(12.dp)
            ) {
                StatCard(
                    modifier = Modifier.weight(1f),
                    icon = Icons.Default.Shield,
                    label = "THREAT LEVEL",
                    value = threatLevel,
                    color = CyberGreen,
                )
                StatCard(
                    modifier = Modifier.weight(1f),
                    icon = Icons.Default.Storage,
                    label = "EVIDENCE SHARDS",
                    value = "$shardCount",
                    color = CyberCyan,
                )
                StatCard(
                    modifier = Modifier.weight(1f),
                    icon = Icons.Default.Warning,
                    label = "ALERTS",
                    value = "$alertCount",
                    color = if (alertCount > 0) CyberYellow else CyberGreen,
                )
            }

            Spacer(modifier = Modifier.height(24.dp))

            // --- REPORT BUTTON (Core UX) ---
            if (isSubmitting) {
                CircularProgressIndicator(color = CyberRed, modifier = Modifier.size(80.dp), strokeWidth = 8.dp)
                Spacer(modifier = Modifier.height(16.dp))
                Text("Analyzing Evidence & Submitting...", color = CyberRed, fontWeight = FontWeight.Bold)
                Spacer(modifier = Modifier.height(84.dp))
            } else {
                ReportButton(onClick = { showReportDialog = true })
            }

            Spacer(modifier = Modifier.height(24.dp))

            // --- Data Streams Status ---
            SectionHeader("ACTIVE DATA STREAMS")
            DataStreamItem("Network Traffic", "Monitoring all connections", CyberCyan, true)
            DataStreamItem("App Activity", "Tracking 47 apps", CyberPurple, true)
            DataStreamItem("System Logs", "Security events captured", CyberGreen, true)
            DataStreamItem("File System", "Watching sensitive dirs", CyberYellow, true)
            DataStreamItem("SMS/Call Metadata", "SIM swap detection active", CyberRed, true)

            Spacer(modifier = Modifier.height(24.dp))

            // --- Recent Alerts ---
            SectionHeader("RECENT ALERTS")
            AlertItem(
                "HIGH", "Suspicious connection to 185.220.101.47 (Tor Exit Node)",
                "2 hours ago", CyberRed
            )
            AlertItem(
                "MEDIUM", "App com.system.update.service accessing camera in background",
                "5 hours ago", CyberYellow
            )
            AlertItem(
                "LOW", "Unusual data transfer pattern detected (2.3MB screen-off)",
                "8 hours ago", CyberCyan
            )

            Spacer(modifier = Modifier.height(32.dp))
        }

        // Report confirmation dialog
        if (showReportDialog) {
            ReportConfirmationDialog(
                onConfirm = {
                    showReportDialog = false
                    isSubmitting = true
                    threatLevel = "ANALYZING"
                    
                    // Launch API call in coroutine
                    scope.launch {
                        try {
                            val api = com.cyberspy.app.network.ApiClient.getApi(context)
                            
                            // 1. Authenticate / Register Device
                            val authReq = com.cyberspy.app.network.DeviceRegisterRequest(
                                device_id = android.provider.Settings.Secure.getString(context.contentResolver, android.provider.Settings.Secure.ANDROID_ID) ?: "dev_123",
                                device_fingerprint = "sha256-hash-placeholder",
                                device_model = android.os.Build.MODEL,
                                android_version = android.os.Build.VERSION.RELEASE
                            )
                            val authRes = api.registerDevice(authReq)
                            val token = authRes.body()?.access_token ?: throw Exception("Auth failed")

                            // 2. Prepare Evidence Payload (Mocked for Demo)
                            val logsJson = """{"network": {"activeConnections": ["185.220.101.47:443", "8.8.8.8:53"]}, "apps": [], "systemLogs": [{"message": "avc: denied access"}]}"""
                            val logsBody = logsJson.toRequestBody("application/json".toMediaTypeOrNull())
                            val stateCode = com.cyberspy.app.network.AppPreferences.getVictimState(context)
                            val stateBody = stateCode.toRequestBody("text/plain".toMediaTypeOrNull())
                            
                            val fileBody = "encrypted-evidence-data-mock".toRequestBody("application/octet-stream".toMediaTypeOrNull())
                            val filePart = okhttp3.MultipartBody.Part.createFormData("evidence_file", "evidence_shards.enc", fileBody)

                            // 3. Submit
                            val submitRes = api.submitEvidence("Bearer $token", filePart, logsBody, stateBody)
                            
                            if (submitRes.isSuccessful) {
                                val caseId = submitRes.body()?.case_id
                                // Fetch analysis status
                                kotlinx.coroutines.delay(2000) // Wait for LLM backend
                                val statusRes = api.getCaseStatus("Bearer $token", caseId ?: "")
                                
                                val crn = statusRes.body()?.authority_crn
                                threatLevel = statusRes.body()?.threat_level ?: "HIGH"
                                submissionResult = "Report Submitted Successfully!\n\nThreat: $threatLevel\nRouted to: ${statusRes.body()?.dispatched_to}\nAuthority CRN: $crn"
                            } else {
                                submissionResult = "Failed to submit: HTTP ${submitRes.code()}"
                                threatLevel = "ERROR"
                            }
                        } catch (e: Exception) {
                            submissionResult = "Error: ${e.message}"
                            threatLevel = "ERROR"
                        } finally {
                            isSubmitting = false
                        }
                    }
                },
                onDismiss = { showReportDialog = false }
            )
        }

        // Result Dialog
        if (submissionResult != null) {
            AlertDialog(
                onDismissRequest = { submissionResult = null },
                containerColor = CyberSurface,
                title = { Text("Investigation Update", color = CyberCyan, fontWeight = FontWeight.Bold) },
                text = { Text(submissionResult!!) },
                confirmButton = {
                    Button(onClick = { submissionResult = null }, colors = ButtonDefaults.buttonColors(containerColor = CyberCyan)) {
                        Text("OK", color = CyberDark, fontWeight = FontWeight.Bold)
                    }
                }
            )
        }
    }
}

// ============================================================
//  COMPONENTS
// ============================================================

@Composable
fun MonitoringStatusCard(isActive: Boolean, onToggle: () -> Unit) {
    Card(
        modifier = Modifier.fillMaxWidth(),
        colors = CardDefaults.cardColors(containerColor = CyberSurface),
        shape = RoundedCornerShape(12.dp),
    ) {
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .padding(20.dp),
            verticalAlignment = Alignment.CenterVertically,
        ) {
            Box(
                modifier = Modifier
                    .size(12.dp)
                    .clip(CircleShape)
                    .background(if (isActive) CyberGreen else CyberRed)
            )
            Spacer(modifier = Modifier.width(12.dp))
            Column(modifier = Modifier.weight(1f)) {
                Text(
                    if (isActive) "MONITORING ACTIVE" else "MONITORING PAUSED",
                    color = CyberTextPrimary,
                    fontWeight = FontWeight.Bold,
                    fontSize = 14.sp,
                    letterSpacing = 2.sp,
                )
                Text(
                    if (isActive) "All data streams operational • Evidence vault secure"
                    else "Tap to resume monitoring",
                    color = CyberTextSecondary,
                    fontSize = 12.sp,
                )
            }
            Switch(
                checked = isActive,
                onCheckedChange = { onToggle() },
                colors = SwitchDefaults.colors(
                    checkedThumbColor = CyberGreen,
                    checkedTrackColor = CyberGreen.copy(alpha = 0.3f),
                )
            )
        }
    }
}

@Composable
fun StatCard(
    modifier: Modifier = Modifier,
    icon: ImageVector,
    label: String,
    value: String,
    color: Color,
) {
    Card(
        modifier = modifier,
        colors = CardDefaults.cardColors(containerColor = CyberSurface),
        shape = RoundedCornerShape(12.dp),
    ) {
        Column(
            modifier = Modifier
                .fillMaxWidth()
                .padding(16.dp),
            horizontalAlignment = Alignment.CenterHorizontally,
        ) {
            Icon(icon, label, tint = color, modifier = Modifier.size(24.dp))
            Spacer(modifier = Modifier.height(8.dp))
            Text(
                value,
                color = CyberTextPrimary,
                fontWeight = FontWeight.Bold,
                fontSize = 18.sp,
            )
            Text(
                label,
                color = CyberTextSecondary,
                fontSize = 9.sp,
                letterSpacing = 1.sp,
            )
        }
    }
}

@Composable
fun ReportButton(onClick: () -> Unit) {
    Button(
        onClick = onClick,
        modifier = Modifier
            .size(180.dp)
            .clip(CircleShape),
        colors = ButtonDefaults.buttonColors(containerColor = Color.Transparent),
        contentPadding = PaddingValues(0.dp),
    ) {
        Box(
            modifier = Modifier
                .fillMaxSize()
                .background(
                    brush = Brush.radialGradient(
                        colors = listOf(CyberRed, CyberRed.copy(alpha = 0.6f))
                    ),
                    shape = CircleShape,
                ),
            contentAlignment = Alignment.Center,
        ) {
            Column(horizontalAlignment = Alignment.CenterHorizontally) {
                Icon(
                    Icons.Default.Report,
                    "Report",
                    tint = Color.White,
                    modifier = Modifier.size(40.dp)
                )
                Spacer(modifier = Modifier.height(4.dp))
                Text(
                    "REPORT",
                    color = Color.White,
                    fontWeight = FontWeight.Black,
                    fontSize = 18.sp,
                    letterSpacing = 4.sp,
                )
                Text(
                    "Tap to send evidence",
                    color = Color.White.copy(alpha = 0.7f),
                    fontSize = 10.sp,
                )
            }
        }
    }
}

@Composable
fun SectionHeader(title: String) {
    Text(
        title,
        color = CyberCyan,
        fontSize = 11.sp,
        fontWeight = FontWeight.Bold,
        letterSpacing = 3.sp,
        modifier = Modifier
            .fillMaxWidth()
            .padding(bottom = 12.dp),
    )
}

@Composable
fun DataStreamItem(name: String, detail: String, color: Color, active: Boolean) {
    Card(
        modifier = Modifier
            .fillMaxWidth()
            .padding(bottom = 8.dp),
        colors = CardDefaults.cardColors(containerColor = CyberSurface),
        shape = RoundedCornerShape(8.dp),
    ) {
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .padding(14.dp),
            verticalAlignment = Alignment.CenterVertically,
        ) {
            Box(
                modifier = Modifier
                    .size(8.dp)
                    .clip(CircleShape)
                    .background(if (active) color else CyberTextSecondary)
            )
            Spacer(modifier = Modifier.width(12.dp))
            Column(modifier = Modifier.weight(1f)) {
                Text(name, color = CyberTextPrimary, fontWeight = FontWeight.SemiBold, fontSize = 13.sp)
                Text(detail, color = CyberTextSecondary, fontSize = 11.sp)
            }
            Text(
                if (active) "LIVE" else "OFF",
                color = if (active) color else CyberTextSecondary,
                fontSize = 9.sp,
                fontWeight = FontWeight.Bold,
                letterSpacing = 1.sp,
            )
        }
    }
}

@Composable
fun AlertItem(level: String, message: String, time: String, color: Color) {
    Card(
        modifier = Modifier
            .fillMaxWidth()
            .padding(bottom = 8.dp),
        colors = CardDefaults.cardColors(containerColor = CyberSurface),
        shape = RoundedCornerShape(8.dp),
    ) {
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .padding(14.dp),
            verticalAlignment = Alignment.Top,
        ) {
            Surface(
                color = color.copy(alpha = 0.15f),
                shape = RoundedCornerShape(4.dp),
            ) {
                Text(
                    level,
                    color = color,
                    fontSize = 9.sp,
                    fontWeight = FontWeight.Bold,
                    modifier = Modifier.padding(horizontal = 8.dp, vertical = 3.dp),
                    letterSpacing = 1.sp,
                )
            }
            Spacer(modifier = Modifier.width(12.dp))
            Column(modifier = Modifier.weight(1f)) {
                Text(message, color = CyberTextPrimary, fontSize = 12.sp)
                Text(time, color = CyberTextSecondary, fontSize = 10.sp, modifier = Modifier.padding(top = 4.dp))
            }
        }
    }
}

@Composable
fun ReportConfirmationDialog(onConfirm: () -> Unit, onDismiss: () -> Unit) {
    AlertDialog(
        onDismissRequest = onDismiss,
        containerColor = CyberSurface,
        titleContentColor = CyberTextPrimary,
        textContentColor = CyberTextSecondary,
        title = { Text("Submit Evidence Report?", fontWeight = FontWeight.Bold) },
        text = {
            Text(
                "This will:\n\n" +
                "1. Recover all evidence shards from hidden storage\n" +
                "2. Verify integrity (SHA-256) of each fragment\n" +
                "3. Generate an AI-powered forensic report\n" +
                "4. Submit directly to your State Cyber Cell\n\n" +
                "Your evidence will be court-admissible (Section 65B compliant)."
            )
        },
        confirmButton = {
            Button(
                onClick = onConfirm,
                colors = ButtonDefaults.buttonColors(containerColor = CyberRed)
            ) { Text("SEND REPORT", fontWeight = FontWeight.Bold) }
        },
        dismissButton = {
            TextButton(onClick = onDismiss) {
                Text("Cancel", color = CyberTextSecondary)
            }
        },
    )
}
