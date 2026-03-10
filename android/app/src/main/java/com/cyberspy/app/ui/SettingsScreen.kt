package com.cyberspy.app.ui

import android.content.Context
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.ArrowBack
import androidx.compose.material.icons.filled.CheckCircle
import androidx.compose.material.icons.filled.Wifi
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.cyberspy.app.network.ApiClient
import com.cyberspy.app.network.AppPreferences
import kotlinx.coroutines.launch

// Reusing the colour palette from MainActivity
private val CyberDark    = Color(0xFF080E1C)
private val CyberSurface = Color(0xFF0F1628)
private val CyberCyan    = Color(0xFF00D4FF)
private val CyberGreen   = Color(0xFF00FF88)
private val CyberRed     = Color(0xFFFF3366)
private val CyberTextPrimary   = Color(0xFFE0E8F0)
private val CyberTextSecondary = Color(0xFF7B8FA8)

/**
 * SettingsScreen — lets the user enter the backend server IP address.
 *
 * Workflow:
 *  1. User opens Settings from the dashboard.
 *  2. Types their laptop's local IP (e.g., 192.168.1.42) and port.
 *  3. Taps "Test & Save" — app pings the /health endpoint.
 *  4. If reachable, saves and returns to the dashboard.
 */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun SettingsScreen(onBack: () -> Unit) {
    val context = LocalContext.current
    val scope   = rememberCoroutineScope()

    // Load stored IP or sensible default
    var ipInput by remember {
        mutableStateOf(
            AppPreferences.getBackendUrl(context)
                .removePrefix("http://")
                .removePrefix("https://")
        )
    }
    var victimState by remember { mutableStateOf(AppPreferences.getVictimState(context)) }
    var testStatus  by remember { mutableStateOf<String?>(null) }
    var testSuccess by remember { mutableStateOf(false) }
    var isTesting   by remember { mutableStateOf(false) }

    Scaffold(
        containerColor = CyberDark,
        topBar = {
            TopAppBar(
                title = { Text("BACKEND SETTINGS", color = CyberCyan, fontSize = 14.sp, letterSpacing = 2.sp, fontWeight = FontWeight.Bold) },
                navigationIcon = {
                    IconButton(onClick = onBack) {
                        Icon(Icons.Default.ArrowBack, "Back", tint = CyberTextSecondary)
                    }
                },
                colors = TopAppBarDefaults.topAppBarColors(containerColor = CyberDark),
            )
        }
    ) { padding ->
        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(padding)
                .padding(horizontal = 20.dp),
        ) {
            Spacer(modifier = Modifier.height(16.dp))

            InfoCard()

            Spacer(modifier = Modifier.height(24.dp))

            // ---- Backend URL Field ----
            Text("BACKEND IP & PORT", color = CyberCyan, fontSize = 11.sp,
                fontWeight = FontWeight.Bold, letterSpacing = 2.sp)
            Spacer(modifier = Modifier.height(8.dp))
            OutlinedTextField(
                value = ipInput,
                onValueChange = { ipInput = it; testStatus = null },
                modifier = Modifier.fillMaxWidth(),
                placeholder = { Text("192.168.1.42:8000", color = CyberTextSecondary) },
                label = { Text("e.g. 192.168.1.42:8000", color = CyberTextSecondary) },
                singleLine = true,
                keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Uri),
                colors = OutlinedTextFieldDefaults.colors(
                    focusedBorderColor   = CyberCyan,
                    unfocusedBorderColor = CyberTextSecondary,
                    focusedTextColor     = CyberTextPrimary,
                    unfocusedTextColor   = CyberTextPrimary,
                    cursorColor          = CyberCyan,
                ),
            )

            Spacer(modifier = Modifier.height(16.dp))

            // ---- State Code Field ----
            Text("YOUR STATE (for authority routing)", color = CyberCyan, fontSize = 11.sp,
                fontWeight = FontWeight.Bold, letterSpacing = 2.sp)
            Spacer(modifier = Modifier.height(8.dp))
            OutlinedTextField(
                value = victimState,
                onValueChange = { if (it.length <= 2) victimState = it.uppercase() },
                modifier = Modifier.fillMaxWidth(),
                placeholder = { Text("KA / MH / DL / TN...", color = CyberTextSecondary) },
                label = { Text("2-letter Indian state code", color = CyberTextSecondary) },
                singleLine = true,
                colors = OutlinedTextFieldDefaults.colors(
                    focusedBorderColor   = CyberCyan,
                    unfocusedBorderColor = CyberTextSecondary,
                    focusedTextColor     = CyberTextPrimary,
                    unfocusedTextColor   = CyberTextPrimary,
                    cursorColor          = CyberCyan,
                ),
            )

            Spacer(modifier = Modifier.height(24.dp))

            // ---- Test & Save Button ----
            Button(
                onClick = {
                    scope.launch {
                        isTesting = true
                        testStatus = null
                        val fullUrl = buildUrl(ipInput)
                        // Save first so ApiClient picks it up
                        AppPreferences.setBackendUrl(context, fullUrl)
                        AppPreferences.setVictimState(context, victimState)
                        ApiClient.initialize(context)

                        try {
                            val resp = ApiClient.getApi(context).healthCheck()
                            if (resp.isSuccessful) {
                                testSuccess = true
                                testStatus = "Connected! Backend is online ✓"
                            } else {
                                testSuccess = false
                                testStatus = "Reached server but got ${resp.code()} — check logs"
                            }
                        } catch (e: Exception) {
                            testSuccess = false
                            testStatus = "Cannot reach $fullUrl — check IP and that backend is running"
                        }
                        isTesting = false
                    }
                },
                modifier   = Modifier.fillMaxWidth().height(52.dp),
                shape      = RoundedCornerShape(8.dp),
                colors     = ButtonDefaults.buttonColors(containerColor = CyberCyan),
                enabled    = !isTesting && ipInput.isNotBlank(),
            ) {
                if (isTesting) {
                    CircularProgressIndicator(color = CyberDark, modifier = Modifier.size(22.dp), strokeWidth = 2.dp)
                } else {
                    Icon(Icons.Default.Wifi, null, tint = CyberDark)
                    Spacer(modifier = Modifier.width(8.dp))
                    Text("TEST CONNECTION & SAVE", color = CyberDark, fontWeight = FontWeight.Bold, letterSpacing = 1.sp)
                }
            }

            // ---- Connection Status ----
            testStatus?.let { msg ->
                Spacer(modifier = Modifier.height(16.dp))
                Card(
                    colors = CardDefaults.cardColors(
                        containerColor = if (testSuccess) CyberGreen.copy(alpha = 0.1f) else CyberRed.copy(alpha = 0.1f)
                    ),
                    shape = RoundedCornerShape(8.dp),
                ) {
                    Row(
                        modifier = Modifier.padding(14.dp),
                        verticalAlignment = Alignment.CenterVertically,
                    ) {
                        Icon(
                            Icons.Default.CheckCircle, null,
                            tint = if (testSuccess) CyberGreen else CyberRed,
                            modifier = Modifier.size(20.dp),
                        )
                        Spacer(modifier = Modifier.width(10.dp))
                        Text(msg, color = if (testSuccess) CyberGreen else CyberRed, fontSize = 13.sp)
                    }
                }
            }
        }
    }
}

@Composable
private fun InfoCard() {
    Card(
        colors = CardDefaults.cardColors(containerColor = CyberSurface),
        shape  = RoundedCornerShape(10.dp),
    ) {
        Column(modifier = Modifier.padding(16.dp)) {
            Text("HOW TO CONNECT", color = CyberCyan, fontSize = 11.sp,
                fontWeight = FontWeight.Bold, letterSpacing = 2.sp)
            Spacer(modifier = Modifier.height(10.dp))
            InfoRow("1", "Connect your phone and laptop to the SAME Wi-Fi network")
            InfoRow("2", "On your laptop, run the CyberSpy backend server")
            InfoRow("3", "Find your laptop's local IP: run `ipconfig` in Command Prompt")
            InfoRow("4", "Look for 'IPv4 Address' under your Wi-Fi adapter (e.g. 192.168.1.42)")
            InfoRow("5", "Enter that IP + port 8000 below and tap Test")
        }
    }
}

@Composable
private fun InfoRow(num: String, text: String) {
    Row(modifier = Modifier.padding(vertical = 3.dp)) {
        Text("$num. ", color = CyberCyan, fontWeight = FontWeight.Bold, fontSize = 13.sp)
        Text(text, color = CyberTextSecondary, fontSize = 13.sp)
    }
}

private fun buildUrl(input: String): String {
    val clean = input.trim()
        .removePrefix("http://")
        .removePrefix("https://")
    return "http://$clean"
}
