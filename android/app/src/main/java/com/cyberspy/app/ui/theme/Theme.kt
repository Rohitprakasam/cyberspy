package com.cyberspy.app.ui.theme

import android.os.Build
import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.material3.*
import androidx.compose.runtime.Composable
import androidx.compose.ui.graphics.Color

private val CyberSpyColorScheme = darkColorScheme(
    primary = Color(0xFF00D4FF),
    onPrimary = Color(0xFF080E1C),
    secondary = Color(0xFF00FF88),
    onSecondary = Color(0xFF080E1C),
    tertiary = Color(0xFF7B2FFF),
    background = Color(0xFF080E1C),
    surface = Color(0xFF0F1628),
    onBackground = Color(0xFFE0E8F0),
    onSurface = Color(0xFFE0E8F0),
    error = Color(0xFFFF3366),
    outline = Color(0xFF1E2D45),
)

@Composable
fun CyberSpyTheme(content: @Composable () -> Unit) {
    MaterialTheme(
        colorScheme = CyberSpyColorScheme,
        content = content,
    )
}
