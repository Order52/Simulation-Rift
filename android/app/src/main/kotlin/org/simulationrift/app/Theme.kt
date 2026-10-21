package org.simulationrift.app

import android.os.Build
import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.darkColorScheme
import androidx.compose.material3.dynamicDarkColorScheme
import androidx.compose.material3.dynamicLightColorScheme
import androidx.compose.material3.lightColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.runtime.CompositionLocalProvider
import androidx.compose.runtime.Immutable
import androidx.compose.runtime.staticCompositionLocalOf
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext

// The browser app has the same file (org.simulationrift.browser.Theme.kt):
// the two apps share no Compose code, and their screens must look alike.

/**
 * Colours that mean something, whatever the wallpaper: dynamic colour
 * changes the brand colours, never these. Danger is the scheme's error.
 */
@Immutable
data class StatusColors(
    val safe: Color,
    val onSafe: Color,
    val safeContainer: Color,
    val onSafeContainer: Color,
    val warning: Color,
    val warningContainer: Color,
    val onWarningContainer: Color,
)

private val LightStatus = StatusColors(
    safe = Color(0xFF1B7F3B),
    onSafe = Color.White,
    safeContainer = Color(0xFFD3F5DC),
    onSafeContainer = Color(0xFF00210C),
    warning = Color(0xFF9A5B00),
    warningContainer = Color(0xFFFFE1BC),
    onWarningContainer = Color(0xFF2E1800),
)

private val DarkStatus = StatusColors(
    safe = Color(0xFF7EDB9B),
    onSafe = Color(0xFF00391A),
    safeContainer = Color(0xFF0F5228),
    onSafeContainer = Color(0xFFB8F5C9),
    warning = Color(0xFFFFB95C),
    warningContainer = Color(0xFF5C3700),
    onWarningContainer = Color(0xFFFFDDB6),
)

val LocalStatusColors = staticCompositionLocalOf { LightStatus }

/** Rift's violet, for devices without dynamic colour (before API 31). */
private val LightBrand = lightColorScheme(
    primary = Color(0xFF5B3FD9),
    onPrimary = Color.White,
    primaryContainer = Color(0xFFE6DEFF),
    onPrimaryContainer = Color(0xFF1B0063),
    secondary = Color(0xFF5E5C71),
    onSecondary = Color.White,
    secondaryContainer = Color(0xFFE4DFF9),
    onSecondaryContainer = Color(0xFF1B192C),
    tertiary = Color(0xFF006A6A),
    onTertiary = Color.White,
    tertiaryContainer = Color(0xFF9CF1F0),
    onTertiaryContainer = Color(0xFF002020),
    background = Color(0xFFFBF8FF),
    onBackground = Color(0xFF1B1B21),
    surface = Color(0xFFFBF8FF),
    onSurface = Color(0xFF1B1B21),
    surfaceVariant = Color(0xFFE5E1EC),
    onSurfaceVariant = Color(0xFF47464F),
    surfaceContainerLowest = Color.White,
    surfaceContainerLow = Color(0xFFF5F2FA),
    surfaceContainer = Color(0xFFEFEDF4),
    surfaceContainerHigh = Color(0xFFE9E7EF),
    surfaceContainerHighest = Color(0xFFE4E1E9),
    outline = Color(0xFF787680),
    outlineVariant = Color(0xFFC8C5D0),
)

private val DarkBrand = darkColorScheme(
    primary = Color(0xFFC9BEFF),
    onPrimary = Color(0xFF2E1A87),
    primaryContainer = Color(0xFF4527B9),
    onPrimaryContainer = Color(0xFFE6DEFF),
    secondary = Color(0xFFC8C3DC),
    onSecondary = Color(0xFF302E41),
    secondaryContainer = Color(0xFF474459),
    onSecondaryContainer = Color(0xFFE4DFF9),
    tertiary = Color(0xFF80D5D4),
    onTertiary = Color(0xFF003737),
    tertiaryContainer = Color(0xFF004F4F),
    onTertiaryContainer = Color(0xFF9CF1F0),
    background = Color(0xFF131318),
    onBackground = Color(0xFFE4E1E9),
    surface = Color(0xFF131318),
    onSurface = Color(0xFFE4E1E9),
    surfaceVariant = Color(0xFF47464F),
    onSurfaceVariant = Color(0xFFC8C5D0),
    surfaceContainerLowest = Color(0xFF0E0E13),
    surfaceContainerLow = Color(0xFF1B1B21),
    surfaceContainer = Color(0xFF1F1F25),
    surfaceContainerHigh = Color(0xFF2A292F),
    surfaceContainerHighest = Color(0xFF35343A),
    outline = Color(0xFF928F9A),
    outlineVariant = Color(0xFF47464F),
)

/** Light or dark with the system; the wallpaper's colours where Android offers them (API 31+). */
@Composable
fun RiftTheme(content: @Composable () -> Unit) {
    val dark = isSystemInDarkTheme()
    val colors = when {
        Build.VERSION.SDK_INT >= Build.VERSION_CODES.S -> {
            val context = LocalContext.current
            if (dark) dynamicDarkColorScheme(context) else dynamicLightColorScheme(context)
        }
        dark -> DarkBrand
        else -> LightBrand
    }
    CompositionLocalProvider(LocalStatusColors provides if (dark) DarkStatus else LightStatus) {
        MaterialTheme(colorScheme = colors, content = content)
    }
}
