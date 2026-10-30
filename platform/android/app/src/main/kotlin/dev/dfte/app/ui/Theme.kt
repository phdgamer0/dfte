// Copyright (c) 2026 Yazdan Samari. All rights reserved except as granted by LICENSE.
// SPDX-License-Identifier: PolyForm-Shield-1.0.0

package dev.dfte.app.ui

import androidx.compose.animation.core.CubicBezierEasing
import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.darkColorScheme
import androidx.compose.material3.lightColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.runtime.CompositionLocalProvider
import androidx.compose.runtime.Immutable
import androidx.compose.runtime.staticCompositionLocalOf
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.TextStyle
import androidx.compose.ui.text.font.Font
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.em
import androidx.compose.ui.unit.sp
import dev.dfte.app.R

// Tokens from .claude/design/ui-spec.html. Change them there first.

@Immutable
data class Palette(
    val bg: Color,
    val surface: Color,
    val surface2: Color,
    val line: Color,
    val text: Color,
    val text2: Color,
    val text3: Color,
    val accent: Color,
    val accentSoft: Color,
    val onAccent: Color,
    val ok: Color,
    val okSoft: Color,
    val warn: Color,
    val warnSoft: Color,
    val danger: Color,
    val dangerSoft: Color,
    val scrim: Color,
)

private val Light = Palette(
    bg = Color(0xFFF5F4F1), surface = Color(0xFFFFFFFF), surface2 = Color(0xFFEEEDE9), line = Color(0xFFE3E1DC),
    text = Color(0xFF1B1C1F), text2 = Color(0xFF6B6D74), text3 = Color(0xFF9A9CA3),
    accent = Color(0xFF5B5BD6), accentSoft = Color(0xFFECEBFB), onAccent = Color(0xFFFFFFFF),
    ok = Color(0xFF2F8F6B), okSoft = Color(0xFFE4F3EC), warn = Color(0xFFB7791F), warnSoft = Color(0xFFF8EEDB),
    danger = Color(0xFFC8443C), dangerSoft = Color(0xFFF9E5E3), scrim = Color(0x470A0A14),
)

private val Dark = Palette(
    bg = Color(0xFF111214), surface = Color(0xFF1A1B1E), surface2 = Color(0xFF232428), line = Color(0xFF2C2D32),
    text = Color(0xFFECECEF), text2 = Color(0xFFA3A5AD), text3 = Color(0xFF6F717A),
    accent = Color(0xFF8B8CF2), accentSoft = Color(0xFF24244A), onAccent = Color(0xFF0F0F1A),
    ok = Color(0xFF5CC49A), okSoft = Color(0xFF16302A), warn = Color(0xFFE0A84A), warnSoft = Color(0xFF33281A),
    danger = Color(0xFFEC7A72), dangerSoft = Color(0xFF3A1F1D), scrim = Color(0x8C000000),
)

private val Inter = FontFamily(Font(R.font.inter_regular, FontWeight.Normal), Font(R.font.inter_semibold, FontWeight.SemiBold))
private val Mono = FontFamily(Font(R.font.jetbrains_mono_regular, FontWeight.Normal))

@Immutable
data class Type(
    val display: TextStyle = TextStyle(fontFamily = Inter, fontWeight = FontWeight.SemiBold, fontSize = 34.sp, lineHeight = 40.sp, fontFeatureSettings = "tnum"),
    val title: TextStyle = TextStyle(fontFamily = Inter, fontWeight = FontWeight.SemiBold, fontSize = 22.sp, lineHeight = 28.sp, letterSpacing = (-0.01).em),
    val head: TextStyle = TextStyle(fontFamily = Inter, fontWeight = FontWeight.SemiBold, fontSize = 17.sp, lineHeight = 24.sp),
    val body: TextStyle = TextStyle(fontFamily = Inter, fontWeight = FontWeight.Normal, fontSize = 15.sp, lineHeight = 22.sp),
    val label: TextStyle = TextStyle(fontFamily = Inter, fontWeight = FontWeight.SemiBold, fontSize = 13.sp, lineHeight = 18.sp),
    val caption: TextStyle = TextStyle(fontFamily = Inter, fontWeight = FontWeight.Normal, fontSize = 12.sp, lineHeight = 16.sp),
    val mono: TextStyle = TextStyle(fontFamily = Mono, fontWeight = FontWeight.Normal, fontSize = 12.sp, lineHeight = 16.sp, letterSpacing = 0.02.em),
    val number: TextStyle = TextStyle(fontFamily = Inter, fontWeight = FontWeight.SemiBold, fontSize = 30.sp, lineHeight = 32.sp, fontFeatureSettings = "tnum"),
)

object Shapes {
    val sm = RoundedCornerShape(10.dp)
    val md = RoundedCornerShape(16.dp)
    val lg = RoundedCornerShape(24.dp)
    val pill = RoundedCornerShape(percent = 50)
}

object Motion {
    val ease = CubicBezierEasing(0.2f, 0.8f, 0.2f, 1f)
    const val FAST = 120
    const val BASE = 200
    const val SLOW = 280
}

private val LocalPalette = staticCompositionLocalOf { Light }
private val LocalType = staticCompositionLocalOf { Type() }

object Dfte {
    val colors: Palette @Composable get() = LocalPalette.current
    val type: Type @Composable get() = LocalType.current
}

@Composable
fun DfteTheme(content: @Composable () -> Unit) {
    val dark = isSystemInDarkTheme()
    val p = if (dark) Dark else Light
    // Material is only used for a few primitives (sheet, text); its colors follow the palette.
    val scheme = (if (dark) darkColorScheme() else lightColorScheme()).copy(
        primary = p.accent, onPrimary = p.onAccent, background = p.bg, onBackground = p.text,
        surface = p.surface, onSurface = p.text, surfaceContainerLow = p.surface, scrim = p.scrim,
    )
    CompositionLocalProvider(LocalPalette provides p, LocalType provides Type()) {
        MaterialTheme(colorScheme = scheme, content = content)
    }
}
