package dev.dfte.app.ui

import androidx.compose.animation.core.animateFloatAsState
import androidx.compose.animation.core.tween
import androidx.compose.foundation.Canvas
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.interaction.MutableInteractionSource
import androidx.compose.foundation.interaction.collectIsPressedAsState
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.ColumnScope
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.RowScope
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.material3.Icon
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.remember
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.StrokeCap
import androidx.compose.ui.graphics.drawscope.Stroke
import androidx.compose.ui.graphics.graphicsLayer
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.text.TextStyle
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.Dp
import androidx.compose.ui.unit.dp

/** Press feedback from the spec: scale 0.97 over 120 ms, no ripple. Only transform animates. */
@Composable
fun Modifier.press(enabled: Boolean = true, onClick: () -> Unit): Modifier {
    val source = remember { MutableInteractionSource() }
    val pressed by source.collectIsPressedAsState()
    val scale by animateFloatAsState(if (pressed) 0.97f else 1f, tween(Motion.FAST, easing = Motion.ease), label = "press")
    return this
        .graphicsLayer { scaleX = scale; scaleY = scale }
        .clickable(interactionSource = source, indication = null, enabled = enabled, onClick = onClick)
}

enum class Kind { Primary, Secondary, Ghost, Danger }

@Composable
fun PillButton(text: String, onClick: () -> Unit, modifier: Modifier = Modifier, kind: Kind = Kind.Primary, icon: ImageVector? = null, small: Boolean = false, enabled: Boolean = true) {
    val c = Dfte.colors
    val (bg, fg) = when (kind) {
        Kind.Primary -> c.accent to c.onAccent
        Kind.Secondary -> c.surface2 to c.text
        Kind.Ghost -> Color.Transparent to c.text2
        Kind.Danger -> c.dangerSoft to c.danger
    }
    Row(
        modifier
            .height(if (small) 36.dp else 48.dp)
            .graphicsLayer { alpha = if (enabled) 1f else 0.5f }
            .clip(Shapes.pill)
            .background(bg)
            .press(enabled, onClick)
            .padding(horizontal = if (small) 16.dp else 22.dp),
        horizontalArrangement = Arrangement.spacedBy(8.dp, Alignment.CenterHorizontally),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        if (icon != null) Icon(icon, null, Modifier.size(20.dp), tint = fg)
        Text(text, style = Dfte.type.label.copy(fontSize = if (small) Dfte.type.label.fontSize else Dfte.type.body.fontSize), color = fg, maxLines = 1)
    }
}

/** A surface card; children separated by hairlines when built with [Rows]. */
@Composable
fun Card(modifier: Modifier = Modifier, color: Color = Dfte.colors.surface, content: @Composable ColumnScope.() -> Unit) {
    Column(modifier.fillMaxWidth().clip(Shapes.md).background(color), content = content)
}

@Composable
fun <T> Rows(items: List<T>, modifier: Modifier = Modifier, color: Color = Dfte.colors.surface, row: @Composable (T) -> Unit) {
    Card(modifier, color) {
        items.forEachIndexed { i, item ->
            if (i > 0) Box(Modifier.fillMaxWidth().height(1.dp).background(Dfte.colors.line))
            row(item)
        }
    }
}

@Composable
fun ListRow(title: String, modifier: Modifier = Modifier, caption: String? = null, leading: @Composable (() -> Unit)? = null, trailing: @Composable (RowScope.() -> Unit)? = null, muted: Boolean = false, onClick: (() -> Unit)? = null) {
    Row(
        modifier.fillMaxWidth().then(if (onClick != null) Modifier.press(onClick = onClick) else Modifier).padding(horizontal = 16.dp, vertical = 14.dp),
        verticalAlignment = Alignment.CenterVertically,
        horizontalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        leading?.invoke()
        Column(Modifier.weight(1f)) {
            Text(title, style = Dfte.type.body, color = if (muted) Dfte.colors.text3 else Dfte.colors.text, maxLines = 1, overflow = TextOverflow.Ellipsis)
            if (caption != null) Text(caption, style = Dfte.type.caption, color = Dfte.colors.text3, maxLines = 1, overflow = TextOverflow.Ellipsis)
        }
        trailing?.invoke(this)
    }
}

@Composable
fun Ic(icon: ImageVector, tint: Color = Dfte.colors.text2, size: Dp = 22.dp) = Icon(icon, null, Modifier.size(size), tint = tint)

enum class Tone { Neutral, Ok, Warn, Danger, Accent }

@Composable
fun Chip(text: String, tone: Tone = Tone.Neutral, dot: Boolean = true) {
    val c = Dfte.colors
    val (bg, fg, dotColor) = when (tone) {
        Tone.Neutral -> Triple(c.surface2, c.text2, c.text3)
        Tone.Ok -> Triple(c.okSoft, c.ok, c.ok)
        Tone.Warn -> Triple(c.surface2, c.text2, c.warn)
        Tone.Danger -> Triple(c.dangerSoft, c.danger, c.danger)
        Tone.Accent -> Triple(c.accentSoft, c.accent, c.accent)
    }
    Row(Modifier.height(26.dp).clip(Shapes.pill).background(bg).padding(horizontal = 10.dp), verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(6.dp)) {
        if (dot) Box(Modifier.size(6.dp).clip(CircleShape).background(dotColor))
        Text(text, style = Dfte.type.caption.copy(fontWeight = Dfte.type.label.fontWeight), color = fg, maxLines = 1)
    }
}

@Composable
fun Avatar(icon: ImageVector, size: Dp = 40.dp) {
    Box(Modifier.size(size).clip(CircleShape).background(Dfte.colors.accentSoft), contentAlignment = Alignment.Center) {
        Ic(icon, Dfte.colors.accent, size * 0.5f)
    }
}

@Composable
fun AvatarText(text: String) {
    Box(Modifier.size(40.dp).clip(CircleShape).background(Dfte.colors.accentSoft), contentAlignment = Alignment.Center) {
        Text(text, style = Dfte.type.label, color = Dfte.colors.accent)
    }
}

/** The 6-digit verification code, grouped 3+3 (manual §12.1). */
@Composable
fun SasCode(sas: String) {
    Row(horizontalArrangement = Arrangement.spacedBy(10.dp), modifier = Modifier.fillMaxWidth(), verticalAlignment = Alignment.CenterVertically) {
        Spacer(Modifier.weight(1f))
        sas.forEachIndexed { i, ch ->
            if (i == 3) Spacer(Modifier.width(10.dp))
            Box(Modifier.width(44.dp).height(58.dp).clip(Shapes.sm).background(Dfte.colors.surface2), contentAlignment = Alignment.Center) {
                Text(ch.toString(), style = Dfte.type.display, color = Dfte.colors.text)
            }
        }
        Spacer(Modifier.weight(1f))
    }
}

/** Progress eases between engine updates (≤10 Hz) with one 200 ms tween; nothing animates when idle. */
@Composable
fun ProgressRing(fraction: Float, size: Dp, stroke: Dp = 8.dp, content: @Composable () -> Unit) {
    val c = Dfte.colors
    val f by animateFloatAsState(fraction, tween(Motion.BASE, easing = Motion.ease), label = "ring")
    Box(Modifier.size(size), contentAlignment = Alignment.Center) {
        Canvas(Modifier.size(size)) {
            val w = stroke.toPx()
            val inset = w / 2
            val arcSize = androidx.compose.ui.geometry.Size(this.size.width - w, this.size.height - w)
            val topLeft = androidx.compose.ui.geometry.Offset(inset, inset)
            drawArc(c.accentSoft, 0f, 360f, false, topLeft, arcSize, style = Stroke(w))
            if (f > 0f) drawArc(c.accent, -90f, 360f * f, false, topLeft, arcSize, style = Stroke(w, cap = StrokeCap.Round))
        }
        content()
    }
}

@Composable
fun LinearBar(fraction: Float, modifier: Modifier = Modifier) {
    val f by animateFloatAsState(fraction, tween(Motion.BASE, easing = Motion.ease), label = "bar")
    Box(modifier.fillMaxWidth().height(6.dp).clip(Shapes.pill).background(Dfte.colors.accentSoft)) {
        Box(Modifier.fillMaxWidth(f).height(6.dp).clip(Shapes.pill).background(Dfte.colors.accent))
    }
}

@Composable
fun TopBar(title: String? = null, onBack: (() -> Unit)? = null, backIcon: ImageVector = Icons.Back, large: Boolean = false, trailing: @Composable (() -> Unit)? = null) {
    Box(Modifier.fillMaxWidth().height(44.dp)) {
        if (onBack != null) Box(Modifier.align(Alignment.CenterStart).size(40.dp).clip(CircleShape).press(onClick = onBack), contentAlignment = Alignment.CenterStart) { Ic(backIcon, Dfte.colors.text) }
        if (title != null) {
            if (large) Text(title, style = Dfte.type.title, color = Dfte.colors.text, modifier = Modifier.align(Alignment.CenterStart))
            else Text(title, style = Dfte.type.head, color = Dfte.colors.text, modifier = Modifier.align(Alignment.Center))
        }
        if (trailing != null) Box(Modifier.align(Alignment.CenterEnd)) { trailing() }
    }
}

@Composable
fun Label(text: String, hint: String? = null) {
    Row(verticalAlignment = Alignment.CenterVertically) {
        Text(text, style = Dfte.type.label, color = Dfte.colors.text2)
        if (hint != null) Text(" · $hint", style = Dfte.type.caption, color = Dfte.colors.text3)
    }
}

@Composable
fun Caption(text: String, modifier: Modifier = Modifier, center: Boolean = false, color: Color = Dfte.colors.text3) =
    Text(text, style = Dfte.type.caption, color = color, modifier = modifier, textAlign = if (center) TextAlign.Center else null)

@Composable
fun Body(text: String, modifier: Modifier = Modifier, color: Color = Dfte.colors.text2, center: Boolean = false, style: TextStyle = Dfte.type.body) =
    Text(text, style = style, color = color, modifier = modifier, textAlign = if (center) TextAlign.Center else null)
