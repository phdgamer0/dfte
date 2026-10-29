package dev.dfte.app.ui

import android.os.StatFs
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.navigationBarsPadding
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.text.BasicTextField
import androidx.compose.foundation.text.KeyboardActions
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.ModalBottomSheet
import androidx.compose.material3.SheetValue
import androidx.compose.material3.Text
import androidx.compose.material3.rememberModalBottomSheetState
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.focus.FocusRequester
import androidx.compose.ui.focus.focusRequester
import androidx.compose.ui.graphics.SolidColor
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.input.ImeAction
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.unit.dp
import dev.dfte.app.Copy
import dev.dfte.app.Engine
import dev.dfte.app.Received
import uniffi.platform_ffi.IncomingOffer

@Composable
private fun Grabber() {
    Box(Modifier.fillMaxWidth().padding(top = 10.dp, bottom = 4.dp), contentAlignment = Alignment.Center) {
        Box(Modifier.width(36.dp).height(4.dp).clip(Shapes.pill).background(Dfte.colors.line))
    }
}

// ---- 5 · Incoming offer -----------------------------------------------------

/** A decision, so it can't be swiped away: Accept or Decline (or the offer times out). */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun IncomingSheet(offer: IncomingOffer, verified: Boolean, onAccept: () -> Unit, onDecline: () -> Unit) {
    val c = Dfte.colors
    val ctx = LocalContext.current
    val state = rememberModalBottomSheetState(skipPartiallyExpanded = true, confirmValueChange = { it != SheetValue.Hidden })
    val free = remember(offer.transferId) { Received.stagingFor(ctx, offer.transferId).let { StatFs(it.path).availableBytes } }
    ModalBottomSheet(
        onDismissRequest = {},
        sheetState = state,
        shape = Shapes.lg.copy(bottomStart = androidx.compose.foundation.shape.CornerSize(0.dp), bottomEnd = androidx.compose.foundation.shape.CornerSize(0.dp)),
        containerColor = c.surface,
        scrimColor = c.scrim,
        dragHandle = { Grabber() },
    ) {
        Column(Modifier.padding(start = 20.dp, end = 20.dp, bottom = 22.dp).navigationBarsPadding(), verticalArrangement = Arrangement.spacedBy(16.dp)) {
            Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(12.dp)) {
                Avatar(Icons.Laptop)
                Column {
                    Text("${offer.peerName} wants to send", style = Dfte.type.head, color = c.text)
                    Caption(listOfNotNull("Verified".takeIf { verified }, Copy.items(offer.files.count { !it.isDir }), Copy.bytes(offer.bytesTotal.toLong())).joinToString(" · "))
                }
            }
            val shown = offer.files.filter { !it.isDir }.take(2)
            val more = offer.files.count { !it.isDir } - shown.size
            Rows(shown.map { it.path to it.size.toLong() } + listOfNotNull(if (more > 0) "+ $more more" to -1L else null), color = c.surface2) { (path, size) ->
                if (size < 0) ListRow(path, muted = true)
                else ListRow(path.substringAfterLast('/'), leading = { Ic(Icons.File) }, trailing = { Caption(Copy.bytes(size)) })
            }
            Caption("Saves to Downloads/DFTE · ${Copy.bytes(free)} free")
            Row(horizontalArrangement = Arrangement.spacedBy(12.dp)) {
                PillButton("Decline", onDecline, Modifier.weight(1f), Kind.Secondary)
                PillButton("Accept", onAccept, Modifier.weight(1.4f), enabled = free >= offer.bytesTotal.toLong())
            }
        }
    }
}

// ---- Enter address ----------------------------------------------------------

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun AddressSheet(onSend: (String) -> Unit, onDismiss: () -> Unit) {
    val c = Dfte.colors
    var text by remember { mutableStateOf("") }
    val focus = remember { FocusRequester() }
    val addr = normalizeAddress(text)
    ModalBottomSheet(
        onDismissRequest = onDismiss,
        sheetState = rememberModalBottomSheetState(skipPartiallyExpanded = true),
        containerColor = c.surface,
        scrimColor = c.scrim,
        dragHandle = { Grabber() },
    ) {
        Column(Modifier.padding(start = 20.dp, end = 20.dp, bottom = 22.dp).navigationBarsPadding(), verticalArrangement = Arrangement.spacedBy(14.dp)) {
            Text("Enter address", style = Dfte.type.head, color = c.text)
            Caption("Shown on the other device's Receive screen, like 192.168.1.20:${Engine.PORT}.")
            Box(Modifier.fillMaxWidth().height(48.dp).clip(Shapes.sm).background(c.surface2).padding(horizontal = 14.dp), contentAlignment = Alignment.CenterStart) {
                if (text.isEmpty()) Text("192.168.1.20:${Engine.PORT}", style = Dfte.type.body, color = c.text3)
                BasicTextField(
                    value = text,
                    onValueChange = { text = it.trim() },
                    singleLine = true,
                    textStyle = Dfte.type.body.copy(color = c.text),
                    cursorBrush = SolidColor(c.accent),
                    keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Uri, imeAction = ImeAction.Send),
                    keyboardActions = KeyboardActions(onSend = { addr?.let(onSend) }),
                    modifier = Modifier.fillMaxWidth().focusRequester(focus),
                )
            }
            PillButton("Send", { addr?.let(onSend) }, Modifier.fillMaxWidth(), enabled = addr != null)
        }
    }
    LaunchedEffect(Unit) { focus.requestFocus() }
}

/** `host` or `host:port`; the port defaults to the app's. Null while not plausible yet. */
private fun normalizeAddress(s: String): String? {
    if (s.isEmpty() || s.any { it.isWhitespace() }) return null
    val (host, port) = if (s.count { it == ':' } == 1) s.substringBefore(':') to s.substringAfter(':') else s to Engine.PORT.toString()
    val p = port.toIntOrNull() ?: return null
    if (host.isEmpty() || p !in 1..65535) return null
    return "$host:$p"
}

@Composable
fun Notice(text: String) {
    val c = Dfte.colors
    Row(
        Modifier.fillMaxWidth().clip(Shapes.md).background(c.text).padding(horizontal = 16.dp, vertical = 14.dp),
        verticalAlignment = Alignment.CenterVertically,
        horizontalArrangement = Arrangement.spacedBy(10.dp),
    ) {
        Ic(Icons.Alert, c.bg, 20.dp)
        Text(text, style = Dfte.type.body, color = c.bg, modifier = Modifier.weight(1f))
    }
}
