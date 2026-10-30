// Copyright (c) 2026 Yazdan Samari. All rights reserved except as granted by LICENSE.
// SPDX-License-Identifier: PolyForm-Shield-1.0.0

package dev.dfte.app.ui

import androidx.compose.animation.core.animateFloatAsState
import androidx.compose.animation.core.tween
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableLongStateOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberUpdatedState
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.graphicsLayer
import androidx.compose.ui.text.SpanStyle
import androidx.compose.ui.text.buildAnnotatedString
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.text.withStyle
import androidx.compose.ui.unit.dp
import dev.dfte.app.Direct
import dev.dfte.app.Copy
import dev.dfte.app.Engine
import dev.dfte.app.EngineState
import dev.dfte.app.Job
import dev.dfte.app.Picked
import java.net.Inet4Address
import java.net.NetworkInterface
import kotlinx.coroutines.delay
import uniffi.platform_ffi.Direction
import uniffi.platform_ffi.Peer
import uniffi.platform_ffi.TransferState
import uniffi.platform_ffi.TransportKind
import uniffi.platform_ffi.VerifyRequest

private val Gutter = Modifier.fillMaxSize().padding(start = 20.dp, end = 20.dp, top = 8.dp, bottom = 20.dp)

// ---- 1 · Home ---------------------------------------------------------------

@Composable
fun HomeScreen(engine: Engine, state: EngineState, onSend: () -> Unit, onReceive: () -> Unit, onOpen: (String) -> Unit) {
    val c = Dfte.colors
    Column(Gutter, verticalArrangement = Arrangement.spacedBy(12.dp)) {
        TopBar("Transfer", large = true)
        Row(horizontalArrangement = Arrangement.spacedBy(12.dp)) {
            ActionCard("Send", "Choose files", Icons.Up, main = true, onClick = onSend, modifier = Modifier.weight(1f))
            ActionCard("Receive", "Be visible nearby", Icons.Down, main = false, onClick = onReceive, modifier = Modifier.weight(1f))
        }
        val recent = state.jobs.values.filter { it.direction != null }.reversed().take(4)
        Spacer(Modifier.height(6.dp))
        if (recent.isNotEmpty()) {
            Label("Recent")
            Rows(recent) { job ->
                ListRow(
                    job.label.ifEmpty { "Transfer" },
                    caption = listOfNotNull((if (job.direction == Direction.RECEIVE) "From " else "To ") + (job.peerName ?: "nearby device"), Copy.bytes(job.bytesTotal).takeIf { job.bytesTotal > 0 }).joinToString(" · "),
                    leading = { Ic(if (job.direction == Direction.RECEIVE) Icons.Down else Icons.Up) },
                    trailing = { StatusChip(job) },
                    onClick = { onOpen(job.id) },
                )
            }
        } else {
            Card { Body("Nothing sent yet. Tap Send to share files with a nearby device.", Modifier.padding(16.dp)) }
        }
        Spacer(Modifier.weight(1f))
        Card {
            ListRow(
                engine.deviceName,
                caption = null,
                leading = { AvatarText(initials(engine.deviceName)) },
                trailing = { Text(Copy.fingerprint(engine.fingerprint, short = true), style = Dfte.type.mono, color = c.text3) },
            )
        }
    }
}

@Composable
private fun ActionCard(title: String, caption: String, icon: androidx.compose.ui.graphics.vector.ImageVector, main: Boolean, onClick: () -> Unit, modifier: Modifier) {
    val c = Dfte.colors
    Column(
        modifier.clip(Shapes.md).background(if (main) c.accent else c.surface).press(onClick = onClick).padding(horizontal = 16.dp, vertical = 18.dp),
        verticalArrangement = Arrangement.spacedBy(22.dp),
    ) {
        Ic(icon, if (main) c.onAccent else c.accent)
        Column {
            Text(title, style = Dfte.type.head, color = if (main) c.onAccent else c.text)
            Caption(caption, color = if (main) c.onAccent.copy(alpha = 0.75f) else c.text3)
        }
    }
}

@Composable
fun StatusChip(job: Job) = when (job.state) {
    is TransferState.Completed -> Chip("Done", Tone.Ok)
    is TransferState.Paused, is TransferState.Interrupted -> Chip("Paused", Tone.Warn)
    is TransferState.Failed -> Chip("Failed", Tone.Danger)
    is TransferState.Cancelled -> Chip("Cancelled")
    is TransferState.Transferring -> Chip("${(job.fraction * 100).toInt()}%", Tone.Accent)
    is TransferState.Negotiating -> Chip("Connecting", Tone.Accent)
    is TransferState.Pending -> Chip("Waiting")
}

private fun initials(name: String): String = name.split(' ', '-', '_').filter { it.isNotBlank() }.take(2).joinToString("") { it.take(1).uppercase() }.ifEmpty { "?" }

// ---- 2 · Send to ------------------------------------------------------------

@Composable
fun SendToScreen(engine: Engine, state: EngineState, picked: Picked, busy: Boolean, onBack: () -> Unit, onPeer: (Peer) -> Unit, onAddress: () -> Unit, onAllowDirect: () -> Unit) {
    Column(Gutter, verticalArrangement = Arrangement.spacedBy(12.dp)) {
        TopBar("Send to", onBack = onBack)
        Card {
            ListRow(picked.label, caption = "${Copy.items(picked.names.size)} · ${Copy.bytes(picked.totalBytes)}", leading = { Ic(Icons.File) })
        }
        Spacer(Modifier.height(4.dp))
        Label("Nearby", if (state.visible) "Looking for devices…" else null)
        val peers = state.peers.values.sortedBy { it.displayName.lowercase() }
        if (peers.isEmpty()) {
            Card { Body("Open DFTE on the other device and choose Receive. Laptops can join this phone over Wi-Fi Direct; phones need the same Wi-Fi or this phone's hotspot.", Modifier.padding(16.dp)) }
        } else {
            Rows(peers) { p ->
                val trusted = engine.isTrusted(p.fingerprint)
                ListRow(
                    p.displayName,
                    caption = if (trusted) "Trusted · Nearby" else "New device · Nearby",
                    leading = { Avatar(Icons.Laptop) },
                    trailing = { if (trusted) Ic(Icons.Shield, Dfte.colors.ok) },
                    onClick = { if (!busy) onPeer(p) },
                )
            }
        }
        DirectCard(engine, state, onAllowDirect)
        Spacer(Modifier.weight(1f))
        PillButton("Enter address", onAddress, Modifier.fillMaxWidth(), Kind.Secondary, Icons.Link)
        Caption("For devices that don't show up, type the address shown on their Receive screen.", Modifier.fillMaxWidth(), center = true)
    }
}

// ---- Receive ----------------------------------------------------------------

@Composable
fun ReceiveScreen(engine: Engine, state: EngineState, onBack: () -> Unit, onAllowDirect: () -> Unit) {
    val addrs = remember(state.visible, state.direct) { localAddresses() }
    Column(Gutter.verticalScroll(rememberScrollState()), verticalArrangement = Arrangement.spacedBy(12.dp)) {
        TopBar("Receive", onBack = onBack)
        Card {
            Column(Modifier.fillMaxWidth().padding(18.dp), horizontalAlignment = Alignment.CenterHorizontally, verticalArrangement = Arrangement.spacedBy(10.dp)) {
                if (state.visible) Chip("Visible as ${engine.deviceName}", Tone.Ok) else Chip("Not visible")
                Body("Open DFTE on the other device and choose Send.", center = true)
            }
        }
        DirectCard(engine, state, onAllowDirect)
        Spacer(Modifier.height(4.dp))
        Label("This phone")
        Rows(listOf("addr", "fp")) { k ->
            if (k == "addr") {
                ListRow("Address", caption = addrs.joinToString("  ") { "$it:${Engine.PORT}" }.ifEmpty { "Not connected to Wi-Fi" }, leading = { Ic(Icons.Link) })
            } else {
                ListRow("Fingerprint", caption = Copy.fingerprint(engine.fingerprint), leading = { Ic(Icons.Shield) })
            }
        }
        Caption("Received files are saved to Downloads/DFTE. Keep this screen open until a transfer starts.")
    }
}

/** Wi-Fi Direct status, or the in-context permission ask (manual §26) with an honest reason. */
@Composable
private fun DirectCard(engine: Engine, state: EngineState, onAllow: () -> Unit) {
    if (!engine.wifiDirect.supported) return
    val context = androidx.compose.ui.platform.LocalContext.current
    Card {
        when {
            state.direct is Direct.Linked -> ListRow("Wi-Fi Direct connected", caption = "Linked to a nearby device · no router needed", leading = { Ic(Icons.Wifi, Dfte.colors.ok) })
            state.direct == Direct.Discoverable -> ListRow("Wi-Fi Direct is on", caption = "Laptops nearby can find this phone. Accept Android's invitation when it appears.", leading = { Ic(Icons.Wifi, Dfte.colors.ok) })
            !engine.wifiDirect.permitted -> ListRow(
                "Connect without a router",
                caption = "Android files Wi-Fi Direct under Location. DFTE never reads where you are.",
                leading = { Ic(Icons.Wifi) },
                trailing = { PillButton("Allow", onAllow, small = true, kind = Kind.Secondary) },
            )
            !engine.wifiDirect.locationReady -> ListRow(
                "Turn on Location for Wi-Fi Direct",
                caption = "This Android version needs it to find nearby devices. DFTE never reads where you are.",
                leading = { Ic(Icons.Wifi) },
                trailing = { PillButton("Settings", { context.startActivity(android.content.Intent(android.provider.Settings.ACTION_LOCATION_SOURCE_SETTINGS)) }, small = true, kind = Kind.Secondary) },
            )
            else -> ListRow("Starting Wi-Fi Direct…", leading = { Ic(Icons.Wifi) }, muted = true)
        }
    }
}

/** IPv4 addresses on Wi-Fi-like interfaces (station, hotspot, Wi-Fi Direct). */
private fun localAddresses(): List<String> = try {
    NetworkInterface.getNetworkInterfaces().toList()
        .filter { it.isUp && !it.isLoopback && (it.name.startsWith("wlan") || it.name.startsWith("swlan") || it.name.startsWith("ap") || it.name.startsWith("p2p")) }
        .flatMap { i -> i.inetAddresses.toList().filterIsInstance<Inet4Address>().map { it.hostAddress.orEmpty() } }
        .filter { it.isNotEmpty() }
} catch (e: java.net.SocketException) {
    android.util.Log.w("dfte", "could not list network interfaces", e)
    emptyList()
}

// ---- 4 · Transfer / 6 · Done --------------------------------------------------

@Composable
fun TransferScreen(engine: Engine, job: Job?, onBack: () -> Unit, onDone: () -> Unit) {
    if (job == null) {
        Column(Gutter) {
            TopBar(onBack = onBack)
            Body("This transfer is no longer available.", Modifier.padding(top = 24.dp))
        }
        return
    }
    if (job.terminal) return DoneView(engine, job, onDone)
    val c = Dfte.colors
    val sending = job.direction != Direction.RECEIVE
    val peer = job.peerName ?: "nearby device"

    // Speed text refreshes at most twice a second so it stays readable (ui-spec motion rules).
    val latest by rememberUpdatedState(job)
    var shownRate by remember { mutableLongStateOf(job.bytesPerSec) }
    LaunchedEffect(job.id) {
        while (true) {
            shownRate = latest.bytesPerSec
            delay(500)
        }
    }

    Column(Gutter, verticalArrangement = Arrangement.spacedBy(12.dp)) {
        TopBar(if (sending) "Sending" else "Receiving", onBack = onBack)
        Box(Modifier.fillMaxWidth().padding(top = 8.dp), contentAlignment = Alignment.Center) {
            ProgressRing(job.fraction, 140.dp) {
                Column(horizontalAlignment = Alignment.CenterHorizontally) {
                    Text("${(job.fraction * 100).toInt()}%", style = Dfte.type.number, color = c.text)
                    Caption(if (sending) "to $peer" else "from $peer")
                }
            }
        }
        val left = job.bytesTotal - job.bytesDone
        Card {
            Row(Modifier.fillMaxWidth().padding(vertical = 14.dp, horizontal = 6.dp)) {
                Stat(if (shownRate > 0) Copy.rate(shownRate) else "—", "MB/s", Modifier.weight(1f))
                Stat(Copy.bytes(job.bytesDone), "of ${Copy.bytes(job.bytesTotal)}", Modifier.weight(1f))
                Stat(if (shownRate > 0) Copy.duration(left / shownRate) else "—", "left", Modifier.weight(1f))
            }
        }
        Card { ListRow(job.label.ifEmpty { "Files" }, caption = "${Copy.items(job.items)} · ${Copy.bytes(job.bytesTotal)}", leading = { Ic(Icons.File) }) }
        phaseText(job, peer)?.let { Body(it, Modifier.fillMaxWidth().padding(top = 4.dp), center = true) }
        Spacer(Modifier.weight(1f))
        val resumable = job.state is TransferState.Paused || job.state is TransferState.Interrupted
        Row(horizontalArrangement = Arrangement.spacedBy(12.dp)) {
            if (sending) {
                if (resumable) PillButton("Resume", { engine.resume(job.id) }, Modifier.weight(1f), Kind.Secondary, Icons.Play)
                else PillButton("Pause", { engine.pause(job.id) }, Modifier.weight(1f), Kind.Secondary, Icons.Pause, enabled = job.state is TransferState.Transferring)
            }
            PillButton("Cancel", { engine.cancel(job.id) }, Modifier.weight(1f), Kind.Danger)
        }
        val transport = when (job.transport) {
            TransportKind.TCP -> " · TCP"
            TransportKind.QUIC -> " · QUIC"
            null -> ""
        }
        Caption("Encrypted$transport · Keeps going in the background", Modifier.fillMaxWidth(), center = true)
    }
}

private fun phaseText(job: Job, peer: String): String? = when (job.state) {
    is TransferState.Pending -> if (job.direction == Direction.SEND) "Waiting for $peer to accept…" else null
    is TransferState.Negotiating -> "Connecting…"
    is TransferState.Paused -> "Paused. Resume to continue where it stopped."
    is TransferState.Interrupted -> "Connection lost. Resume when $peer is back in range."
    else -> null
}

@Composable
private fun Stat(value: String, unit: String, modifier: Modifier) {
    Column(modifier, horizontalAlignment = Alignment.CenterHorizontally) {
        Text(value, style = Dfte.type.head.copy(fontFeatureSettings = "tnum"), color = Dfte.colors.text, maxLines = 1)
        Caption(unit)
    }
}

@Composable
private fun DoneView(engine: Engine, job: Job, onDone: () -> Unit) {
    val c = Dfte.colors
    val peer = job.peerName ?: "nearby device"
    val ok = job.state is TransferState.Completed
    val failed = job.state as? TransferState.Failed
    val sending = job.direction != Direction.RECEIVE
    Column(Gutter, horizontalAlignment = Alignment.CenterHorizontally, verticalArrangement = Arrangement.spacedBy(12.dp)) {
        TopBar(onBack = onDone, backIcon = Icons.Close)
        Spacer(Modifier.height(44.dp))
        Box(Modifier.size(72.dp).clip(CircleShape).background(if (ok) c.okSoft else if (failed != null) c.dangerSoft else c.surface2), contentAlignment = Alignment.Center) {
            Ic(if (ok) Icons.Check else if (failed != null) Icons.Alert else Icons.Close, if (ok) c.ok else if (failed != null) c.danger else c.text2, 32.dp)
        }
        Spacer(Modifier.height(6.dp))
        Text(
            when {
                ok && sending -> "Sent to $peer"
                ok -> "Received from $peer"
                failed != null -> "Transfer failed"
                else -> "Transfer cancelled"
            },
            style = Dfte.type.title, color = c.text, textAlign = TextAlign.Center,
        )
        Body(
            when {
                failed != null -> Copy.error(failed.code, job.peerName)
                else -> "${Copy.items(job.items)} · ${Copy.bytes(job.bytesTotal)}"
            },
            center = true,
        )
        when {
            ok && !sending -> Caption(job.savedTo?.let { "Saved to $it" } ?: "Moving files to Downloads…", center = true)
            ok -> Caption("Every file was checked end to end.", center = true)
        }
        Spacer(Modifier.weight(1f))
        PillButton("Done", onDone, Modifier.fillMaxWidth())
        if (failed != null && sending) PillButton("Try again", { engine.resume(job.id) }, Modifier.fillMaxWidth().height(40.dp), Kind.Ghost)
    }
}

// ---- 3 · Verify -------------------------------------------------------------

@Composable
fun VerifyScreen(req: VerifyRequest, onAnswer: (accept: Boolean, remember: Boolean) -> Unit) {
    val c = Dfte.colors
    var remember by remember(req.requestId) { mutableStateOf(true) }
    Column(Modifier.fillMaxSize().background(c.bg).then(Gutter), horizontalAlignment = Alignment.CenterHorizontally, verticalArrangement = Arrangement.spacedBy(12.dp)) {
        TopBar(onBack = { onAnswer(false, false) }, backIcon = Icons.Close)
        Avatar(Icons.Laptop, 56.dp)
        Text("Compare this code", style = Dfte.type.title, color = c.text)
        Text(
            buildAnnotatedString {
                append("Check that ")
                withStyle(SpanStyle(color = c.text, fontWeight = FontWeight.SemiBold)) { append(req.peer.deviceName) }
                append(" shows the same six digits.")
            },
            style = Dfte.type.body, color = c.text2, textAlign = TextAlign.Center,
        )
        Spacer(Modifier.height(4.dp))
        SasCode(req.peer.sas)
        Text(Copy.fingerprint(req.peer.fingerprint), style = Dfte.type.mono, color = c.text3)
        Spacer(Modifier.weight(1f))
        Card {
            ListRow(
                "Trust this device",
                caption = "Skip this check next time",
                trailing = { Toggle(remember) },
                onClick = { remember = !remember },
            )
        }
        PillButton("Codes match", { onAnswer(true, remember) }, Modifier.fillMaxWidth())
        PillButton("They don't match", { onAnswer(false, false) }, Modifier.fillMaxWidth().height(40.dp), Kind.Ghost)
    }
}

@Composable
private fun Toggle(on: Boolean) {
    val c = Dfte.colors
    val x by animateFloatAsState(if (on) 1f else 0f, tween(Motion.BASE, easing = Motion.ease), label = "toggle")
    Box(Modifier.width(44.dp).height(26.dp).clip(Shapes.pill).background(if (on) c.accent else c.line).padding(3.dp)) {
        Box(Modifier.size(20.dp).graphicsLayer { translationX = x * 18.dp.toPx() }.clip(CircleShape).background(c.surface))
    }
}
