package dev.dfte.app.ui

import androidx.activity.compose.BackHandler
import androidx.compose.animation.AnimatedContent
import androidx.compose.animation.AnimatedVisibility
import androidx.compose.animation.core.tween
import androidx.compose.animation.fadeIn
import androidx.compose.animation.fadeOut
import androidx.compose.animation.slideInHorizontally
import androidx.compose.animation.slideInVertically
import androidx.compose.animation.slideOutVertically
import androidx.compose.animation.togetherWith
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.WindowInsets
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.safeDrawing
import androidx.compose.foundation.layout.windowInsetsPadding
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalDensity
import androidx.compose.ui.unit.dp
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import dev.dfte.app.DfteApp
import dev.dfte.app.Screen
import dev.dfte.app.Target
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch

/**
 * Root of the phone layout (ui-spec.html "Phone layout"). Screens push with a
 * 24 px slide + fade (200 ms); the verify step and incoming offers overlay
 * whatever is on screen, because they can arrive at any time.
 */
@Composable
fun AppRoot(app: DfteApp, pickFiles: () -> Unit, askPermissions: () -> Unit, allowWifiDirect: () -> Unit) {
    val engine = app.engine
    val nav = app.nav
    val state by engine.state.collectAsStateWithLifecycle()
    val scope = rememberCoroutineScope()
    var addressFor by remember { mutableStateOf<Screen.SendTo?>(null) }
    var sending by remember { mutableStateOf(false) }
    val slide = with(LocalDensity.current) { 24.dp.roundToPx() }

    BackHandler(enabled = nav.stack.size > 1) { nav.pop() }

    // Host a Wi-Fi Direct group only while a screen peers must reach us from is open,
    // or while a transfer still runs over it.
    val wantsGroup = nav.wantsPeers
    val anyActive = state.jobs.values.any { it.active }
    LaunchedEffect(wantsGroup, anyActive) {
        if (wantsGroup) engine.hostNearby() else if (!anyActive) engine.stopHosting()
    }

    fun send(screen: Screen.SendTo, target: Target) {
        if (sending) return
        sending = true
        askPermissions()
        scope.launch {
            try {
                val id = engine.send(target, screen.picked)
                if (nav.top == screen) nav.replaceTop(Screen.Transfer(id))
            } catch (e: Exception) {
                // The picked files were released by send(); start over from Home.
                engine.notify(e.message ?: "Could not start the transfer.")
                if (nav.top == screen) nav.replaceTop(Screen.Home)
            } finally {
                sending = false
            }
        }
    }

    Box(Modifier.fillMaxSize().background(Dfte.colors.bg).windowInsetsPadding(WindowInsets.safeDrawing)) {
        AnimatedContent(
            targetState = nav.top,
            transitionSpec = {
                (fadeIn(tween(Motion.BASE, easing = Motion.ease)) + slideInHorizontally(tween(Motion.BASE, easing = Motion.ease)) { slide })
                    .togetherWith(fadeOut(tween(Motion.FAST)))
            },
            label = "screen",
        ) { screen ->
            when (screen) {
                Screen.Home -> HomeScreen(engine, state, onSend = pickFiles, onReceive = { nav.push(Screen.Receive) }, onOpen = { nav.push(Screen.Transfer(it)) })
                Screen.Receive -> ReceiveScreen(engine, state, onBack = { nav.pop() }, onAllowDirect = allowWifiDirect)
                is Screen.SendTo -> SendToScreen(
                    engine, state, screen.picked, sending,
                    onBack = { nav.pop() },
                    onPeer = { send(screen, Target.ToPeer(it)) },
                    onAddress = { addressFor = screen },
                    onAllowDirect = allowWifiDirect,
                )
                is Screen.Transfer -> TransferScreen(engine, state.jobs[screen.id], onBack = { nav.pop() }, onDone = { nav.doneReceiving() })
            }
        }

        addressFor?.let { screen ->
            AddressSheet(onSend = { addr -> addressFor = null; send(screen, Target.ToAddress(addr)) }, onDismiss = { addressFor = null })
        }

        state.offers.firstOrNull()?.let { offer ->
            IncomingSheet(
                offer,
                verified = true, // offers only arrive after the handshake and the code check (manual §9.1)
                onAccept = {
                    askPermissions()
                    engine.accept(offer)
                    nav.push(Screen.Transfer(offer.transferId))
                },
                onDecline = { engine.decline(offer) },
            )
        }

        AnimatedVisibility(state.verifies.isNotEmpty(), enter = fadeIn(tween(Motion.BASE)), exit = fadeOut(tween(Motion.FAST))) {
            state.verifies.firstOrNull()?.let { req ->
                VerifyScreen(req) { accept, remember -> engine.confirm(req, accept, remember) }
            }
        }

        val notice = state.notice
        AnimatedVisibility(
            notice != null,
            modifier = Modifier.align(Alignment.BottomCenter).padding(16.dp),
            enter = fadeIn(tween(Motion.BASE)) + slideInVertically(tween(Motion.BASE)) { it / 2 },
            exit = fadeOut(tween(Motion.FAST)) + slideOutVertically(tween(Motion.FAST)) { it / 2 },
        ) {
            var last by remember { mutableStateOf("") }
            if (notice != null) last = notice
            Notice(last)
        }
        LaunchedEffect(notice) {
            if (notice != null) {
                delay(4000)
                engine.clearNotice()
            }
        }
    }
}
