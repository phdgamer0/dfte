package dev.dfte.app

import android.app.Application
import android.content.Context
import android.net.wifi.WifiManager
import android.os.Build
import android.provider.Settings
import android.util.Log
import java.io.File
import java.util.concurrent.ConcurrentHashMap
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import uniffi.platform_ffi.Direction
import uniffi.platform_ffi.EngineException
import uniffi.platform_ffi.ErrorInfo
import uniffi.platform_ffi.IncomingOffer
import uniffi.platform_ffi.ManagerConfig
import uniffi.platform_ffi.Peer
import uniffi.platform_ffi.Transfer
import uniffi.platform_ffi.TransferManager
import uniffi.platform_ffi.TransferObserver
import uniffi.platform_ffi.TransferState
import uniffi.platform_ffi.TransportKind
import uniffi.platform_ffi.VerifyRequest

/** One transfer as the UI sees it: the engine's snapshot plus what the app knows about it. */
data class Job(
    val id: String,
    val direction: Direction? = null,
    val state: TransferState = TransferState.Pending,
    val transport: TransportKind? = null,
    val bytesTotal: Long = 0,
    val bytesDone: Long = 0,
    val bytesPerSec: Long = 0,
    val peerName: String? = null,
    val label: String = "",
    val items: Int = 0,
    val error: ErrorInfo? = null,
    val savedTo: String? = null,
) {
    val active: Boolean get() = state is TransferState.Negotiating || state is TransferState.Transferring
    val terminal: Boolean get() = state is TransferState.Completed || state is TransferState.Cancelled || state is TransferState.Failed
    val fraction: Float get() = if (bytesTotal > 0) (bytesDone.toFloat() / bytesTotal).coerceIn(0f, 1f) else 0f
}

data class EngineState(
    /** Start order (oldest first). */
    val jobs: Map<String, Job> = emptyMap(),
    val peers: Map<String, Peer> = emptyMap(),
    val offers: List<IncomingOffer> = emptyList(),
    val verifies: List<VerifyRequest> = emptyList(),
    val visible: Boolean = false,
    /** Wi-Fi Direct, while a Send or Receive screen is open or a transfer runs over it. */
    val direct: Direct = Direct.Off,
    /** A message not tied to one transfer; the UI shows it once and clears it. */
    val notice: String? = null,
)

sealed interface Direct {
    data object Off : Direct
    /** Nearby laptops can find this phone and start a connection. */
    data object Discoverable : Direct
    data class Linked(val link: DirectLink) : Direct
}

sealed interface Target {
    data class ToPeer(val peer: Peer) : Target
    data class ToAddress(val addr: String) : Target
}

/**
 * Adapts the Rust TransferManager (manual §22) to Compose: observer callbacks
 * arrive on engine threads and are folded into one immutable [state]. No
 * transfer logic lives here, only bookkeeping the UI needs (manual §23).
 */
class Engine(private val app: Application) : TransferObserver {
    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.Default)
    private val identity = IdentityStore.load(app)
    val deviceName: String = Settings.Global.getString(app.contentResolver, Settings.Global.DEVICE_NAME)?.takeIf { it.isNotBlank() } ?: Build.MODEL
    private val manager = TransferManager(
        ManagerConfig(
            identitySecret = identity.secret,
            storageRoot = File(app.getExternalFilesDir(null), "engine").path,
            deviceName = deviceName,
            transport = null,
            verifyTimeoutMs = null,
            acceptTimeoutMs = null,
            progressIntervalMs = null,
        ),
        null,
    )
    val fingerprint: String = manager.fingerprint()

    private val _state = MutableStateFlow(EngineState(notice = if (identity.wasReset) "This phone has a new identity. Devices you trusted will ask you to compare codes again." else null))
    val state: StateFlow<EngineState> = _state

    private val picks = ConcurrentHashMap<String, Picked>()
    private val trust = app.getSharedPreferences("trust", Context.MODE_PRIVATE)
    private val lifecycle = Mutex()
    private var listening = false
    private var multicast: WifiManager.MulticastLock? = null
    val wifiDirect = WifiDirect(app)
    private var rearm: kotlinx.coroutines.Job? = null

    init {
        manager.setObserver(this)
        wifiDirect.watch(::onLink)
    }

    // ---- lifecycle -------------------------------------------------------

    /** App came to the foreground: listen (once) and become visible nearby. */
    fun foreground() = act {
        lifecycle.withLock {
            if (!listening) {
                try {
                    manager.listen("0.0.0.0:$PORT")
                } catch (e: EngineException) {
                    Log.w(TAG, "port $PORT busy, using any free port", e)
                    manager.listen("0.0.0.0:0")
                }
                listening = true
            }
            if (!_state.value.visible) {
                multicastLock().acquire()
                manager.startScan()
                _state.update { it.copy(visible = true) }
            }
        }
    }

    /** App left the foreground: stop advertising unless a transfer still needs the radio. */
    fun background() = act {
        lifecycle.withLock {
            if (_state.value.visible && _state.value.jobs.values.none { it.active }) {
                stopHostingLocked()
                manager.stopScan()
                multicast?.let { if (it.isHeld) it.release() }
                _state.update { it.copy(visible = false, peers = emptyMap()) }
            }
        }
    }

    /** A screen peers must reach us from is open: be discoverable over Wi-Fi Direct, if allowed (manual §26: asked in context). */
    fun hostNearby() = act {
        lifecycle.withLock {
            if (rearm?.isActive == true || !wifiDirect.supported || !wifiDirect.permitted || !wifiDirect.locationReady) return@withLock
            wifiDirect.discoverable()
            if (_state.value.direct == Direct.Off) _state.update { it.copy(direct = Direct.Discoverable) }
            // Android ends peer discovery after about two minutes.
            rearm = scope.launch {
                while (true) {
                    kotlinx.coroutines.delay(REARM_MS)
                    try {
                        wifiDirect.discoverable()
                    } catch (e: Exception) {
                        Log.w(TAG, "re-arming Wi-Fi Direct discovery failed", e)
                    }
                }
            }
        }
    }

    /** No screen needs Wi-Fi Direct any more; a link stays up while a transfer runs over it. */
    fun stopHosting() = act {
        lifecycle.withLock { if (_state.value.jobs.values.none { it.active }) stopHostingLocked() }
    }

    private suspend fun stopHostingLocked() {
        val running = rearm?.isActive == true
        rearm?.cancel()
        rearm = null
        if (!running && _state.value.direct == Direct.Off) return
        _state.update { it.copy(direct = Direct.Off) }
        wifiDirect.stop()
    }

    /** A group formed or ended. As a member, announce ourselves to the owner (it answers). */
    private fun onLink(link: DirectLink?) {
        val wanted = rearm?.isActive == true
        _state.update { it.copy(direct = if (link != null) Direct.Linked(link) else if (wanted) Direct.Discoverable else Direct.Off) }
        if (link == null) {
            // Android stops discovery when a group forms; be findable again right away.
            if (wanted) act { wifiDirect.discoverable() }
            return
        }
        val owner = link.ownerAddress ?: return
        act { manager.addBeaconTarget("$owner:${WifiDirect.BEACON_PORT}") }
    }

    private fun multicastLock(): WifiManager.MulticastLock = multicast ?: (app.getSystemService(Context.WIFI_SERVICE) as WifiManager)
        .createMulticastLock("dfte-discovery").apply { setReferenceCounted(false) }.also { multicast = it }

    // ---- actions ---------------------------------------------------------

    /** Starts a send; the engine owns [picked] from here and it is closed when the job ends. */
    suspend fun send(target: Target, picked: Picked): String {
        val id = try {
            when (target) {
                is Target.ToPeer -> manager.sendToPeer(target.peer, picked.paths)
                is Target.ToAddress -> manager.sendToAddress(target.addr, null, picked.paths)
            }
        } catch (e: Exception) {
            picked.close()
            throw e
        }
        picks[id] = picked
        upsert(id) { it.copy(direction = Direction.SEND, label = picked.label, items = picked.names.size, bytesTotal = it.bytesTotal.takeIf { b -> b > 0 } ?: picked.totalBytes) }
        if (_state.value.jobs[id]?.terminal == true) release(id)
        return id
    }

    fun accept(offer: IncomingOffer) = act {
        _state.update { s -> s.copy(offers = s.offers - offer) }
        manager.acceptIncoming(offer.transferId, Received.stagingFor(app, offer.transferId).path)
    }

    fun decline(offer: IncomingOffer) = act {
        _state.update { s -> s.copy(offers = s.offers - offer) }
        manager.rejectIncoming(offer.transferId)
    }

    fun confirm(req: VerifyRequest, accept: Boolean, remember: Boolean) = act {
        _state.update { s -> s.copy(verifies = s.verifies - req) }
        manager.confirmPeer(req.requestId, accept)
        if (accept && remember) trust.edit().putString(req.peer.fingerprint, req.peer.deviceName).apply()
    }

    fun pause(id: String) = act { manager.pause(id) }
    fun resume(id: String) = act { manager.resume(id) }
    fun cancel(id: String) = act { manager.cancel(id) }
    fun clearNotice() = _state.update { it.copy(notice = null) }
    fun isTrusted(fingerprint: String?): Boolean = fingerprint != null && trust.contains(fingerprint)
    fun notify(message: String) = _state.update { it.copy(notice = message) }

    /** Runs an engine call off the UI thread; failures become a visible notice, never silence. */
    private fun act(block: suspend () -> Unit) = scope.launch {
        try {
            block()
        } catch (e: Exception) {
            Log.e(TAG, "engine call failed", e)
            notify(e.message ?: e.javaClass.simpleName)
        }
    }

    // ---- observer (engine threads) --------------------------------------

    override fun onProgress(transfer: Transfer) = upsert(transfer.id) {
        it.copy(
            direction = transfer.direction,
            state = transfer.state,
            transport = transfer.transport,
            bytesTotal = transfer.bytesTotal.toLong(),
            bytesDone = transfer.bytesDone.toLong(),
            bytesPerSec = transfer.throughputBytesPerSec.toLong(),
            peerName = transfer.peerName ?: it.peerName,
        )
    }

    override fun onStateChanged(transferId: String, state: TransferState) {
        upsert(transferId) { it.copy(state = state, bytesPerSec = if (state is TransferState.Transferring) it.bytesPerSec else 0) }
        val job = _state.value.jobs[transferId] ?: return
        if (job.active) TransferService.start(app)
        if (job.terminal) {
            _state.update { s -> s.copy(offers = s.offers.filterNot { it.transferId == transferId }, verifies = s.verifies.filterNot { it.transferId == transferId }) }
            // A failed send can be retried under the same id (manual §19), so it keeps its files.
            if (state !is TransferState.Failed) release(transferId)
            if (state is TransferState.Completed && job.direction == Direction.RECEIVE) publish(transferId)
        }
    }

    override fun onPeerFound(peer: Peer) = _state.update { it.copy(peers = it.peers + (peer.handle to peer)) }
    override fun onPeerLost(handle: String) = _state.update { it.copy(peers = it.peers - handle) }

    override fun onError(transferId: String?, error: ErrorInfo) {
        Log.w(TAG, "engine error ${error.code}: ${error.message} (transfer $transferId)")
        if (transferId != null) upsert(transferId) { it.copy(error = error) } else notify(Copy.error(error.code, null))
    }

    override fun onIncoming(offer: IncomingOffer) {
        upsert(offer.transferId) {
            it.copy(direction = Direction.RECEIVE, peerName = offer.peerName, label = Copy.offerLabel(offer), items = offer.files.size, bytesTotal = offer.bytesTotal.toLong())
        }
        _state.update { it.copy(offers = it.offers + offer) }
    }

    override fun onVerifyPeer(request: VerifyRequest) {
        upsert(request.transferId) { it.copy(peerName = request.peer.deviceName) }
        // A pinned fingerprint skips the code comparison (manual §9.1); first pairings never do.
        if (isTrusted(request.peer.fingerprint)) {
            try {
                manager.confirmPeer(request.requestId, true)
            } catch (e: EngineException) {
                Log.e(TAG, "auto-confirm for a trusted peer failed", e)
                notify(e.message ?: "Could not confirm ${request.peer.deviceName}")
            }
        } else {
            _state.update { it.copy(verifies = it.verifies + request) }
        }
    }

    // ---- internals -------------------------------------------------------

    private fun upsert(id: String, f: (Job) -> Job) = _state.update { s -> s.copy(jobs = s.jobs + (id to f(s.jobs[id] ?: Job(id)))) }

    private fun release(id: String) {
        picks.remove(id)?.close()
    }

    private fun publish(id: String) = scope.launch(Dispatchers.IO) {
        try {
            val moved = Received.publish(app, Received.stagingFor(app, id))
            val where = if (moved.size == 1) "Downloads/DFTE/${moved[0].name}" else "Downloads/DFTE"
            upsert(id) { it.copy(savedTo = where) }
        } catch (e: Exception) {
            Log.e(TAG, "could not move received files into Downloads", e)
            upsert(id) { it.copy(savedTo = "app storage (moving to Downloads failed: ${e.message})") }
        }
    }

    companion object {
        /** Same default as the `dfte` CLI, so `dfte send --to PHONE_IP` just works. */
        const val PORT = 47821
        private const val REARM_MS = 100_000L
        private const val TAG = "dfte"
    }
}
