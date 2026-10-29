package dev.dfte.app

import android.Manifest
import android.annotation.SuppressLint
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.content.pm.PackageManager
import android.location.LocationManager
import android.net.wifi.p2p.WifiP2pInfo
import android.net.wifi.p2p.WifiP2pManager
import android.os.Build
import android.os.Looper
import android.util.Log
import androidx.core.content.ContextCompat
import androidx.core.location.LocationManagerCompat
import kotlin.coroutines.resume
import kotlinx.coroutines.suspendCancellableCoroutine
import kotlinx.coroutines.withTimeoutOrNull

/** A Wi-Fi Direct group this phone is in. [ownerAddress] is null when the phone owns it. */
data class DirectLink(val ownerAddress: String?)

/**
 * Wi-Fi Direct for laptops (manual §5/§7): the phone stays discoverable while a Send or
 * Receive screen is open, the laptop starts the connection, and Android asks the user to
 * accept it. Negotiation picks the group owner; whoever owns it serves DHCP. Once a group
 * forms, the engine beacons to the owner and both ends learn each other.
 *
 * Why not host a group here: NetworkManager (the usual Linux Wi-Fi stack) can only
 * negotiate a new group, never join an existing one, and Android refuses negotiation
 * while it already owns a group. Radio work only; no protocol logic here (manual §1.4).
 */
class WifiDirect(private val context: Context) {
    private val manager = context.getSystemService(Context.WIFI_P2P_SERVICE) as WifiP2pManager?
    /**
     * The framework connection. Android can drop it (its Wi-Fi service restarted, or it
     * never finished connecting); every request on a dead channel is silently ignored, so
     * a lost one is replaced at once.
     */
    @Volatile private var channelRef: WifiP2pManager.Channel? = null
    private val channel: WifiP2pManager.Channel? get() = channelRef ?: synchronized(this) { channelRef ?: open() }

    private fun open(): WifiP2pManager.Channel? = manager?.initialize(context, Looper.getMainLooper()) {
        Log.w(TAG, "Wi-Fi Direct channel lost; reconnecting")
        synchronized(this) { channelRef = null }
    }?.also { channelRef = it }

    init {
        // Connect now, so it's ready by the first request.
        channel
    }
    private var receiver: BroadcastReceiver? = null

    /** The permission P2P calls need: location up to Android 12 (an OS quirk, manual §26), then nearby Wi-Fi devices. */
    val permission: String =
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) Manifest.permission.NEARBY_WIFI_DEVICES else Manifest.permission.ACCESS_FINE_LOCATION

    val supported: Boolean get() = manager != null && context.packageManager.hasSystemFeature(PackageManager.FEATURE_WIFI_DIRECT)
    val permitted: Boolean get() = ContextCompat.checkSelfPermission(context, permission) == PackageManager.PERMISSION_GRANTED

    /** Up to Android 12, peer discovery also needs the Location switch on. */
    val locationReady: Boolean
        get() = Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU ||
            LocationManagerCompat.isLocationEnabled(context.getSystemService(Context.LOCATION_SERVICE) as LocationManager)

    /**
     * Makes the phone discoverable: the radio answers probes while peer discovery runs.
     * Android ends discovery after about two minutes, so callers re-arm it.
     */
    @SuppressLint("MissingPermission") // checked by `permitted`, which callers ensure first
    suspend fun discoverable() {
        check(supported) { "This phone has no Wi-Fi Direct." }
        check(permitted) { "Wi-Fi Direct needs the $permission permission." }
        val m = manager!!
        val ch = channel!!
        // After a group ends, Android can still believe discovery runs while the radio has
        // stopped searching, and then discoverPeers does nothing. Stopping first resets that.
        val stopped = call { m.stopPeerDiscovery(ch, it) }
        if (stopped != null) Log.d(TAG, "stopPeerDiscovery before re-arming: ${reason(stopped)}")
        val err = call { m.discoverPeers(ch, it) }
        // BUSY: a discovery or connection is already in progress, which keeps us visible too.
        if (err != null && err != WifiP2pManager.BUSY) error("Could not start Wi-Fi Direct (${reason(err)}).")
    }

    /** Stops searching but keeps any group: a search makes the radio hop to the social channels. */
    suspend fun stopDiscovery() {
        val m = manager ?: return
        val ch = channel ?: return
        val err = call { m.stopPeerDiscovery(ch, it) }
        if (err != null) Log.i(TAG, "stopPeerDiscovery: ${reason(err)}")
    }

    /** Stops discovery and leaves any group. No-ops when nothing runs. */
    suspend fun stop() {
        val m = manager ?: return
        val ch = channel ?: return
        val a = call { m.stopPeerDiscovery(ch, it) }
        val b = call { m.removeGroup(ch, it) }
        // Failures here mostly mean "nothing to stop"; worth a log line, not a user notice.
        if (a != null || b != null) Log.i(TAG, "stop: discovery ${a?.let(::reason) ?: "ok"}, group ${b?.let(::reason) ?: "ok"}")
    }

    /** Reports group changes: a [DirectLink] when one forms, null when it ends. */
    fun watch(onChange: (DirectLink?) -> Unit) {
        if (receiver != null || manager == null) return
        val r = object : BroadcastReceiver() {
            override fun onReceive(c: Context, intent: Intent) {
                manager.requestConnectionInfo(channel) { info: WifiP2pInfo? ->
                    onChange(
                        if (info?.groupFormed == true) DirectLink(if (info.isGroupOwner) null else info.groupOwnerAddress?.hostAddress) else null,
                    )
                }
            }
        }
        // A system broadcast: the receiver must be "exported" for it to arrive.
        ContextCompat.registerReceiver(context, r, IntentFilter(WifiP2pManager.WIFI_P2P_CONNECTION_CHANGED_ACTION), ContextCompat.RECEIVER_EXPORTED)
        receiver = r
    }

    /**
     * Runs one WifiP2pManager request and waits for its answer: null on success, else the
     * failure code. Android doesn't always answer (seen on the A30 after a group created by
     * an earlier process), and callers hold the engine's lifecycle lock, so give up after
     * [CALL_TIMEOUT_MS] instead of hanging.
     */
    private suspend fun call(op: (WifiP2pManager.ActionListener) -> Unit): Int? {
        // Wrapped so a success (null) is distinguishable from a timeout.
        val answer = withTimeoutOrNull(CALL_TIMEOUT_MS) {
            suspendCancellableCoroutine { cont ->
                op(object : WifiP2pManager.ActionListener {
                    override fun onSuccess() = cont.resume(Answer(null))
                    override fun onFailure(reason: Int) = cont.resume(Answer(reason))
                })
            }
        }
        if (answer == null) {
            Log.w(TAG, "Wi-Fi Direct request got no answer in $CALL_TIMEOUT_MS ms")
            return NO_ANSWER
        }
        return answer.code
    }

    private class Answer(val code: Int?)

    private fun reason(code: Int) = when (code) {
        WifiP2pManager.P2P_UNSUPPORTED -> "not supported"
        WifiP2pManager.BUSY -> "radio busy"
        WifiP2pManager.ERROR -> "internal error; is Wi-Fi on?"
        NO_ANSWER -> "no answer"
        else -> "code $code"
    }

    companion object {
        /** The engine's LAN beacon port (`discovery::lan::DEFAULT_BEACON_PORT`). */
        const val BEACON_PORT = 47820
        private const val CALL_TIMEOUT_MS = 5_000L
        /** Not a WifiP2pManager code: the request was never answered. */
        private const val NO_ANSWER = -1
        private const val TAG = "dfte"
    }
}
