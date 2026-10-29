package dev.dfte.app

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.app.Service
import android.content.Context
import android.content.Intent
import android.content.pm.ServiceInfo
import android.net.wifi.WifiManager
import android.os.Build
import android.os.IBinder
import android.os.PowerManager
import android.util.Log
import androidx.core.app.NotificationCompat
import androidx.core.app.ServiceCompat
import androidx.core.content.ContextCompat
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import uniffi.platform_ffi.Direction

/**
 * Keeps the process and the radio awake while a transfer runs (manual §5/§25):
 * a dataSync foreground service with a quiet progress notification, a partial
 * wake lock, and a Wi-Fi lock so power save doesn't throttle the link. It
 * stops itself as soon as no transfer is active, releasing both locks.
 */
class TransferService : Service() {
    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.Main)
    private var wake: PowerManager.WakeLock? = null
    private var wifi: WifiManager.WifiLock? = null

    override fun onBind(intent: Intent?): IBinder? = null

    override fun onCreate() {
        super.onCreate()
        val nm = getSystemService(NotificationManager::class.java)
        nm.createNotificationChannel(NotificationChannel(CHANNEL, getString(R.string.channel_transfers), NotificationManager.IMPORTANCE_LOW))
        val type = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) ServiceInfo.FOREGROUND_SERVICE_TYPE_DATA_SYNC else 0
        ServiceCompat.startForeground(this, NOTIFICATION, build("Preparing transfer", null), type)

        wake = getSystemService(PowerManager::class.java).newWakeLock(PowerManager.PARTIAL_WAKE_LOCK, "dfte:transfer").apply { acquire(WAKE_TIMEOUT_MS) }
        wifi = wifiLock().apply { setReferenceCounted(false); acquire() }

        val engine = (application as DfteApp).engine
        scope.launch {
            // Sampled at 1 Hz: notifications are rate-limited anyway, and this keeps the shade cheap.
            while (true) {
                val active = engine.state.value.jobs.values.filter { it.active }
                if (active.isEmpty()) {
                    stopSelf()
                    return@launch
                }
                nm.notify(NOTIFICATION, summary(active))
                delay(1000)
            }
        }
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int = START_NOT_STICKY

    override fun onDestroy() {
        scope.cancel()
        wake?.let { if (it.isHeld) it.release() }
        wifi?.let { if (it.isHeld) it.release() }
        super.onDestroy()
    }

    @Suppress("DEPRECATION") // FULL_HIGH_PERF is the mode that also holds with the screen off; LOW_LATENCY doesn't.
    private fun wifiLock(): WifiManager.WifiLock = (applicationContext.getSystemService(Context.WIFI_SERVICE) as WifiManager)
        .createWifiLock(WifiManager.WIFI_MODE_FULL_HIGH_PERF, "dfte:transfer")

    private fun summary(active: List<Job>): Notification {
        if (active.size > 1) {
            val done = active.sumOf { it.bytesDone }
            val total = active.sumOf { it.bytesTotal }
            return build("${active.size} transfers", if (total > 0) (done * 100 / total).toInt() else null)
        }
        val j = active[0]
        val verb = if (j.direction == Direction.RECEIVE) "Receiving from" else "Sending to"
        return build("$verb ${j.peerName ?: "nearby device"}", (j.fraction * 100).toInt())
    }

    private fun build(title: String, percent: Int?): Notification {
        val open = PendingIntent.getActivity(this, 0, Intent(this, MainActivity::class.java).addFlags(Intent.FLAG_ACTIVITY_SINGLE_TOP), PendingIntent.FLAG_IMMUTABLE)
        return NotificationCompat.Builder(this, CHANNEL)
            .setSmallIcon(R.drawable.ic_notification)
            .setContentTitle(title)
            .setContentText(percent?.let { "$it%" })
            .setProgress(100, percent ?: 0, percent == null)
            .setOngoing(true)
            .setOnlyAlertOnce(true)
            .setSilent(true)
            .setContentIntent(open)
            .build()
    }

    companion object {
        private const val CHANNEL = "transfers"
        private const val NOTIFICATION = 1

        /** Upper bound so a bug can never hold the CPU awake forever (Android lint rule). */
        private const val WAKE_TIMEOUT_MS = 6 * 60 * 60 * 1000L

        fun start(ctx: Context) {
            try {
                ContextCompat.startForegroundService(ctx, Intent(ctx, TransferService::class.java))
            } catch (e: IllegalStateException) {
                // Android 12+ refuses foreground services started from the background.
                Log.e("dfte", "could not start the transfer service", e)
                (ctx.applicationContext as DfteApp).engine.notify("Keep DFTE open until the transfer finishes.")
            }
        }
    }
}
