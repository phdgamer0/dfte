package dev.dfte.app

import android.Manifest
import android.content.Intent
import android.content.pm.PackageManager
import android.net.Uri
import android.os.Build
import android.os.Bundle
import android.util.Log
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.activity.result.contract.ActivityResultContracts
import androidx.core.content.ContextCompat
import androidx.core.content.IntentCompat
import androidx.lifecycle.lifecycleScope
import dev.dfte.app.ui.AppRoot
import dev.dfte.app.ui.DfteTheme
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

class MainActivity : ComponentActivity() {
    private val app get() = application as DfteApp

    private val picker = registerForActivityResult(ActivityResultContracts.OpenMultipleDocuments()) { uris -> openPicked(uris) }

    // Asked in context, the first time a transfer starts (manual §26), never at launch.
    private val permissions = registerForActivityResult(ActivityResultContracts.RequestMultiplePermissions()) { granted ->
        if (granted[Manifest.permission.WRITE_EXTERNAL_STORAGE] == false) {
            app.engine.notify("Without storage access, received files stay in DFTE's own folder.")
        }
    }

    private val wifiDirectPermission = registerForActivityResult(ActivityResultContracts.RequestPermission()) { granted ->
        if (granted) app.engine.hostNearby() else app.engine.notify("Wi-Fi Direct stays off. Devices on the same Wi-Fi can still connect.")
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        enableEdgeToEdge()
        super.onCreate(savedInstanceState)
        setContent {
            DfteTheme {
                AppRoot(app, pickFiles = { picker.launch(arrayOf("*/*")) }, askPermissions = ::askPermissions, allowWifiDirect = { wifiDirectPermission.launch(app.engine.wifiDirect.permission) })
            }
        }
        if (savedInstanceState == null) handleShare(intent)
    }

    override fun onNewIntent(intent: Intent) {
        super.onNewIntent(intent)
        handleShare(intent)
    }

    override fun onStart() {
        super.onStart()
        app.engine.foreground()
        // Back from the permission or Location settings with a Send/Receive screen open.
        if (app.nav.wantsPeers) app.engine.hostNearby()
    }

    override fun onStop() {
        app.engine.background()
        super.onStop()
    }

    /** "Share → DFTE" from another app lands on the device picker. */
    private fun handleShare(intent: Intent?) {
        val uris = when (intent?.action) {
            Intent.ACTION_SEND -> listOfNotNull(IntentCompat.getParcelableExtra(intent, Intent.EXTRA_STREAM, Uri::class.java))
            Intent.ACTION_SEND_MULTIPLE -> IntentCompat.getParcelableArrayListExtra(intent, Intent.EXTRA_STREAM, Uri::class.java).orEmpty()
            else -> return
        }
        openPicked(uris)
    }

    private fun openPicked(uris: List<Uri>) {
        if (uris.isEmpty()) return
        lifecycleScope.launch {
            try {
                val picked = withContext(Dispatchers.IO) { Picked.open(this@MainActivity, uris) }
                app.nav.home()
                app.nav.push(Screen.SendTo(picked))
            } catch (e: Exception) {
                Log.e("dfte", "could not open picked files", e)
                app.engine.notify(e.message ?: "Could not open the selected files.")
            }
        }
    }

    private fun askPermissions() {
        val wanted = buildList {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) add(Manifest.permission.POST_NOTIFICATIONS)
            if (Build.VERSION.SDK_INT < Build.VERSION_CODES.Q) add(Manifest.permission.WRITE_EXTERNAL_STORAGE)
        }.filter { ContextCompat.checkSelfPermission(this, it) != PackageManager.PERMISSION_GRANTED }
        if (wanted.isNotEmpty()) permissions.launch(wanted.toTypedArray())
    }
}
