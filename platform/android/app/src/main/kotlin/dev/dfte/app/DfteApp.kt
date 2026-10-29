package dev.dfte.app

import android.app.Application
import android.util.Log
import kotlin.concurrent.thread
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking

/**
 * Holds the one engine for the process (manual §22: a single long-lived TransferManager).
 *
 * It is built on a background thread at launch: unwrapping the identity from the
 * Keystore, loading the Rust library and starting its runtime took most of a cold start
 * when done on the main thread. The UI draws its background until [engineReady] has it.
 */
class DfteApp : Application() {
    private val built = CompletableDeferred<Engine>()
    private val main = CoroutineScope(SupervisorJob() + Dispatchers.Main.immediate)
    private val _engineReady = MutableStateFlow<Engine?>(null)
    val engineReady: StateFlow<Engine?> = _engineReady
    val nav = Nav()

    /** The engine; waits for it if called before it is built (only paths after the UI is up do). */
    val engine: Engine get() = _engineReady.value ?: runBlocking { built.await() }

    override fun onCreate() {
        super.onCreate()
        thread(name = "dfte-engine-init") {
            try {
                val e = Engine(this)
                Log.i("dfte", "engine ready ${android.os.SystemClock.uptimeMillis() - android.os.Process.getStartUptimeMillis()} ms after process start")
                _engineReady.value = e
                built.complete(e)
            } catch (t: Throwable) {
                // Without an engine the app can't do anything; fail as loudly as before.
                Log.e("dfte", "engine failed to start", t)
                built.completeExceptionally(t)
                main.launch { throw t }
            }
        }
    }

    /** Runs [block] on the main thread once the engine exists (at once if it does). */
    fun withEngine(block: (Engine) -> Unit) {
        val e = _engineReady.value
        if (e != null) block(e) else main.launch { block(built.await()) }
    }
}
