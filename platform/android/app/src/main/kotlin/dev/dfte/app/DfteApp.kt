package dev.dfte.app

import android.app.Application

/** Holds the one engine for the process (manual §22: a single long-lived TransferManager). */
class DfteApp : Application() {
    val engine: Engine by lazy { Engine(this) }
    val nav = Nav()
}
