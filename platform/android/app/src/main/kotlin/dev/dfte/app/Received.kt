package dev.dfte.app

import android.content.Context
import android.media.MediaScannerConnection
import android.os.Environment
import android.util.Log
import java.io.File

/**
 * Manual §14: the engine writes into app-private storage (no FUSE in the data
 * path); once a transfer is verified, its files move into Downloads/DFTE.
 */
object Received {
    /** Where a receive job writes: one folder per transfer, on the same volume as Downloads. */
    fun stagingFor(ctx: Context, transferId: String): File =
        File(ctx.getExternalFilesDir(null), "incoming/$transferId").apply { mkdirs() }

    fun downloads(): File = File(Environment.getExternalStoragePublicDirectory(Environment.DIRECTORY_DOWNLOADS), "DFTE")

    /** Moves every top-level item of [from] into Downloads/DFTE; returns the final locations. */
    fun publish(ctx: Context, from: File): List<File> {
        val dest = downloads()
        if (!dest.isDirectory && !dest.mkdirs()) error("cannot create ${dest.path}")
        val moved = ArrayList<File>()
        for (item in from.listFiles().orEmpty().sortedBy { it.name }) {
            val target = unique(dest, item.name)
            // A rename is metadata-only when both sides are on one volume. If the
            // platform refuses it, copy and delete instead: slower, never lossy.
            if (!item.renameTo(target)) {
                Log.w("dfte", "rename into Downloads refused for ${item.name}; copying")
                item.copyRecursively(target, overwrite = false)
                check(item.deleteRecursively()) { "copied ${item.name} but could not remove the staged copy" }
            }
            moved += target
        }
        if (!from.delete()) Log.w("dfte", "staging folder ${from.path} not empty after publishing")
        val files = moved.flatMap { f -> if (f.isDirectory) f.walkTopDown().filter { it.isFile }.toList() else listOf(f) }
        MediaScannerConnection.scanFile(ctx, files.map { it.path }.toTypedArray(), null, null)
        return moved
    }

    private fun unique(dir: File, name: String): File {
        var f = File(dir, name)
        if (!f.exists()) return f
        val dot = name.lastIndexOf('.').takeIf { it > 0 } ?: name.length
        var i = 2
        while (f.exists()) {
            f = File(dir, "${name.substring(0, dot)} ($i)${name.substring(dot)}")
            i++
        }
        return f
    }
}
