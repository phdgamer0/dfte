// Copyright (c) 2026 Yazdan Samari. All rights reserved except as granted by LICENSE.
// SPDX-License-Identifier: PolyForm-Shield-1.0.0

package dev.dfte.app

import android.content.Context
import android.media.MediaScannerConnection
import android.os.Environment
import android.util.Log
import java.io.File
import java.io.FileInputStream
import java.io.FileOutputStream

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
            // A rename is metadata-only when both sides are on one volume. Since Android 11
            // app storage and Downloads are separate mounts (rename fails), so copy and
            // delete instead: slower, never lossy.
            if (!item.renameTo(target)) {
                try {
                    copyTree(item, target)
                } catch (e: Exception) {
                    // Don't leave half a file in Downloads; the staged copy is still whole.
                    target.deleteRecursively()
                    throw e
                }
                check(item.deleteRecursively()) { "copied ${item.name} but could not remove the staged copy" }
            }
            moved += target
        }
        if (!from.delete()) Log.w("dfte", "staging folder ${from.path} not empty after publishing")
        val files = moved.flatMap { f -> if (f.isDirectory) f.walkTopDown().filter { it.isFile }.toList() else listOf(f) }
        MediaScannerConnection.scanFile(ctx, files.map { it.path }.toTypedArray(), null, null)
        return moved
    }

    /**
     * Copies a file or folder. Files go through FileChannel.transferTo in large steps:
     * Downloads sits behind Android's FUSE layer, where every write is a round trip to the
     * media provider, so File.copyTo's 8 KiB writes are what made publishing slow.
     */
    private fun copyTree(from: File, to: File) {
        if (from.isDirectory) {
            if (!to.mkdirs() && !to.isDirectory) error("cannot create ${to.path}")
            for (child in from.listFiles().orEmpty()) copyTree(child, File(to, child.name))
            return
        }
        FileInputStream(from).channel.use { src ->
            FileOutputStream(to).channel.use { dst ->
                val size = src.size()
                var pos = 0L
                while (pos < size) {
                    val n = src.transferTo(pos, minOf(COPY_STEP, size - pos), dst)
                    if (n <= 0) error("copy of ${from.name} stalled at $pos of $size bytes")
                    pos += n
                }
                dst.force(false)
            }
        }
    }

    private const val COPY_STEP = 8L shl 20

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
