// Copyright (c) 2026 Yazdan Samari. All rights reserved except as granted by LICENSE.
// SPDX-License-Identifier: PolyForm-Shield-1.0.0

package dev.dfte.app

import android.content.Context
import android.net.Uri
import android.os.ParcelFileDescriptor
import android.provider.OpenableColumns
import android.system.Os
import java.io.Closeable
import java.io.File
import java.util.UUID

/**
 * Files chosen in the system picker, made visible to the Rust core as paths
 * without copying them. The picker hands out `content://` URIs; each one is
 * opened once and kept open, and a symlink named after the file points at its
 * `/proc/self/fd/N`. The engine follows top-level symlinks and takes the name
 * from the link, so the receiver sees the real file name.
 */
class Picked private constructor(
    private val dir: File,
    private val fds: List<ParcelFileDescriptor>,
    val paths: List<String>,
    val names: List<String>,
    val totalBytes: Long,
) : Closeable {

    val label: String get() = if (names.size == 1) names[0] else "${names[0]} + ${names.size - 1}"

    override fun close() {
        fds.forEach { it.close() }
        dir.deleteRecursively()
    }

    class NotLocal(name: String) : Exception("$name isn't stored on this phone. Download it first, then send it.")

    companion object {
        fun open(ctx: Context, uris: List<Uri>): Picked {
            require(uris.isNotEmpty()) { "nothing selected" }
            val dir = File(ctx.cacheDir, "send/${UUID.randomUUID()}").apply { mkdirs() }
            val fds = ArrayList<ParcelFileDescriptor>()
            val names = ArrayList<String>()
            val paths = ArrayList<String>()
            var total = 0L
            try {
                for (uri in uris) {
                    val name = unique(displayName(ctx, uri), names)
                    val pfd = ctx.contentResolver.openFileDescriptor(uri, "r") ?: throw NotLocal(name)
                    fds += pfd
                    // Pipes and sockets (cloud providers streaming on demand) have no size.
                    if (pfd.statSize < 0) throw NotLocal(name)
                    val link = File(dir, name)
                    Os.symlink("/proc/self/fd/${pfd.fd}", link.path)
                    names += name
                    paths += link.path
                    total += pfd.statSize
                }
            } catch (e: Exception) {
                fds.forEach { it.close() }
                dir.deleteRecursively()
                throw e
            }
            return Picked(dir, fds, paths, names, total)
        }

        private fun displayName(ctx: Context, uri: Uri): String {
            val raw = ctx.contentResolver.query(uri, arrayOf(OpenableColumns.DISPLAY_NAME), null, null, null)?.use { c ->
                if (c.moveToFirst()) c.getString(0) else null
            } ?: uri.lastPathSegment ?: "file"
            // A peer validates paths too (manual §35); keep ours plain so nothing is refused.
            val clean = raw.replace('/', '_').replace('\\', '_').trim().trimStart('.')
            return clean.ifEmpty { "file" }
        }

        private fun unique(name: String, taken: List<String>): String {
            if (name !in taken) return name
            val dot = name.lastIndexOf('.').takeIf { it > 0 } ?: name.length
            var i = 2
            while (true) {
                val n = "${name.substring(0, dot)} ($i)${name.substring(dot)}"
                if (n !in taken) return n
                i++
            }
        }
    }
}
