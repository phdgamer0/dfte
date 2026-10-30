// Copyright (c) 2026 Yazdan Samari. All rights reserved except as granted by LICENSE.
// SPDX-License-Identifier: PolyForm-Shield-1.0.0

package dev.dfte.app

import java.util.Locale
import uniffi.platform_ffi.ErrorCode
import uniffi.platform_ffi.IncomingOffer

/** User-facing words (ui-spec.html "Same words everywhere"; error copy from manual §36). */
object Copy {
    fun error(code: ErrorCode, peer: String?): String {
        val who = peer ?: "The other device"
        return when (code) {
            ErrorCode.PEER_LOST -> "Lost connection to $who. Move closer and try again."
            ErrorCode.CONNECTION_REJECTED, ErrorCode.DECLINED -> "$who declined the transfer."
            ErrorCode.AUTHENTICATION_FAILED -> "Security check failed. This may not be the device you expect, so the connection was blocked."
            ErrorCode.DISK_FULL -> "Not enough free space to receive this transfer."
            ErrorCode.PEER_DISK_FULL -> "$who doesn't have enough free space."
            ErrorCode.SOURCE_FILE_CHANGED -> "A file changed while sending. Try again."
            ErrorCode.SOURCE_FILE_MISSING -> "A file could not be found."
            ErrorCode.CORRUPTED_DATA -> "The transfer failed an integrity check and was stopped."
            ErrorCode.UNSUPPORTED_VERSION -> "$who's app version isn't compatible. Update both apps."
            ErrorCode.TIMEOUT -> "$who stopped responding."
            ErrorCode.CANCELLED -> "The transfer was cancelled."
            ErrorCode.UNSAFE_PATH -> "$who sent a file name that isn't allowed, so the transfer was stopped."
            ErrorCode.PROTOCOL_VIOLATION -> "$who sent something unexpected, so the transfer was stopped."
            ErrorCode.RADIO_UNAVAILABLE -> "Turn on Wi-Fi to find nearby devices."
            ErrorCode.PERMISSION_DENIED -> "DFTE needs a permission to do this."
            ErrorCode.DISCOVERY -> "Couldn't look for nearby devices."
            ErrorCode.IO -> "A storage error stopped the transfer."
            else -> "Something went wrong (${code.name.lowercase(Locale.ROOT).replace('_', ' ')})."
        }
    }

    fun offerLabel(offer: IncomingOffer): String {
        val first = offer.files.firstOrNull()?.path?.substringBefore('/') ?: "Files"
        val tops = offer.files.map { it.path.substringBefore('/') }.distinct().size
        return if (tops <= 1) first else "$first + ${tops - 1}"
    }

    /** Decimal units, like Android's own file sizes: 1.4 GB, 29.4 MB/s. */
    fun bytes(n: Long): String {
        if (n < 1000) return "$n B"
        val units = arrayOf("KB", "MB", "GB", "TB")
        var v = n / 1000.0
        var i = 0
        while (v >= 1000 && i < units.lastIndex) {
            v /= 1000
            i++
        }
        return if (v >= 100) String.format(Locale.ROOT, "%.0f %s", v, units[i]) else String.format(Locale.ROOT, "%.1f %s", v, units[i])
    }

    fun rate(bps: Long): String = String.format(Locale.ROOT, "%.1f", bps / 1_000_000.0)

    fun duration(secs: Long): String = when {
        secs < 0 -> "—"
        secs < 3600 -> String.format(Locale.ROOT, "%d:%02d", secs / 60, secs % 60)
        else -> String.format(Locale.ROOT, "%d:%02d:%02d", secs / 3600, secs / 60 % 60, secs % 60)
    }

    fun items(n: Int): String = if (n == 1) "1 file" else "$n files"

    /** Fingerprint shown in groups, as on the desktop (first four groups when short). */
    fun fingerprint(fp: String, short: Boolean = false): String = if (short) fp.split('-').take(4).joinToString("-") else fp
}
