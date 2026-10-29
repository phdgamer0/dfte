package dev.dfte.app

import android.content.Context
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.Log
import java.io.File
import java.security.KeyStore
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec
import uniffi.platform_ffi.generateIdentity

/**
 * The device's Ed25519 secret (manual §6/§12.3). It is stored wrapped by an
 * AES-GCM key that lives in the Android Keystore and never leaves it, in
 * no-backup storage so it doesn't travel to other devices.
 */
object IdentityStore {
    private const val ALIAS = "dfte-identity-wrap"
    private const val FILE = "identity.bin"
    private const val IV_LEN = 12

    class Loaded(val secret: ByteArray, val wasReset: Boolean)

    fun load(ctx: Context): Loaded {
        val file = File(ctx.noBackupFilesDir, FILE)
        val existed = file.exists()
        if (existed) {
            try {
                return Loaded(unwrap(file.readBytes()), wasReset = false)
            } catch (e: Exception) {
                // The Keystore key is gone (e.g. lock-screen reset): the old identity is
                // unrecoverable. Make a new one and tell the user; peers must re-verify.
                Log.e("dfte", "identity could not be unwrapped; creating a new one", e)
            }
        }
        val secret = generateIdentity()
        val tmp = File(file.path + ".tmp")
        tmp.writeBytes(wrap(secret))
        check(tmp.renameTo(file)) { "could not save the device identity" }
        return Loaded(secret, wasReset = existed)
    }

    private fun key(): SecretKey {
        val ks = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
        (ks.getKey(ALIAS, null) as? SecretKey)?.let { return it }
        val gen = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore")
        gen.init(
            KeyGenParameterSpec.Builder(ALIAS, KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT)
                .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                .setKeySize(256)
                .build(),
        )
        return gen.generateKey()
    }

    private fun wrap(secret: ByteArray): ByteArray {
        val c = Cipher.getInstance("AES/GCM/NoPadding").apply { init(Cipher.ENCRYPT_MODE, key()) }
        return c.iv + c.doFinal(secret)
    }

    private fun unwrap(blob: ByteArray): ByteArray {
        val c = Cipher.getInstance("AES/GCM/NoPadding")
        c.init(Cipher.DECRYPT_MODE, key(), GCMParameterSpec(128, blob, 0, IV_LEN))
        return c.doFinal(blob, IV_LEN, blob.size - IV_LEN)
    }
}
