package org.simulationrift.app

import android.app.KeyguardManager
import android.content.Context
import android.hardware.biometrics.BiometricManager.Authenticators
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyInfo
import android.security.keystore.KeyPermanentlyInvalidatedException
import android.security.keystore.KeyProperties
import android.security.keystore.StrongBoxUnavailableException
import java.security.KeyStore
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.SecretKeyFactory
import javax.crypto.spec.GCMParameterSpec

/**
 * The vault-wrapping key (§8.7): AES-256-GCM in Android Keystore, never
 * exportable, usable only while the device is unlocked and only for one
 * operation after the user authenticates (biometric or lock-screen
 * credential, through BiometricPrompt with a CryptoObject). StrongBox if the
 * device has it, otherwise the TEE.
 *
 * The wrapped identity is `[FORMAT][12-byte IV][ciphertext + 16-byte tag]`.
 */
internal object VaultKeystore {
    /** Thrown when the key cannot be used; `message` is a sentence for the user. */
    class Unavailable(message: String, cause: Throwable? = null) : Exception(message, cause)

    /** Auth-bound keys need a secure lock screen; without one the vault uses a passphrase. */
    fun deviceSecure(context: Context): Boolean =
        context.getSystemService(KeyguardManager::class.java).isDeviceSecure

    /**
     * A new key, replacing any earlier one: it is created only for a new
     * vault, and the vault an earlier key wrapped no longer exists.
     */
    fun newEncryptCipher(): Cipher {
        val key = try {
            generate(strongBox = true)
        } catch (e: StrongBoxUnavailableException) {
            generate(strongBox = false)
        }
        return Cipher.getInstance(TRANSFORMATION).apply { init(Cipher.ENCRYPT_MODE, key) }
    }

    /** The cipher that unwraps `wrapped`, to be authorized by the user. */
    fun decryptCipher(wrapped: ByteArray): Cipher {
        if (wrapped.size < 1 + IV_BYTES + TAG_BYTES || wrapped[0] != FORMAT) {
            throw Unavailable("The vault's wrapped key is not in a format this version reads.")
        }
        // Removing the screen lock deletes the key outright (API 35 emulator,
        // Phase 4); an enrolment change can leave it invalidated instead.
        val key = keyStore().getKey(ALIAS, null) as? SecretKey ?: throw Unavailable(INVALIDATED)
        return try {
            Cipher.getInstance(TRANSFORMATION).apply {
                init(Cipher.DECRYPT_MODE, key, GCMParameterSpec(TAG_BYTES * 8, wrapped, 1, IV_BYTES))
            }
        } catch (e: KeyPermanentlyInvalidatedException) {
            throw Unavailable(INVALIDATED, e)
        }
    }

    /** Wraps `secret` with an authorized encrypt cipher. */
    fun seal(cipher: Cipher, secret: ByteArray): ByteArray {
        val iv = cipher.iv
        check(iv.size == IV_BYTES) { "unexpected IV length ${iv.size}" }
        return byteArrayOf(FORMAT) + iv + cipher.doFinal(secret)
    }

    /** Unwraps with an authorized decrypt cipher; a changed blob fails its GCM tag. */
    fun open(cipher: Cipher, wrapped: ByteArray): ByteArray =
        try {
            cipher.doFinal(wrapped, 1 + IV_BYTES, wrapped.size - 1 - IV_BYTES)
        } catch (e: javax.crypto.AEADBadTagException) {
            throw Unavailable("The vault's wrapped key failed its check, so it was changed or damaged.", e)
        }

    /** Where the key lives, for the vault screen ("StrongBox", "TEE", or what Keystore reports). */
    fun securityLevel(): String? {
        val key = keyStore().getKey(ALIAS, null) as? SecretKey ?: return null
        val info = SecretKeyFactory.getInstance(key.algorithm, PROVIDER).getKeySpec(key, KeyInfo::class.java) as KeyInfo
        return when (info.securityLevel) {
            KeyProperties.SECURITY_LEVEL_STRONGBOX -> "StrongBox"
            KeyProperties.SECURITY_LEVEL_TRUSTED_ENVIRONMENT -> "TEE"
            KeyProperties.SECURITY_LEVEL_SOFTWARE -> "software only"
            else -> "unknown"
        }
    }

    /** Removes the key; called when a platform vault is deleted. */
    fun delete() = keyStore().deleteEntry(ALIAS)

    const val AUTHENTICATORS = Authenticators.BIOMETRIC_STRONG or Authenticators.DEVICE_CREDENTIAL

    const val INVALIDATED = "The vault's key is gone from this device's keystore: Android removes it when the screen " +
        "lock is removed or new fingerprints or faces are enrolled. This vault can no longer be opened; delete it to start a new one."

    /** [INVALIDATED], for a vault that has a recovery passphrase. */
    const val INVALIDATED_RECOVERABLE = "The vault's key is gone from this device's keystore: Android removes it when the " +
        "screen lock is removed or new fingerprints or faces are enrolled. Unlock with the recovery passphrase instead."

    private fun generate(strongBox: Boolean): SecretKey {
        val spec = KeyGenParameterSpec.Builder(ALIAS, KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT)
            .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
            .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
            .setKeySize(256)
            .setUnlockedDeviceRequired(true)
            .setUserAuthenticationRequired(true)
            // 0: every use needs its own authentication, bound to the operation.
            .setUserAuthenticationParameters(0, KeyProperties.AUTH_BIOMETRIC_STRONG or KeyProperties.AUTH_DEVICE_CREDENTIAL)
            .setIsStrongBoxBacked(strongBox)
            .build()
        return KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, PROVIDER).run {
            init(spec)
            generateKey()
        }
    }

    private fun keyStore() = KeyStore.getInstance(PROVIDER).apply { load(null) }

    private const val PROVIDER = "AndroidKeyStore"
    private const val ALIAS = "rift-vault-wrap"
    private const val TRANSFORMATION = "AES/GCM/NoPadding"
    private const val FORMAT: Byte = 1
    private const val IV_BYTES = 12
    private const val TAG_BYTES = 16
}
