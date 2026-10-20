package org.simulationrift.app

import android.app.Activity
import android.content.Context
import android.hardware.biometrics.BiometricPrompt
import android.net.Uri
import android.os.CancellationSignal
import android.util.Log
import java.io.File
import java.util.concurrent.Executors
import java.util.concurrent.ScheduledFuture
import java.util.concurrent.TimeUnit
import javax.crypto.Cipher
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.update
import org.simulationrift.core.PlatformKey
import org.simulationrift.core.ScanFailure
import org.simulationrift.core.Sessions
import org.simulationrift.core.VaultEntry
import org.simulationrift.core.VaultFailure
import org.simulationrift.core.VaultHandle
import org.simulationrift.core.VaultProtection
import org.simulationrift.core.vaultHasRecovery
import org.simulationrift.core.vaultProtection

/**
 * The Rift Vault on Android (§14): the files the user chose to keep after a
 * session, in `files/rift/vault`, sealed to an identity that is wrapped by
 * the Keystore key (§8.7) or, without a secure lock screen or by choice, by
 * a passphrase. The identity is in memory only while the vault is unlocked;
 * the vault locks on request, when Rift goes to the background, and after
 * [inactivityMs] without a vault action.
 *
 * The browser app has no way to reach any of this: CoreService has no vault
 * operation, and this directory is not visible to its UID (§8.3).
 */
object Locker {
    sealed interface State {
        data object Opening : State

        /** No vault yet; `deviceSecure`: the Keystore key is possible (a secure lock screen is set). */
        data class Absent(val deviceSecure: Boolean) : State

        /** `recovery`: a platform vault that also opens with its recovery passphrase. */
        data class Locked(val protection: VaultProtection, val recovery: Boolean) : State

        /**
         * `keyLevel`: where the platform key lives, or null if it is gone (the
         * vault was opened with the recovery passphrase).
         */
        data class Unlocked(
            val protection: VaultProtection,
            val entries: List<VaultEntry>,
            val keyLevel: String?,
            val recovery: Boolean,
        ) : State

        data class Failed(val message: String) : State
    }

    private val _state = MutableStateFlow<State>(State.Opening)
    val state: StateFlow<State> = _state

    /** The outcome of the last vault action, for the vault card. */
    private val _message = MutableStateFlow<String?>(null)
    val message: StateFlow<String?> = _message

    /** Quarantined files of the current session already kept, by file id. */
    private val _kept = MutableStateFlow<Set<String>>(emptySet())
    val kept: StateFlow<Set<String>> = _kept

    /**
     * Previews of kept files, by vault object id: shown only while the vault
     * stays unlocked, and cleared when it locks (§14.2).
     */
    private val _previews = MutableStateFlow<Map<String, Core.Preview>>(emptyMap())
    val previews: StateFlow<Map<String, Core.Preview>> = _previews

    // Counts locks; a preview finishing after a lock is not shown.
    private val locks = java.util.concurrent.atomic.AtomicLong()

    /** How long the vault stays unlocked without a vault action (§14.2: 5 minutes). */
    @Volatile internal var inactivityMs: Long = 5 * 60 * 1000L

    /**
     * Set while a system screen Rift opened for the vault is in front (the
     * export picker, the authentication prompt), so that covering Rift's
     * window with it is not taken for going to the background.
     */
    @Volatile var holding = false

    // Vault work is serialized here, off the UI thread: unlocking with a
    // passphrase runs scrypt, and saving or exporting moves up to 100 MiB.
    private val vaulting = Executors.newSingleThreadScheduledExecutor { Thread(it, "rift-vault") }
    private var timeout: ScheduledFuture<*>? = null

    // Written only on [vaulting].
    @Volatile private var handle: VaultHandle? = null
    private lateinit var app: Context
    private lateinit var dir: File

    fun open(context: Context) {
        app = context.applicationContext
        dir = File(app.filesDir, "rift/vault")
        vaulting.execute(::refresh)
    }

    fun createWithPassphrase(passphrase: ByteArray) = vaulting.execute {
        act("The vault was not created") {
            try {
                handle = VaultHandle.createWithPassphrase(dir.path, passphrase)
            } finally {
                passphrase.fill(0)
            }
            Log.i(TAG, "vault created (passphrase)")
            "Vault created. It is protected by your passphrase; if you forget it, the vault cannot be opened."
        }
    }

    /** Creates a vault whose identity the Keystore key wraps, after the user authenticates. */
    fun createWithDeviceLock(activity: Activity) = vaulting.execute {
        // A new key replaces the old one, which would lose the vault it wraps.
        if (vaultProtection(dir.path) != null) {
            _message.value = "The vault was not created: ${describe(VaultFailure.Exists())}"
            return@execute
        }
        val cipher = try {
            VaultKeystore.newEncryptCipher()
        } catch (e: Exception) {
            Log.w(TAG, "vault key not created", e)
            _message.value = "The vault was not created: the device's keystore refused a new key (${e.javaClass.simpleName})."
            return@execute
        }
        authenticate(activity, cipher, "Create the Rift vault") { authorized ->
            act("The vault was not created") {
                handle = VaultHandle.createForPlatform(dir.path, sealer(authorized))
                val level = VaultKeystore.securityLevel()
                Log.i(TAG, "vault created (platform, $level)")
                "Vault created. Its key is in this device's keystore ($level). If the lock screen is removed or new " +
                    "fingerprints or faces are enrolled, Android deletes the key; only a recovery passphrase opens the vault then."
            }
        }
    }

    fun unlockWithPassphrase(passphrase: ByteArray) = vaulting.execute {
        act("The vault was not unlocked") {
            try {
                opened().unlockWithPassphrase(passphrase)
            } finally {
                passphrase.fill(0)
            }
            Log.i(TAG, "vault unlocked (passphrase)")
            null
        }
    }

    fun unlockWithDeviceLock(activity: Activity) = vaulting.execute {
        val (vault, wrapped, cipher) = try {
            val vault = opened()
            val wrapped = vault.platformWrapped()
            Triple(vault, wrapped, VaultKeystore.decryptCipher(wrapped))
        } catch (e: VaultFailure) {
            _message.value = "The vault was not unlocked: ${describe(e)}"
            return@execute
        } catch (e: VaultKeystore.Unavailable) {
            val recoverable = e.message == VaultKeystore.INVALIDATED && vaultHasRecovery(dir.path)
            _message.value = if (recoverable) VaultKeystore.INVALIDATED_RECOVERABLE else e.message
            return@execute
        } catch (e: java.security.GeneralSecurityException) {
            Log.w(TAG, "vault key unusable", e)
            _message.value = "The vault was not unlocked: the device's keystore refused the key (${e.javaClass.simpleName})."
            return@execute
        }
        authenticate(activity, cipher, "Unlock the Rift vault") { authorized ->
            act("The vault was not unlocked") {
                val secret = VaultKeystore.open(authorized, wrapped)
                try {
                    vault.unlockWithSecret(secret)
                } finally {
                    secret.fill(0)
                }
                Log.i(TAG, "vault unlocked (platform)")
                null
            }
        }
    }

    /** Adds a second copy of a platform vault's identity under a passphrase (§8.7). */
    fun setRecoveryPassphrase(passphrase: ByteArray) = vaulting.execute {
        act("The recovery passphrase was not set") {
            try {
                unlocked().setRecoveryPassphrase(passphrase)
            } finally {
                passphrase.fill(0)
            }
            Log.i(TAG, "vault: recovery passphrase set")
            "Recovery passphrase set. If this device's key is lost, it opens the vault; keep it somewhere safe."
        }
    }

    fun unlockWithRecovery(passphrase: ByteArray) = vaulting.execute {
        act("The vault was not unlocked") {
            try {
                opened().unlockWithRecovery(passphrase)
            } finally {
                passphrase.fill(0)
            }
            Log.i(TAG, "vault unlocked (recovery)")
            null
        }
    }

    /**
     * After recovery: a new Keystore key wraps the identity again. Only when
     * the old key is gone, since a new key replaces it and would make the
     * stored wrapped identity unreadable if this did not complete.
     */
    fun protectAgain(activity: Activity) = vaulting.execute {
        val vault = handle?.takeIf { it.isUnlocked() } ?: return@execute
        if (VaultKeystore.securityLevel() != null) return@execute
        val cipher = try {
            VaultKeystore.newEncryptCipher()
        } catch (e: Exception) {
            Log.w(TAG, "vault key not created", e)
            _message.value = "The vault was not protected again: the device's keystore refused a new key (${e.javaClass.simpleName})."
            return@execute
        }
        authenticate(activity, cipher, "Protect the Rift vault") { authorized ->
            act("The vault was not protected again") {
                vault.rewrapForPlatform(sealer(authorized))
                Log.i(TAG, "vault: identity wrapped by a new key (${VaultKeystore.securityLevel()})")
                "The vault is protected by this device's screen lock again."
            }
        }
    }

    /** Drops the identity and the index from memory (§14.2). */
    fun lock(reason: String = "on request") = vaulting.execute {
        val vault = handle ?: return@execute
        if (!vault.isUnlocked()) return@execute
        locks.incrementAndGet()
        _previews.value = emptyMap()
        vault.lock() // also refuses the reply of any preview still running
        timeout?.cancel(false)
        Log.i(TAG, "vault locked: $reason")
        refresh()
    }

    /** Rift's window went to the background (not to a screen Rift opened for the vault). */
    fun backgrounded() {
        if (!holding) lock("Rift went to the background")
    }

    /** Copies quarantined file `fileId` of `generation` into the vault; the session's copy stays until reset. */
    internal fun keep(sessions: Sessions, generation: Long, fileId: String) = vaulting.execute {
        act("The file was not kept") {
            val entry = sessions.saveToVault(generation.toULong(), fileId, unlocked(), nowUnix())
            _kept.update { it + fileId }
            Log.i(TAG, "vault: kept a ${entry.size}-byte file")
            "Kept ${entry.displayName} in the vault. It is the original file and is still untrusted."
        }
    }

    /** The session ended: what the home screen shows as kept belongs to it. */
    internal fun sessionEnded() {
        _kept.value = emptySet()
    }

    /** Writes object `id` to `target`, which the user chose after the export warning (§11.4). */
    fun export(id: String, target: Uri) = vaulting.execute {
        holding = false
        act("The file was not exported") {
            val bytes = unlocked().read(id)
            try {
                val output = app.contentResolver.openOutputStream(target, "wt")
                    ?: throw java.io.IOException("the chosen location could not be opened")
                output.use { it.write(bytes) }
            } finally {
                bytes.fill(0)
            }
            Log.i(TAG, "vault: exported a ${bytes.size}-byte file")
            "Exported. The copy is outside Rift's protection now, and was not made safe."
        }
    }

    /** Previews kept file `id` like a quarantined one (§11.3), in a fresh isolated worker. */
    fun preview(id: String, service: Class<out android.app.Service> = PreviewService::class.java) = vaulting.execute {
        val vault = handle?.takeIf { it.isUnlocked() } ?: return@execute
        val unlock = locks.get()
        _previews.update { it + (id to Core.Preview(id)) }
        touch()
        Core.render(id, "the vault", service, { max -> vault.preview(id, max, max) }) { outcome ->
            if (locks.get() == unlock) _previews.update { it + (id to outcome) }
        }
    }

    /** Ids of kept files being scanned again. */
    private val _rescanning = MutableStateFlow<Set<String>>(emptySet())
    val rescanning: StateFlow<Set<String>> = _rescanning

    /**
     * Scans kept file `id` again with the installed database; the vault
     * records the result in place of the earlier one (rift-ffi refuses it if
     * the vault was locked meanwhile). The worker runs off [vaulting], so a
     * scan never delays a lock.
     */
    fun rescan(id: String, service: Class<out android.app.Service> = PreviewService::class.java) = vaulting.execute {
        val vault = handle?.takeIf { it.isUnlocked() } ?: return@execute
        if (id in _rescanning.value) return@execute
        _rescanning.update { it + id }
        touch()
        Core.scanKept(vault, id, service) { outcome ->
            vaulting.execute {
                _rescanning.update { it - id }
                if (handle?.isUnlocked() == true) touch()
                // The entries first, so the message never comes before the result it reports.
                refresh()
                _message.value = outcome.fold(
                    { v -> "Scanned again: ${v.label}" + (if (v.demo) " (DEMO database, not real coverage)" else "") + "." },
                    { e -> "The file was not scanned again: ${(e as? ScanFailure)?.let(::describe) ?: e.toString()}." },
                )
            }
        }
    }

    fun remove(id: String) = vaulting.execute {
        act("The file was not removed") {
            unlocked().remove(id)
            _previews.update { it - id }
            "Removed from the vault."
        }
    }

    /**
     * Deletes the vault and its key, for a vault that can no longer be opened
     * (a forgotten passphrase, an invalidated key) or is no longer wanted.
     */
    fun destroy() = vaulting.execute {
        locks.incrementAndGet()
        _previews.value = emptyMap()
        handle?.lock()
        handle = null
        timeout?.cancel(false)
        val deleted = dir.deleteRecursively()
        try {
            VaultKeystore.delete()
        } catch (e: java.security.GeneralSecurityException) {
            Log.w(TAG, "vault key not deleted", e)
        }
        Log.i(TAG, "vault deleted: $deleted")
        _message.value = if (deleted) "The vault and everything in it were deleted." else "The vault could not be deleted completely."
        refresh()
    }

    private fun refresh() {
        val vault = handle
        _state.value = try {
            when {
                vault != null && vault.isUnlocked() -> State.Unlocked(protection(), vault.entries(), keyLevel(), vaultHasRecovery(dir.path))
                else -> vaultProtection(dir.path)?.let { State.Locked(it, vaultHasRecovery(dir.path)) }
                    ?: State.Absent(VaultKeystore.deviceSecure(app))
            }
        } catch (e: VaultFailure) {
            State.Failed(describe(e))
        }
    }

    /** Runs a vault action on [vaulting]: its sentence, or why it failed, goes to [message]. */
    private fun act(failed: String, action: () -> String?) {
        _message.value = try {
            action().also { touch() }
        } catch (e: VaultFailure) {
            Log.w(TAG, "vault: $failed", e)
            "$failed: ${describe(e)}"
        } catch (e: VaultKeystore.Unavailable) {
            "$failed: ${e.message}"
        } catch (e: java.io.IOException) {
            Log.w(TAG, "vault: $failed", e)
            "$failed: ${e.message}"
        } catch (e: java.security.GeneralSecurityException) {
            Log.w(TAG, "vault: $failed", e)
            "$failed: the device's keystore refused the operation (${e.javaClass.simpleName})"
        }
        refresh()
    }

    /** Restarts the inactivity timer after a vault action. */
    private fun touch() {
        timeout?.cancel(false)
        timeout = vaulting.schedule({ lock("inactivity") }, inactivityMs, TimeUnit.MILLISECONDS)
    }

    private fun opened(): VaultHandle = handle ?: VaultHandle.open(dir.path).also { handle = it }

    private fun unlocked(): VaultHandle = handle?.takeIf { it.isUnlocked() } ?: throw VaultFailure.Locked()

    private fun protection(): VaultProtection = vaultProtection(dir.path) ?: throw VaultFailure.Missing()

    private fun keyLevel(): String? = if (protection() == VaultProtection.PLATFORM) {
        try {
            VaultKeystore.securityLevel()
        } catch (e: java.security.GeneralSecurityException) {
            null
        }
    } else {
        null
    }

    /** Hands the core an authorized cipher; every failure becomes a [VaultFailure], as the trait requires. */
    private fun sealer(cipher: Cipher) = object : PlatformKey {
        override fun wrap(secret: ByteArray): ByteArray = try {
            VaultKeystore.seal(cipher, secret)
        } catch (e: Exception) {
            throw VaultFailure.Platform("the keystore did not wrap the vault key (${e.javaClass.simpleName})")
        } finally {
            secret.fill(0)
        }
    }

    /**
     * Asks the user to authorize one use of the Keystore key (§8.7): a strong
     * biometric or the lock-screen credential, bound to `cipher`. `then` runs
     * on [vaulting] with the authorized cipher.
     */
    private fun authenticate(activity: Activity, cipher: Cipher, title: String, then: (Cipher) -> Unit) {
        holding = true
        activity.runOnUiThread {
            val prompt = BiometricPrompt.Builder(activity)
                .setTitle(title)
                .setDescription("Rift's vault key is in this device's keystore and needs your fingerprint, face or screen lock.")
                .setAllowedAuthenticators(VaultKeystore.AUTHENTICATORS)
                .build()
            prompt.authenticate(
                BiometricPrompt.CryptoObject(cipher),
                CancellationSignal(),
                vaulting,
                object : BiometricPrompt.AuthenticationCallback() {
                    override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
                        holding = false
                        val authorized = result.cryptoObject?.cipher
                        if (authorized == null) {
                            _message.value = "The device did not authorize the vault key."
                        } else {
                            then(authorized)
                        }
                    }

                    override fun onAuthenticationError(code: Int, text: CharSequence) {
                        holding = false
                        Log.i(TAG, "vault authentication ended: $code")
                        _message.value = "Not authorized: $text"
                    }
                },
            )
        }
    }

    // UniFFI renders errors as field lists, so the sentences are written here.
    internal fun describe(e: VaultFailure): String = when (e) {
        is VaultFailure.Missing -> "there is no vault"
        is VaultFailure.Exists -> "a vault already exists"
        is VaultFailure.Locked -> "the vault is locked"
        is VaultFailure.WeakPassphrase -> "the passphrase must have at least ${e.minimum} characters"
        is VaultFailure.WrongSecret -> "the passphrase or key does not open this vault"
        is VaultFailure.WrongProtection -> "the vault is protected another way"
        is VaultFailure.UnknownObject -> "the vault has no such file"
        is VaultFailure.NoRecovery -> "the vault has no recovery passphrase"
        is VaultFailure.TooLarge -> "files larger than ${e.limit} bytes are not kept"
        is VaultFailure.Damaged -> "the vault's data failed its check (${e.detail})"
        is VaultFailure.Storage -> "the vault's storage failed (${e.detail})"
        is VaultFailure.Platform -> e.detail
        is VaultFailure.SessionEnded -> "the session this file belonged to has ended"
        is VaultFailure.NotFound -> "the file is not in this session's quarantine"
        is VaultFailure.Poisoned -> "vault state is unusable after an internal error"
    }

    private fun describe(e: ScanFailure): String = when (e) {
        is ScanFailure.NoDatabase -> "no threat database is installed"
        is ScanFailure.Locked -> "the vault was locked before the scan finished, so the result was not recorded"
        is ScanFailure.NotFound -> "the vault has no such file"
        is ScanFailure.Storage -> "the vault's copy could not be read (${e.detail})"
        is ScanFailure.Unconfined -> "the scan worker is not confined (${e.detail})"
        is ScanFailure.BadReply -> "the scan worker sent an invalid reply (${e.detail})"
        is ScanFailure.SessionEnded -> "the session ended"
        is ScanFailure.Poisoned -> "vault state is unusable after an internal error"
    }

    private fun nowUnix(): ULong = (System.currentTimeMillis() / 1000).toULong()
}
