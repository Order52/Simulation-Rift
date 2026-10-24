package org.simulationrift.app

import android.content.Context
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.Log
import java.io.File
import java.io.IOException
import java.security.GeneralSecurityException
import java.security.KeyStore
import java.util.concurrent.Executors
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import org.json.JSONArray
import org.json.JSONException
import org.json.JSONObject
import org.simulationrift.core.LinkCheck

/**
 * Check's history (§10.13): off unless the user turns it on. Then the last
 * [MAX_ENTRIES] links checked (address, verdict, time) are kept in one file
 * encrypted with AES-GCM under a key in Android Keystore, which never leaves
 * it. A reset does not touch it; Clear deletes it, and turning it off deletes
 * the file and the key. This is the one record Rift keeps of what the user
 * did, and only by choice.
 */
object CheckHistory {

    data class Entry(val time: Long, val address: String, val verdict: String, val severity: Int)

    data class State(val on: Boolean = false, val entries: List<Entry> = emptyList())

    private const val TAG = "RiftHistory"
    private const val DIR = "rift/history"
    private const val FILE = "history.bin"
    private const val SWITCH = "on"
    private const val KEY_ALIAS = "rift-check-history"
    private const val MAX_ENTRIES = 200
    private const val IV_BYTES = 12

    private val _state = MutableStateFlow(State())
    val state: StateFlow<State> = _state

    /** An address the user tapped in the history, for the home screen's Check to take. */
    val again = MutableStateFlow<String?>(null)

    private val work = Executors.newSingleThreadExecutor { Thread(it, "rift-history") }
    private lateinit var dir: File

    /** From Core.ensureStarted (main thread). */
    fun init(context: Context) {
        dir = File(context.filesDir, DIR).apply { mkdirs() }
        work.execute {
            if (!File(dir, SWITCH).isFile) return@execute
            _state.value = State(on = true, entries = load())
        }
    }

    fun setOn(on: Boolean) {
        work.execute {
            if (on) {
                File(dir, SWITCH).writeText("1")
                _state.value = State(on = true, entries = load())
            } else {
                forget()
                _state.value = State(on = false)
            }
        }
    }

    fun clear() {
        work.execute {
            File(dir, FILE).delete()
            _state.value = _state.value.copy(entries = emptyList())
        }
    }

    /** Called with every Check result; does nothing while the history is off. */
    fun record(check: LinkCheck) {
        if (!_state.value.on) return
        val entry = Entry(System.currentTimeMillis(), check.address, titleOf(severity(check)), severity(check))
        work.execute {
            if (!_state.value.on) return@execute
            val entries = (listOf(entry) + _state.value.entries).take(MAX_ENTRIES)
            _state.value = _state.value.copy(entries = entries)
            store(entries)
        }
    }

    /** The verdict titles of [verdictOf], by [severity]. */
    fun titleOf(severity: Int): String = when (severity) {
        5 -> "Known malicious"
        4 -> "Rift won't open this"
        3 -> "Listed as dangerous"
        2 -> "Looks dangerous"
        1 -> "Warning signs"
        else -> "No known threats found"
    }

    private fun forget() {
        File(dir, FILE).delete()
        File(dir, SWITCH).delete()
        try {
            KeyStore.getInstance("AndroidKeyStore").apply { load(null) }.deleteEntry(KEY_ALIAS)
        } catch (e: GeneralSecurityException) {
            Log.w(TAG, "key not deleted: ${e.message}")
        } catch (e: IOException) {
            Log.w(TAG, "key not deleted: ${e.message}")
        }
    }

    private fun key(): SecretKey {
        val store = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
        (store.getKey(KEY_ALIAS, null) as? SecretKey)?.let { return it }
        return KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore").apply {
            init(
                KeyGenParameterSpec.Builder(KEY_ALIAS, KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT)
                    .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                    .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                    .setKeySize(256)
                    .build(),
            )
        }.generateKey()
    }

    /** On [work]. */
    private fun store(entries: List<Entry>) {
        val json = JSONArray(entries.map {
            JSONObject().put("t", it.time).put("a", it.address).put("v", it.verdict).put("s", it.severity)
        }).toString().toByteArray()
        try {
            val cipher = Cipher.getInstance("AES/GCM/NoPadding").apply { init(Cipher.ENCRYPT_MODE, key()) }
            val sealed = cipher.iv + cipher.doFinal(json)
            File(dir, "$FILE.tmp").apply { writeBytes(sealed) }.renameTo(File(dir, FILE))
        } catch (e: GeneralSecurityException) {
            Log.e(TAG, "history not saved", e)
        } catch (e: IOException) {
            Log.e(TAG, "history not saved", e)
        }
    }

    /** On [work]: the saved entries; none if there are none or they cannot be read (a new key, say). */
    private fun load(): List<Entry> {
        val file = File(dir, FILE)
        if (!file.isFile) return emptyList()
        return try {
            val sealed = file.readBytes()
            if (sealed.size <= IV_BYTES) return emptyList()
            val cipher = Cipher.getInstance("AES/GCM/NoPadding")
            cipher.init(Cipher.DECRYPT_MODE, key(), GCMParameterSpec(128, sealed.copyOfRange(0, IV_BYTES)))
            val array = JSONArray(String(cipher.doFinal(sealed, IV_BYTES, sealed.size - IV_BYTES)))
            (0 until minOf(array.length(), MAX_ENTRIES)).map { i ->
                val o = array.getJSONObject(i)
                Entry(o.getLong("t"), o.getString("a"), o.getString("v"), o.optInt("s"))
            }
        } catch (e: GeneralSecurityException) {
            Log.w(TAG, "history unreadable, starting again: ${e.message}")
            emptyList()
        } catch (e: IOException) {
            Log.w(TAG, "history unreadable: ${e.message}")
            emptyList()
        } catch (e: JSONException) {
            Log.w(TAG, "history unreadable: ${e.message}")
            emptyList()
        }
    }
}
