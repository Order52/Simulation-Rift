# Phase 4 report: the Rift Vault (Android)

**Status (20 Oct 2026):** built and tested on the host and on the API 35 emulator (16 KB pages, arm64). Files kept from a session are stored in `files/rift/vault`, sealed with age to a vault identity. That identity is wrapped by an Android Keystore key, which needs the user's biometric or screen lock for every use, or by a passphrase (age scrypt) when the device has no secure screen lock or the user prefers one. The vault locks on request, when Rift goes to the background, and after 5 minutes without a vault action. Export is explicit, warned, and goes only where the user chooses. **Not built:** the recovery passphrase, scan summaries in the index, and the Linux vault (Linux is now the last phase and will use Qt, §22). "Verified" means tested on macOS arm64 and on the stated emulator. Nothing here has run on a physical phone, so hardware backing of the key (TEE or StrongBox) is **unverified**: the emulator's Keystore reports "software only".

## What was built

| Part | What it does | Where |
|---|---|---|
| `rift-core::locker` | The vault directory: `identity.pass` (age scrypt, passphrase ≥ 10 characters) or `identity.platform` (an opaque blob the platform wrapped), `index.age` (+ `.prev`), and `objects/<random id>.age`. Unlocking authenticates the index (§14.1) and removes object files the index does not list. Adding streams the plaintext into a sealed temporary file, fsyncs it, renames it, then writes the index; removing writes the index first. Objects are capped at 100 MiB, as quarantined downloads are. | `crates/rift-core/src/locker.rs` |
| `rift-ffi::vault` | `VaultHandle` (create, open, unlock, lock, entries, read, remove) behind one mutex; the `PlatformKey` foreign trait through which Kotlin wraps a new identity; `Sessions::save_to_vault`, which decrypts a quarantined file with the session key in memory, checks it, and adds it to the vault. Errors are typed (`VaultFailure`); the identity secret crosses the FFI only to be wrapped and after being unwrapped. Names, types and source addresses are escaped for display. | `crates/rift-ffi/src/vault.rs` |
| `VaultKeystore` | AES-256-GCM key in Android Keystore: non-exportable, StrongBox if present (else TEE), `setUnlockedDeviceRequired(true)`, `setUserAuthenticationParameters(0, BIOMETRIC_STRONG or DEVICE_CREDENTIAL)`. A new key is made only when no vault exists, because it replaces the old one. | `android/app/src/main/kotlin/.../VaultKeystore.kt` |
| `Locker` | The controller's vault: one handle and one executor; create (screen lock or passphrase), unlock through the platform `BiometricPrompt` with a `CryptoObject`, lock (request, background, inactivity), keep from quarantine, export to a `CreateDocument` target, remove, delete. Every failure becomes one sentence for the vault card. | `android/app/src/main/kotlin/.../Locker.kt` |
| Vault previews | A kept file is previewed like a quarantined one, by a fresh isolated worker (images, PDFs) or as escaped text. The preview job belongs to the vault: its reply is refused once the vault has been locked, even if it was unlocked again meanwhile, and the screen's previews are cleared on lock (§14.2). | `rift-ffi` (`PreviewOwner`), `Locker.preview` |
| UI | A vault card (create, unlock, the kept files with preview, export and remove, lock now, delete with confirmation) and a "Keep in the vault" button under each quarantined file while the vault is unlocked. The export warning says that the copy leaves Rift's protection and was not made safe. | `MainActivity.kt` |
| Manifest | `USE_BIOMETRIC` (normal permission) for the prompt. The browser app is unchanged: it has no vault operation, and the vault directory is not visible to its UID. | `AndroidManifest.xml` |

## Results

| ID | Test | Result | Where |
|---|---|---|---|
| S18 | Vault truncation, tamper, swap or wrong key | **Pass (host).** Truncated and tampered objects fail to decrypt, a swapped object fails its index hash, another identity cannot authenticate the index, and a wrong passphrase is refused; no partial plaintext is returned. | `rift-core` `vault` and `locker` tests, `rift-ffi` vault tests |
| v1 | A kept file outlives the session; no plaintext on disk | **Pass (API 35).** A downloaded file (with a marker string) was kept from quarantine. The vault then held exactly `identity.pass`, `index.age`, `index.age.prev` and one `objects/<random id>.age`. No file in the controller's data directory contained the marker or an age secret key. After a reset (whose leftover check accepts the vault), the vault was locked; a wrong passphrase gave "the passphrase or key does not open this vault" and left it locked. The right one showed the same entry. Export wrote the original bytes to the chosen location; remove deleted the object file. | `v1_*`, [evidence](evidence/phase4-vault-api35-16k/) |
| v2 | Lock in the background and when idle | **Pass (API 35).** With the home screen in front and the vault unlocked, pressing Home locked it. With the inactivity limit set to 1.5 s for the test, the vault locked by itself 1.54 s after unlocking. | `v2_*` |
| v3 | Keystore key through the real prompt | **Pass (API 35).** With a PIN set from the shell, "create" and "unlock" each went through the system BiometricPrompt, and the PIN was typed into its credential screen. The stored blob is 103 bytes and contains no age secret key. After the PIN was removed, unlock said the key is gone and the vault cannot be opened. The key's security level was reported as **software only** (the emulator has no TEE). | `v3_*` |
| v4 | Kept files preview until the vault locks | **Pass (API 35).** A kept PNG was rendered (300×200) from the vault's copy by a fresh worker after the session had ended; no file held the PNG's marker; locking cleared the preview. P1, P2 and S19 (the shared preview path) passed again with it. On the host, a preview started before a lock is refused after it, even across a new unlock. | `v4_*`, `rift-ffi` `vault_previews_end_when_the_vault_locks` |
| — | Everything else, after the change | **Pass (API 35).** The full suite: 36 instrumented tests (the 33 from Phase 3 and v1–v3), then S16d, S16f, S14 and S13 driven from the host. The host-driven steps failed once when run straight after the instrumented tests: `adb root` was refused ("closed"), and in the next attempt S16d and S16f could not find their buttons. Both passed on two reruns. The cause is not established. The likeliest one is v3 leaving the keyguard up after the PIN was removed, so the test script now wakes the screen, dismisses the keyguard and retries `adb root`. | [evidence](evidence/phase4-vault-api35-16k/), [host steps](evidence/phase4-vault-api35-16k/host/) |

Host tests after this phase: 156 (rift-core 108, rift-ffi 13, rift-protocol 11, rift-update 10, rift-worker 10, rift-worker-ffi 4), plus the Linux-only `no_threads` test in CI. `clippy -D warnings`, `fmt` and `cargo deny` are clean.

## Findings

1. **Removing the screen lock deletes the Keystore key outright.** The design expected an invalidated key (`KeyPermanentlyInvalidatedException` when the cipher is initialised). On the API 35 emulator the entry was simply gone after `locksettings clear`. Both cases now give the same sentence ("The vault's key is gone from this device's keystore…") and the card offers to delete the vault. v3 found this by running the real path.
2. **Making a key destroys the previous one.** A new key under the same alias replaces the old one, so "create a vault" while a platform vault exists would make that vault unreadable. Creation now refuses before generating a key, and the core refuses `create_for_platform` before asking the platform to wrap anything (no prompt for a vault that already exists).
3. **Backgrounding and system screens.** Locking on `onStop` would also lock the vault while the export picker or the authentication prompt covers Rift, which breaks export. While such a screen that Rift opened is in front, the background lock is skipped; the inactivity lock still applies.
4. **Secret copies.** The identity secret and passphrases cross the FFI as byte arrays, which Kotlin and Rust overwrite after use. UniFFI's intermediate buffers and the Compose text field (an immutable `String`) are not erased. This matches §14.2: zeroization is best effort, and Rift does not claim every runtime copy is erased.
5. **Size.** `librift_ffi.so` grew by 0.15 MB on arm64 (to 7.72 MB) and 0.18 MB on x86_64 (to 8.62 MB). Native code per ABI is now 19.6 MB (arm64) and 24.3 MB (x86_64) against the 25 MB budget.

## Verified

- On the host: the locker tests (a passphrase vault across lock and unlock with no plaintext or display name on disk; a platform vault that stores only the wrapped blob and refuses another identity; an interrupted save swept on unlock; the 100 MiB limit; a swapped object failing its index check), the Phase 1 format tests (truncation, tampering, index authentication), and the FFI tests (a file kept from a session survives the reset; wrong passphrase and wrong secret are refused; a platform key that refuses leaves no vault behind; no prompt for an existing vault).
- On the API 35 emulator: everything marked Pass above.

## Unverified

- **Hardware backing of the key.** The emulator's Keystore is software only. StrongBox and TEE behaviour, and the security level shown on the vault card, need a physical phone.
- **Biometric unlock.** Only the screen-lock PIN was tested through the prompt; no fingerprint or face was enrolled, so invalidation by a new enrolment is untested.
- **Other API levels.** The vault tests ran on API 35 only; CI runs the suite on API 33 and 34 at the next push.
- **Plaintext in memory.** The inventory checks files, not memory. Kept and exported files pass through the controller's memory whole (at most 100 MiB).

## Could be improved

- An optional recovery passphrase that also wraps the identity, so a lost key is not a lost vault (§8.7).
- The scan summary in the index (§14.1), so a kept file shows the verdict it had.
- Streaming export and keep instead of whole-file buffers.
- A setting for the background lock and the inactivity timeout (§14.2 says "configurable").
