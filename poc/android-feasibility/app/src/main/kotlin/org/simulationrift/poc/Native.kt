package org.simulationrift.poc

/** JNI bindings to `librift_poc_native.so` (poc/android-native). */
object Native {
    init {
        System.loadLibrary("rift_poc_native")
    }

    external fun probes(canaryPath: String, tcpPort: Int): String

    /** [timeoutMs] 0 means no timeout. */
    external fun yaraScan(rules: String, fd: Int, timeoutMs: Long): String
}
