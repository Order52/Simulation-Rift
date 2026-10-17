package org.simulationrift.poc

/** JNI bindings to `librift_poc_native.so` (poc/android-native). */
object Native {
    init {
        System.loadLibrary("rift_poc_native")
    }

    external fun probes(canaryPath: String, tcpPort: Int): String

    external fun yaraScan(rules: String, fd: Int): String
}
