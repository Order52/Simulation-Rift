plugins {
    id("com.android.application") version "9.4.1" apply false
    id("com.android.library") version "9.4.1" apply false
    // Must match the Kotlin version built into the Android Gradle plugin.
    id("org.jetbrains.kotlin.plugin.compose") version "2.2.10" apply false
}

// Every module's resolved dependencies, transitive ones included, are pinned
// in its gradle.lockfile: a new version needs `--write-locks` and shows in
// review. CI scans the lockfiles for known advisories (OSV).
subprojects {
    dependencyLocking { lockAllConfigurations() }
}
