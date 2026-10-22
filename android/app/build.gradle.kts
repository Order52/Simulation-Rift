plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.plugin.compose")
}

android {
    namespace = "org.simulationrift.app"
    compileSdk {
        version = release(37)
    }

    defaultConfig {
        applicationId = "org.simulationrift.app"
        minSdk = 30
        targetSdk = 36
        versionCode = providers.gradleProperty("rift.versionCode").get().toInt()
        versionName = providers.gradleProperty("rift.versionName").get()
        ndk {
            // Phones are arm64; x86_64 is for emulators on Intel hosts and CI.
            // -Prift.abis=arm64-v8a makes a debug build for a phone half the size.
            abiFilters += providers.gradleProperty("rift.abis").orElse("arm64-v8a,x86_64").get().split(",")
        }
        testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"
    }

    buildTypes {
        release {
            // Shrinking also removes code paths an attacker could reuse; the
            // rules keep what JNA and the UniFFI bindings reach by reflection.
            // No signing config: release APKs are signed outside the build,
            // so no key or password is ever in the repository.
            isMinifyEnabled = true
            isShrinkResources = true
            proguardFiles(getDefaultProguardFile("proguard-android-optimize.txt"), "proguard-rules.pro")
        }
    }

    buildFeatures {
        aidl = true
        compose = true
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }

    sourceSets {
        // Kotlin bindings generated from rift-ffi by build.sh (never edited by hand).
        getByName("main").kotlin.directories += "build/generated-rift/kotlin"
        // The signed demo threat database, debug builds only (build.sh).
        getByName("debug").assets.directories += "build/generated-intel"
        // Rift AI's URL model and its report (models/, trained by tools/rift-train).
        getByName("main").assets.directories += "../../models"
        // The production root for updates, when the build is given one (build.sh, RIFT_INTEL_ROOT).
        getByName("main").assets.directories += "build/generated-intel-root"
        // Third-party notices (§25): the Rust crates and the Apache License text
        // (build.sh, notices.py), and this APK's Android libraries (notices.gradle.kts).
        getByName("main").assets.directories += listOf(
            "../build/generated-notices/rust", "../build/generated-notices/common", "build/generated-notices/android",
        )
    }

    packaging {
        // Keep .so files uncompressed and page-aligned in the APK (16 KB devices).
        jniLibs.useLegacyPackaging = false
    }
}

// Release builds are for phones: arm64 only (x86_64 is over half the APK).
androidComponents {
    onVariants(selector().withBuildType("release")) { variant ->
        variant.packaging.jniLibs.excludes.add("lib/x86_64/**")
    }
}

apply(from = rootProject.file("notices.gradle.kts"))

dependencies {
    testImplementation("junit:junit:4.13.2")
    implementation(platform("androidx.compose:compose-bom:2026.09.00"))
    implementation("androidx.compose.material3:material3")
    implementation("androidx.activity:activity-compose:1.13.0")
    // The controller never depends on WebView (§8.4): only the browser app does.
    implementation(project(":bridge"))
    implementation("androidx.core:core-ktx:1.17.0")
    // UniFFI's Kotlin bindings call the Rust library through JNA.
    implementation("net.java.dev.jna:jna:5.19.1@aar")
    // Extra isolation (§8.9), off unless the user turns it on: Shizuku or Sui
    // runs Rift's helper (HardeningService) as shell or root.
    implementation("dev.rikka.shizuku:api:13.1.5")
    implementation("dev.rikka.shizuku:provider:13.1.5")

    androidTestImplementation("androidx.test:runner:1.7.0")
    androidTestImplementation("androidx.test.ext:junit:1.3.0")
    androidTestImplementation("androidx.test.uiautomator:uiautomator:2.3.0")
}
