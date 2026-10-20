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
        versionCode = 1
        versionName = "0.3.0-phase3"
        ndk {
            abiFilters += listOf("arm64-v8a", "x86_64")
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
        // The production root for updates, when the build is given one (build.sh, RIFT_INTEL_ROOT).
        getByName("main").assets.directories += "build/generated-intel-root"
    }

    packaging {
        // Keep .so files uncompressed and page-aligned in the APK (16 KB devices).
        jniLibs.useLegacyPackaging = false
    }
}

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

    androidTestImplementation("androidx.test:runner:1.7.0")
    androidTestImplementation("androidx.test.ext:junit:1.3.0")
    androidTestImplementation("androidx.test.uiautomator:uiautomator:2.3.0")
}
