plugins {
    id("com.android.application")
}

android {
    namespace = "org.simulationrift.poc"
    compileSdk = 36

    defaultConfig {
        applicationId = "org.simulationrift.poc"
        minSdk = 30
        targetSdk = 36
        versionCode = 1
        versionName = "0.0.0-poc"
        ndk {
            abiFilters += listOf("arm64-v8a", "x86_64")
        }
    }

    buildFeatures {
        aidl = true
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }

    packaging {
        // Keep .so files uncompressed and page-aligned in the APK (16 KB devices).
        jniLibs.useLegacyPackaging = false
    }
}

dependencies {
    implementation("androidx.webkit:webkit:1.17.1")
    implementation("androidx.core:core-ktx:1.17.0")
}
