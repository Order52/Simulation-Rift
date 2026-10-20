plugins {
    id("com.android.library")
}

// What the controller and the browser share: the Binder interfaces between
// them, their codecs and the package identities. No WebView, no Rust.
android {
    namespace = "org.simulationrift.bridge"
    compileSdk {
        version = release(37)
    }

    defaultConfig {
        minSdk = 30
    }

    buildFeatures {
        aidl = true
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
}
