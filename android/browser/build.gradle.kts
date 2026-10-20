plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.plugin.compose")
}

// The browser app (§8.2, ADR-04): the WebView host and its session service,
// under a UID that owns nothing of Rift's. It never loads the Rust library.
android {
    namespace = "org.simulationrift.browser"
    compileSdk {
        version = release(37)
    }

    defaultConfig {
        applicationId = "org.simulationrift.browser"
        minSdk = 30
        targetSdk = 36
        versionCode = 1
        versionName = "0.3.0-phase3"
    }

    buildTypes {
        release {
            isMinifyEnabled = true
            isShrinkResources = true
            proguardFiles(getDefaultProguardFile("proguard-android-optimize.txt"))
        }
    }

    buildFeatures {
        compose = true
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
}

dependencies {
    implementation(project(":bridge"))
    implementation(platform("androidx.compose:compose-bom:2026.09.00"))
    implementation("androidx.compose.material3:material3")
    implementation("androidx.activity:activity-compose:1.13.0")
    implementation("androidx.webkit:webkit:1.17.1")

    testImplementation("junit:junit:4.13.2")
}
