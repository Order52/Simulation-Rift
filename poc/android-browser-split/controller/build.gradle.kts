plugins {
    id("com.android.application")
}

android {
    namespace = "org.simulationrift.poc.controller"
    compileSdk {
        version = release(37)
    }
    defaultConfig {
        applicationId = "org.simulationrift.poc.controller"
        minSdk = 30
        targetSdk = 36
        versionCode = 1
        versionName = "poc"
    }
    buildFeatures {
        aidl = true
    }
    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
    sourceSets {
        getByName("main").aidl.directories += rootProject.file("aidl").path
    }
}

dependencies {
    implementation("androidx.webkit:webkit:1.17.1")
}
