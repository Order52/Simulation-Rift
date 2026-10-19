plugins {
    id("com.android.application")
}

android {
    namespace = "org.simulationrift.poc.outsider"
    compileSdk {
        version = release(37)
    }
    defaultConfig {
        applicationId = "org.simulationrift.poc.outsider"
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
    // A different signer from the other two apps: a throwaway key that
    // build.sh generates under build/ (never committed).
    signingConfigs {
        create("outsider") {
            storeFile = rootProject.file("build/outsider.jks")
            storePassword = "poc-outsider"
            keyAlias = "outsider"
            keyPassword = "poc-outsider"
        }
    }
    buildTypes {
        getByName("debug") {
            signingConfig = signingConfigs.getByName("outsider")
        }
    }
}

