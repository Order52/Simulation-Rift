plugins {
    id("com.android.application")
}

// A test app for S24 and S28: what another installed app can do to Rift.
// It is signed with a different key and must not depend on :bridge, whose
// manifest would make it define Rift's permission.
android {
    namespace = "org.simulationrift.outsider"
    compileSdk {
        version = release(37)
    }

    defaultConfig {
        applicationId = "org.simulationrift.outsider"
        minSdk = 30
        targetSdk = 36
        versionCode = 1
        versionName = "test"
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }

    // A throwaway key that build.sh generates under android/build/ (never
    // committed). The password protects nothing: the key only has to differ
    // from Rift's.
    signingConfigs {
        create("outsider") {
            storeFile = rootProject.layout.buildDirectory.file("outsider.jks").get().asFile
            storePassword = "rift-outsider"
            keyAlias = "outsider"
            keyPassword = "rift-outsider"
        }
    }
    buildTypes {
        getByName("debug") {
            signingConfig = signingConfigs.getByName("outsider")
        }
    }
}
