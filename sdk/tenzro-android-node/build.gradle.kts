// The light node for an Android app: its foreground service, and the Keystore keys the node's Android backend
// (crates/tenzro-device-key, through JNI) calls. The native library is the crate in native/.
plugins {
    id("com.android.library") version "9.5.2"
}

android {
    namespace = "com.tenzro.keystore"
    compileSdk = 37

    defaultConfig {
        // The node calls these classes through JNI only: an app that shrinks its code keeps them.
        consumerProguardFiles("consumer-rules.pro")
        minSdk = 28
        testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"
    }
}

dependencies {
    testImplementation("junit:junit:4.13.2")
    androidTestImplementation("junit:junit:4.13.2")
    androidTestImplementation("androidx.test:runner:1.7.0")
    androidTestImplementation("androidx.test.ext:junit:1.3.0")
}
