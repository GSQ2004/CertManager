plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
    id("org.jetbrains.kotlin.plugin.compose")
}
android {
    namespace = "com.certmanager.android"
    compileSdk = 36
    buildToolsVersion = "36.0.0"
    ndkVersion = "27.2.12479018"
    externalNativeBuild { cmake { path = file("src/main/cpp/CMakeLists.txt"); version = "3.22.1" } }
    defaultConfig {
        applicationId = "com.certmanager.android"
        minSdk = 29
        ndk { abiFilters += listOf("arm64-v8a", "x86_64") }
        externalNativeBuild { cmake { arguments += "-DANDROID_STL=c++_static" } }
        targetSdk = 36
        versionCode = 3
        versionName = "1.2.0"
    }
    // Optional release signing is separate from debug and only activates when all secret inputs exist.
    val releaseStore = providers.environmentVariable("CERTMANAGER_KEYSTORE").orNull
    val releasePassword = providers.environmentVariable("CERTMANAGER_STORE_PASSWORD").orNull
    val releaseAlias = providers.environmentVariable("CERTMANAGER_KEY_ALIAS").orNull
    val releaseKeyPassword = providers.environmentVariable("CERTMANAGER_KEY_PASSWORD").orNull
    if (listOf(releaseStore, releasePassword, releaseAlias, releaseKeyPassword).all { !it.isNullOrBlank() }) {
        signingConfigs.create("privateRelease") {
            storeFile = file(releaseStore!!); storePassword = releasePassword
            keyAlias = releaseAlias; keyPassword = releaseKeyPassword
        }
        buildTypes.getByName("release").signingConfig = signingConfigs.getByName("privateRelease")
    }
    buildFeatures { compose = true }
    bundle { language { enableSplit = false } }
    compileOptions { sourceCompatibility = JavaVersion.VERSION_17; targetCompatibility = JavaVersion.VERSION_17 }
    kotlinOptions { jvmTarget = "17" }
    testOptions { unitTests.isReturnDefaultValues = true }
    packaging { jniLibs.useLegacyPackaging = true; resources.excludes += "/META-INF/{AL2.0,LGPL2.1}" }
}
dependencies {
    implementation(platform("androidx.compose:compose-bom:2025.04.01"))
    implementation("androidx.activity:activity-compose:1.10.1")
    implementation("androidx.compose.material3:material3")
    implementation("androidx.compose.material:material-icons-extended")
    implementation("androidx.compose.ui:ui-tooling-preview")
    debugImplementation("androidx.compose.ui:ui-tooling")
    implementation("androidx.lifecycle:lifecycle-viewmodel-compose:2.9.0")
    implementation("androidx.lifecycle:lifecycle-runtime-compose:2.9.0")
    implementation("org.jetbrains.kotlinx:kotlinx-coroutines-android:1.10.2")
    testImplementation("junit:junit:4.13.2")
    testImplementation("org.jetbrains.kotlinx:kotlinx-coroutines-test:1.10.2")
}
