plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
    id("com.google.devtools.ksp")
}

android {
    namespace = "com.securevault"
    compileSdk = 34

    defaultConfig {
        applicationId = "com.securevault"
        minSdk = 26
        targetSdk = 34
        versionCode = 1
        versionName = "0.1.0-prototype"
        testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"

        // ---- Deployment settings (replace for a real backend) -------------------------------
        // Sync / integrity / wipe-command server. Must match network_security_config.xml.
        buildConfigField("String", "SYNC_HOST", "\"api.example.com\"")
        buildConfigField("String", "SYNC_BASE_URL", "\"https://api.example.com\"")
        // SHA-256 public-key pins (base64). PLACEHOLDERS: replace with your server's real pins.
        buildConfigField("String", "PIN_PRIMARY", "\"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\"")
        buildConfigField("String", "PIN_BACKUP", "\"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAE=\"")
        // SHA-256 (hex) of the release signing certificate. Blank = signature check skipped.
        buildConfigField("String", "EXPECTED_CERT_SHA256", "\"\"")
        // Base64 X.509 EC (P-256) public key that signs wipe commands. Blank = remote wipe disabled.
        buildConfigField("String", "WIPE_PUBLIC_KEY_B64", "\"\"")
        // Google Cloud project number for Play Integrity. 0 = Play Integrity skipped.
        buildConfigField("long", "CLOUD_PROJECT_NUMBER", "0L")
    }

    buildTypes {
        debug {
            // Debug builds (and emulators) show integrity signals but never downgrade the vault.
            buildConfigField("boolean", "ENFORCE_INTEGRITY", "false")
        }
        release {
            buildConfigField("boolean", "ENFORCE_INTEGRITY", "true")
            isMinifyEnabled = true
            isShrinkResources = true
            isDebuggable = false
            proguardFiles(getDefaultProguardFile("proguard-android-optimize.txt"), "proguard-rules.pro")
            // Configure signing with your protected upload key (see README).
        }
    }

    buildFeatures {
        buildConfig = true
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
    kotlinOptions {
        jvmTarget = "17"
    }
}

dependencies {
    implementation("androidx.core:core-ktx:1.13.1")
    implementation("androidx.appcompat:appcompat:1.7.0")
    implementation("com.google.android.material:material:1.12.0")
    implementation("androidx.recyclerview:recyclerview:1.3.2")
    implementation("androidx.lifecycle:lifecycle-runtime-ktx:2.8.4")

    // Phase I
    implementation("androidx.biometric:biometric:1.1.0")
    implementation("androidx.room:room-runtime:2.6.1")
    ksp("androidx.room:room-compiler:2.6.1")

    // Phase II
    implementation("com.squareup.okhttp3:okhttp:4.12.0")

    // Phase III
    implementation("com.google.android.play:integrity:1.4.0")
    implementation("androidx.work:work-runtime-ktx:2.9.1")
    implementation("org.jetbrains.kotlinx:kotlinx-coroutines-android:1.8.1")
    implementation("org.jetbrains.kotlinx:kotlinx-coroutines-play-services:1.8.1")

    testImplementation("junit:junit:4.13.2")
    androidTestImplementation("androidx.test.ext:junit:1.1.5")
    androidTestImplementation("androidx.test:runner:1.5.0")
}
