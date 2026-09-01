import java.util.Properties

plugins {
    id("com.android.application")
    // The Flutter Gradle Plugin must be applied after the Android and Kotlin Gradle plugins.
    id("dev.flutter.flutter-gradle-plugin")
}

// Release signing material, supplied by the distribution pipeline and never
// committed. Absent on a developer checkout and in any fork, where the release
// build stays unsigned rather than falling back to a key everyone has.
val keystoreProperties = Properties().apply {
    val file = rootProject.file("key.properties")
    if (file.exists()) file.inputStream().use { load(it) }
}

android {
    namespace = "com.bioauth.phone_auth"
    compileSdk = flutter.compileSdkVersion
    ndkVersion = flutter.ndkVersion

    buildFeatures {
        resValues = true
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }

    defaultConfig {
        applicationId = "com.bioauth.phone_auth"
        // You can update the following values to match your application needs.
        // For more information, see: https://flutter.dev/to/review-gradle-config.
        minSdk = flutter.minSdkVersion
        targetSdk = flutter.targetSdkVersion
        // Uses the version code from pubspec.yaml. When using split APKs, 1000 * ABI_VERSION
        // is added automatically by Flutter. (https://developer.android.com/studio/build/configure-apk-splits#configure-APK-versions)
        // You can force using the value of versionCode by specifying the `-P force-version-code-ignoring-abi=true`
        // flag during build.
        // `pubspec.yaml`'s build number, unless a build says otherwise with
        // `-PbioauthVersionCode=<n>`.
        //
        // Android decides whether an APK may replace the one already
        // installed by comparing these, and the number sat at 7 through every
        // build this project ever produced -- local and CI alike. Replacing an
        // app with something carrying the same version is not an upgrade, and
        // the package installer says so as "App not installed", which reads
        // like a broken file rather than a number nobody moved. Uninstalling
        // first is not a workaround here: it takes the Keystore keys with it,
        // and those are the passkeys and the vault.
        //
        // The override exists so a build meant for a phone that already has
        // one can outrank it without editing a tracked file first.
        versionCode = (project.findProperty("bioauthVersionCode") as String?)?.toIntOrNull()
            ?: flutter.versionCode
        versionName = flutter.versionName
    }

    flavorDimensions += "environment"
    productFlavors {
        create("dev") {
            dimension = "environment"
            applicationIdSuffix = ".dev"
            versionNameSuffix = "-dev"
            resValue("string", "app_name", "PhoneAuth Dev")
        }
        create("staging") {
            dimension = "environment"
            applicationIdSuffix = ".staging"
            versionNameSuffix = "-staging"
            resValue("string", "app_name", "PhoneAuth Staging")
        }
        create("prod") {
            dimension = "environment"
            resValue("string", "app_name", "PhoneAuth")
        }
    }

    signingConfigs {
        if (keystoreProperties.containsKey("storeFile")) {
            create("release") {
                storeFile = rootProject.file(keystoreProperties["storeFile"] as String)
                storePassword = keystoreProperties["storePassword"] as String
                keyAlias = keystoreProperties["keyAlias"] as String
                keyPassword = keystoreProperties["keyPassword"] as String
            }
        }
    }

    buildTypes {
        release {
            // The project key when one was supplied, the debug key when not.
            // An APK with no signature at all is a file Android refuses to
            // install, and a build nobody can install is not a safer build,
            // it is an absent one. What the debug key costs is stated where a
            // person can act on it: an app installed under it cannot be
            // updated by a build signed with a different key, because that is
            // exactly the check Android makes on every update.
            signingConfig = signingConfigs.findByName("release")
                ?: signingConfigs.getByName("debug")
        }
    }
}

kotlin {
    compilerOptions {
        jvmTarget = org.jetbrains.kotlin.gradle.dsl.JvmTarget.JVM_17
    }
}

flutter {
    source = "../.."
}
