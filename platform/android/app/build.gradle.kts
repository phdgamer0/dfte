// Copyright (c) 2026 Yazdan Samari. All rights reserved except as granted by LICENSE.
// SPDX-License-Identifier: PolyForm-Shield-1.0.0

plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.plugin.compose")
}

// The Rust core (crates/platform-ffi) is cross-built and its Kotlin bindings
// generated before every build, so Gradle stays the single entry point
// (`./gradlew assembleDebug`). Rust is always built in release: a debug core
// is far too slow to judge transfer speed on a phone.
val repoRoot: File = rootDir.resolve("../..").canonicalFile
val rustTarget = "aarch64-linux-android"
val rustAbi = "arm64-v8a"
val minApi = 26
val ndkVer = "30.0.16248370"
// `dist-android` profile (Cargo.toml): whole-program LTO, no build paths; the APK
// packaging strips its symbols.
val rustLib = repoRoot.resolve("target/$rustTarget/dist-android/libplatform_ffi.so")
// Plain directories (AGP 9 refuses Provider paths in source sets); preBuild
// depends on the tasks that fill them.
val jniOut: File = layout.buildDirectory.dir("rust/jniLibs").get().asFile
val bindingsOut: File = layout.buildDirectory.dir("generated/uniffi").get().asFile

android {
    namespace = "dev.dfte.app"
    compileSdk = 37
    ndkVersion = ndkVer

    defaultConfig {
        applicationId = "dev.dfte.app"
        minSdk = minApi
        targetSdk = 36
        versionCode = 1
        versionName = "0.1.0"
        ndk { abiFilters += rustAbi }
    }

    buildTypes {
        release {
            isMinifyEnabled = true
            isShrinkResources = true
            proguardFiles(getDefaultProguardFile("proguard-android-optimize.txt"), "proguard-rules.pro")
            // Sideload builds only until release signing exists (manual §47).
            signingConfig = signingConfigs.getByName("debug")
        }
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }

    buildFeatures { compose = true }

    sourceSets.getByName("main") {
        jniLibs.directories.add(jniOut.path)
        kotlin.directories.add(bindingsOut.path)
    }

    packaging { jniLibs { useLegacyPackaging = false } }
}

val ndkBin = provider {
    val sdk = rootDir.resolve("local.properties").readLines().first { it.startsWith("sdk.dir=") }.removePrefix("sdk.dir=")
    "$sdk/ndk/$ndkVer/toolchains/llvm/prebuilt/linux-x86_64/bin"
}

val cargoBuildAndroid = tasks.register<Exec>("cargoBuildAndroid") {
    description = "Cross-builds the Rust core for $rustTarget."
    workingDir = repoRoot
    commandLine("cargo", "build", "--profile", "dist-android", "-p", "platform-ffi", "--target", rustTarget)
    doFirst {
        val bin = ndkBin.get()
        val env = rustTarget.uppercase().replace('-', '_')
        val clang = "$bin/$rustTarget$minApi-clang"
        environment("CARGO_TARGET_${env}_LINKER", clang)
        environment("CC_${rustTarget.replace('-', '_')}", clang)
        environment("AR_${rustTarget.replace('-', '_')}", "$bin/llvm-ar")
        // Keep this machine's paths (and user name) out of the library.
        val home = System.getProperty("user.home")
        val cargoHome = System.getenv("CARGO_HOME") ?: "$home/.cargo"
        val rustupHome = System.getenv("RUSTUP_HOME") ?: "$home/.rustup"
        environment("RUSTFLAGS", listOf("--remap-path-prefix=${repoRoot.path}=dfte", "--remap-path-prefix=$cargoHome=cargo", "--remap-path-prefix=$rustupHome=rustup", "--remap-path-prefix=$home=~").joinToString(" "))
    }
    // Cargo does its own up-to-date checks.
    outputs.upToDateWhen { false }
}

val copyRustLib = tasks.register<Copy>("copyRustLib") {
    dependsOn(cargoBuildAndroid)
    from(rustLib)
    into(jniOut.resolve(rustAbi))
}

val uniffiBindings = tasks.register<Exec>("uniffiBindings") {
    description = "Generates the Kotlin bindings from the built library."
    dependsOn(cargoBuildAndroid)
    workingDir = repoRoot
    val out = bindingsOut
    // A host tool that only reads the library's metadata: a dev build is enough and
    // skips compiling the whole crate graph again with LTO.
    commandLine("cargo", "run", "-q", "-p", "platform-ffi", "--features", "bindgen", "--bin", "uniffi-bindgen", "--", "generate", "--library", rustLib.path, "--language", "kotlin", "--out-dir", out.path, "--no-format")
    doFirst { out.deleteRecursively() }
    outputs.dir(out)
    outputs.upToDateWhen { false }
}

tasks.named("preBuild") { dependsOn(copyRustLib, uniffiBindings) }

dependencies {
    implementation(platform("androidx.compose:compose-bom:2026.09.00"))
    implementation("androidx.compose.ui:ui")
    implementation("androidx.compose.foundation:foundation")
    implementation("androidx.compose.material3:material3")
    implementation("androidx.activity:activity-compose:1.13.0")
    implementation("androidx.core:core-ktx:1.19.1")
    implementation("androidx.lifecycle:lifecycle-runtime-compose:2.11.0")
    implementation("org.jetbrains.kotlinx:kotlinx-coroutines-android:1.11.0")
    implementation("net.java.dev.jna:jna:5.19.1@aar")
}
