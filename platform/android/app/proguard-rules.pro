# Copyright (c) 2026 Yazdan Samari. All rights reserved except as granted by LICENSE.
# SPDX-License-Identifier: PolyForm-Shield-1.0.0

# uniffi bindings reach Rust through JNA, which finds classes and fields by name.
-keep class com.sun.jna.** { *; }
-keep class * implements com.sun.jna.** { *; }
-keep class uniffi.platform_ffi.** { *; }
-dontwarn java.awt.**

# Make the app's own code harder to read back: everything R8 may rename goes into
# one flat package, and stack traces name no source files (there's no crash
# reporting to need them). The JNA/uniffi classes above keep their names.
-repackageclasses ''
-allowaccessmodification
-renamesourcefileattribute ''
-keepattributes !SourceFile
