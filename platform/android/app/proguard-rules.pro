# uniffi bindings reach Rust through JNA, which finds classes and fields by name.
-keep class com.sun.jna.** { *; }
-keep class * implements com.sun.jna.** { *; }
-keep class uniffi.platform_ffi.** { *; }
-dontwarn java.awt.**
