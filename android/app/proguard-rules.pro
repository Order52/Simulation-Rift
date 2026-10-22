# JNA looks up its own classes, Structure fields and Library methods by
# reflection and from native code.
-keep class com.sun.jna.** { *; }
-keepclassmembers class * extends com.sun.jna.** { public *; }
-dontwarn java.awt.**

# UniFFI's generated bindings: Structure subclasses (field order matters),
# the native Library interfaces and callback interfaces are used through JNA.
-keep class org.simulationrift.core.** { *; }
-keep class org.simulationrift.worker.** { *; }

# Extra isolation's helper: Shizuku constructs it by reflection, by name.
-keep class org.simulationrift.app.HardeningService { <init>(...); }
