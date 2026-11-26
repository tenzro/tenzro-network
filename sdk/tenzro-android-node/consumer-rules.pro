# The node's native library calls these through JNI, by name and signature, so shrinking keeps them as they are.
-keep class com.tenzro.keystore.AndroidKeystoreKey { *; }
-keep class com.tenzro.keystore.AndroidKeystoreKey$Companion { *; }
-keep enum com.tenzro.keystore.SecurityLevel { *; }
-keep class com.tenzro.keystore.KeystoreBridge { native <methods>; *; }
