plugins {
    id("com.android.application")
}

android {
    namespace = "org.retrobridge.guestdemo"
    compileSdk = 35

    defaultConfig {
        applicationId = "org.retrobridge.guestdemo"
        minSdk = 26
        targetSdk = 35
        versionCode = 1
        versionName = "1.0"
        ndk {
            abiFilters += "armeabi-v7a"
        }
    }

    sourceSets.getByName("main").jniLibs.srcDir(
        rootProject.layout.projectDirectory.dir("native/build/arm32-fixtures/demo-jni-libs"),
    )
}
