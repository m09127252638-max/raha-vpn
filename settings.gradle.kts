pluginManagement {
    repositories {
        google()
        mavenCentral()
        gradlePluginPortal()
    }
}
dependencyResolutionManagement {
    repositoriesMode.set(RepositoriesMode.FAIL_ON_PROJECT_REPOS)
    repositories {
        google()
        mavenCentral()
        maven { url = uri("https://jitpack.io") }
        exclusiveContent {
            forRepository {
                maven { url = uri("https://raw.githubusercontent.com/guardianproject/gpmaven/master") }
            }
            filter { includeModule("info.guardianproject", "tor-android") }
        }
    }
}
rootProject.name = "H.MAGHSODI"
include(":app")
