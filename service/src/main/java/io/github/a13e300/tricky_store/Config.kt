package io.github.a13e300.tricky_store

import android.content.pm.IPackageManager
import android.content.pm.PackageManager
import android.content.pm.PackageInfo
import android.content.Context
import android.os.FileObserver
import android.os.ServiceManager
import io.github.a13e300.tricky_store.keystore.CertHack
import java.io.File

object Config {
    private lateinit var context: Context

    fun initialize(context: Context) {
        this.context = context
    }

    private val hackPackages = mutableSetOf<String>()
    private val generatePackages = mutableSetOf<String>()

    private fun updateTargetPackages(f: File?) = runCatching {
        hackPackages.clear()
        generatePackages.clear()

        val lines = f?.readLines() ?: return@runCatching

        if (lines.any { it.trim() == "all" }) {
            val packageManager = context.packageManager
            val installedApps = packageManager.getInstalledPackages(0).map { pkgInfo: PackageInfo -> pkgInfo.packageName }
            hackPackages.addAll(installedApps)
        } else {
            lines.forEach { line ->
                if (line.isNotBlank() && !line.startsWith("#")) {
                    val n = line.trim()
                    if (n.endsWith("!"))
                        generatePackages.add(n.removeSuffix("!").trim())
                    else
                        hackPackages.add(n)
                }
            }
        }

        Logger.i("update hack packages: $hackPackages, generate packages=$generatePackages")
    }.onFailure {
        Logger.e("failed to update target files", it)
    }

    private fun updateKeyBox(f: File?) = runCatching {
        CertHack.readFromXml(f?.readText())
    }.onFailure {
        Logger.e("failed to update keybox", it)
    }

    private const val CONFIG_PATH = "/data/adb/tricky_store"
    private const val TARGET_FILE = "target.txt"
    private const val KEYBOX_FILE = "keybox.xml"
    private val root = File(CONFIG_PATH)

    object ConfigObserver : FileObserver(root, CLOSE_WRITE or DELETE or MOVED_FROM or MOVED_TO) {
        override fun onEvent(event: Int, path: String?) {
            path ?: return
            val f = when (event) {
                CLOSE_WRITE, MOVED_TO -> File(root, path)
                DELETE, MOVED_FROM -> null
                else -> return
            }
            when (path) {
                TARGET_FILE -> updateTargetPackages(f)
                KEYBOX_FILE -> updateKeyBox(f)
            }
        }
    }

    fun initialize() {
        root.mkdirs()
        val scope = File(root, TARGET_FILE)
        if (scope.exists()) {
            updateTargetPackages(scope)
        } else {
            Logger.e("target.txt file not found, please put it to $scope !")
        }
        val keybox = File(root, KEYBOX_FILE)
        if (!keybox.exists()) {
            Logger.e("keybox file not found, please put it to $keybox !")
        } else {
            updateKeyBox(keybox)
        }
        ConfigObserver.startWatching()
    }

    private var iPm: IPackageManager? = null

    fun getPm(): IPackageManager? {
        if (iPm == null) {
            iPm = IPackageManager.Stub.asInterface(ServiceManager.getService("package"))
        }
        return iPm
    }

    fun needHack(callingUid: Int) = kotlin.runCatching {
        if (hackPackages.isEmpty()) return false
        val ps = getPm()?.getPackagesForUid(callingUid)
        ps?.any { it in hackPackages }
    }.onFailure { Logger.e("failed to get packages", it) }.getOrNull() ?: false

    fun needGenerate(callingUid: Int) = kotlin.runCatching {
        if (generatePackages.isEmpty()) return false
        val ps = getPm()?.getPackagesForUid(callingUid)
        ps?.any { it in generatePackages }
    }.onFailure { Logger.e("failed to get packages", it) }.getOrNull() ?: false
}
