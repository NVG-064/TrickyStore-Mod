package io.github.a13e300.tricky_store

import android.annotation.SuppressLint
import android.os.IBinder
import android.os.Parcel
import android.os.ServiceManager
import android.security.keystore.IKeystoreService
import io.github.a13e300.tricky_store.binder.BinderInterceptor
import io.github.a13e300.tricky_store.keystore.CertHack
import kotlin.system.exitProcess

@SuppressLint("BlockedPrivateApi")
object KeystoreInterceptor : BinderInterceptor() {
    private val getTransaction =
        getTransactCode(IKeystoreService.Stub::class.java, "get")
    private lateinit var keystore: IBinder

    override fun onPreTransact(
        target: IBinder,
        code: Int,
        flags: Int,
        callingUid: Int,
        callingPid: Int,
        data: Parcel
    ): Result {
        if (code == getTransaction) {
            if (CertHack.canHack()) {
                Logger.d("intercept pre  $target uid=$callingUid pid=$callingPid dataSz=${data.dataSize()}")
                if (Config.needGenerate(callingUid))
                    kotlin.runCatching {
                        // TODO
                    }
                else if (Config.needHack(callingUid)) return Continue
                return Skip
            }
        }
        return Skip
    }

    override fun onPostTransact(
        target: IBinder,
        code: Int,
        flags: Int,
        callingUid: Int,
        callingPid: Int,
        data: Parcel,
        reply: Parcel?,
        resultCode: Int
    ): Result {
        if (target != keystore || code != getTransaction || reply == null) return Skip
        if (kotlin.runCatching { reply.readException() }.exceptionOrNull() != null) return Skip
        val p = Parcel.obtain()
        Logger.d("intercept post $target uid=$callingUid pid=$callingPid dataSz=${data.dataSize()} replySz=${reply.dataSize()}")
        try {
            data.setDataPosition(104)
            val alias = data.readString() ?: ""
            Logger.d("alias: ${alias}")
            var response = reply.createByteArray()
            if (alias.startsWith("USRCERT_")) {
                response = CertHack.hackCertificateChainUSR(response, alias.split("_")[1])
                Logger.i("hacked leaf of uid=$callingUid")
                p.writeNoException()
                p.writeByteArray(response)
                return OverrideReply(0, p)
            } else if(alias.startsWith("CACERT_")){
                response = CertHack.hackCertificateChainCA(response, alias.split("_")[1])
                Logger.i("hacked caList of uid=$callingUid")
                p.writeNoException()
                p.writeByteArray(response)
                return OverrideReply(0, p)
            } else p.recycle()
        } catch (t: Throwable) {
            Logger.e("failed to hack certificate chain of uid=$callingUid pid=$callingPid!", t)
            p.recycle()
        }
        return Skip
    }

    private var triedCount = 0
    private var injected = false

    fun tryRunKeystoreInterceptor(): Boolean {
        Logger.i("trying to register keystore interceptor ($triedCount) ...")
        val b = ServiceManager.getService("android.security.keystore") ?: return false
        val bd = getBinderBackdoor(b)
        if (bd == null) {
            // no binder hook, try inject
            if (triedCount >= 3) {
                Logger.e("tried injection but still has no backdoor, exit")
                exitProcess(1)
            }
            if (!injected) {
                Logger.i("trying to inject keystore ...")
                val p = Runtime.getRuntime().exec(
                    arrayOf(
                        "/system/bin/sh",
                        "-c",
                        "exec ./inject `pidof keystore` libtricky_store.so entry"
                    )
                )
                // logD(p.inputStream.readBytes().decodeToString())
                // logD(p.errorStream.readBytes().decodeToString())
                if (p.waitFor() != 0) {
                    Logger.e("failed to inject! daemon exit")
                    exitProcess(1)
                }
                injected = true
            }
            triedCount += 1
            return false
        }
        keystore = b
        Logger.i("register for Keystore $keystore!")
        registerBinderInterceptor(bd, b, this)
        keystore.linkToDeath(Killer, 0)
        return true
    }

    object Killer : IBinder.DeathRecipient {
        override fun binderDied() {
            Logger.d("keystore exit, daemon restart")
            exitProcess(0)
        }
    }
}