package org.simulationrift.poc.controller

import android.app.Service
import android.content.Intent
import android.os.Binder
import android.os.IBinder
import android.os.Process
import org.simulationrift.poc.ICore

class CoreService : Service() {
    private val binder = object : ICore.Stub() {
        override fun hello(): String =
            "controller uid=${Process.myUid()} caller uid=${Binder.getCallingUid()} caller=${packageManager.getNameForUid(Binder.getCallingUid())}"
    }

    override fun onBind(intent: Intent): IBinder = binder
}

class HiddenService : Service() {
    override fun onBind(intent: Intent): IBinder = Binder()
}
