package com.bioauth.phone_auth_native

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.app.Service
import android.content.Intent
import android.content.pm.ServiceInfo
import android.os.Build
import android.os.IBinder
import androidx.core.app.NotificationCompat
import androidx.core.app.ServiceCompat

class BackgroundSessionService : Service() {
    override fun onCreate() {
        super.onCreate()
        running = true
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            getSystemService(NotificationManager::class.java).createNotificationChannel(
                NotificationChannel(
                    CHANNEL_ID,
                    "Conexões com computadores",
                    NotificationManager.IMPORTANCE_LOW,
                ).apply {
                    description = "Mantém computadores pareados disponíveis para autenticação"
                    setShowBadge(false)
                },
            )
        }
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        ServiceCompat.startForeground(
            this,
            NOTIFICATION_ID,
            notification(),
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
                ServiceInfo.FOREGROUND_SERVICE_TYPE_CONNECTED_DEVICE
            } else {
                0
            },
        )
        // Not sticky, because nothing in this process would come back with
        // it. The sessions are Dart, running in the app's Flutter engine;
        // there is no headless entrypoint. Restarted after the process was
        // killed, this service would put "PhoneAuth está disponível" back on
        // screen over a process with no engine, no runner and no connection to
        // any desktop -- a notification promising exactly the thing that had
        // just stopped being true. The app coming back is what brings the
        // sessions back, and it starts this again itself.
        return START_NOT_STICKY
    }

    override fun onBind(intent: Intent?): IBinder? = null

    override fun onDestroy() {
        running = false
        super.onDestroy()
    }

    private fun notification(): Notification {
        val contentIntent = packageManager.getLaunchIntentForPackage(packageName)?.let {
            PendingIntent.getActivity(
                this,
                0,
                it,
                PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE,
            )
        }
        val icon = applicationInfo.icon.takeIf { it != 0 }
            ?: android.R.drawable.stat_sys_data_bluetooth
        return NotificationCompat.Builder(this, CHANNEL_ID)
            .setSmallIcon(icon)
            .setContentTitle("PhoneAuth está disponível")
            .setContentText("Aguardando solicitações de computadores pareados")
            .setContentIntent(contentIntent)
            .setOngoing(true)
            .setCategory(NotificationCompat.CATEGORY_SERVICE)
            .setPriority(NotificationCompat.PRIORITY_LOW)
            .setOnlyAlertOnce(true)
            .build()
    }

    companion object {
        internal const val CHANNEL_ID = "bioauth_background_sessions"
        private const val NOTIFICATION_ID = 0xB10A
        @Volatile
        var running: Boolean = false
            private set
    }
}
