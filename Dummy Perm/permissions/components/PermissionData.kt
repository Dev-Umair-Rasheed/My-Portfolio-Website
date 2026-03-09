package com.applock.password.fingerprint.pattern.media.vault.gss.core.base.permissions.components

import android.Manifest
import android.annotation.SuppressLint
import android.app.Activity
import android.app.AppOpsManager
import android.app.Dialog
import android.content.Context
import android.content.Context.APP_OPS_SERVICE
import android.content.Intent
import android.content.pm.PackageManager
import android.graphics.Color
import android.net.Uri
import android.os.Binder
import android.os.Build
import android.os.Environment
import android.provider.Settings
import android.view.ViewGroup
import android.widget.ImageView
import android.widget.TextView
import android.widget.Toast
import androidx.core.app.ActivityCompat
import androidx.core.content.ContextCompat
import androidx.core.graphics.drawable.toDrawable
import androidx.core.net.toUri
import com.applock.password.fingerprint.pattern.media.vault.gss.BuildConfig
import com.applock.password.fingerprint.pattern.media.vault.gss.R
import java.lang.reflect.Method

object PermissionData {

    // ✅ Basic Permission Checkers

    @SuppressLint("DiscouragedPrivateApi")
    fun Context.isShowOnLockScreenPermissionEnable(): Boolean {
        return try {
            val manager = this.getSystemService(APP_OPS_SERVICE) as AppOpsManager
            val method: Method = AppOpsManager::class.java.getDeclaredMethod(
                "checkOpNoThrow",
                Int::class.javaPrimitiveType,
                Int::class.javaPrimitiveType,
                String::class.java
            )
            val result =
                method.invoke(manager, 10020, Binder.getCallingUid(), this.packageName) as Int
            AppOpsManager.MODE_ALLOWED == result
        } catch (e: Exception) {
            false
        }
    }

    @SuppressLint("DiscouragedPrivateApi")
    fun Context.isShowOverlayFromBackgroundPermissionEnable(): Boolean {
        return try {
            val manager = this.getSystemService(APP_OPS_SERVICE) as AppOpsManager
            val method: Method = AppOpsManager::class.java.getDeclaredMethod(
                "checkOpNoThrow",
                Int::class.javaPrimitiveType,
                Int::class.javaPrimitiveType,
                String::class.java
            )
            // OP_BACKGROUND_START_ACTIVITY operation code for Xiaomi
            val result =
                method.invoke(manager, 10021, Binder.getCallingUid(), this.packageName) as Int
            AppOpsManager.MODE_ALLOWED == result
        } catch (e: Exception) {
            false
        }
    }

    fun Context.hasManagePermissions(): Boolean {
        return if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
            Environment.isExternalStorageManager()
        } else {
            ContextCompat.checkSelfPermission(
                this, Manifest.permission.WRITE_EXTERNAL_STORAGE
            ) == PackageManager.PERMISSION_GRANTED
        }
    }

    fun hasCameraPermission(context: Context): Boolean {
        return ActivityCompat.checkSelfPermission(
            context, Manifest.permission.CAMERA
        ) == PackageManager.PERMISSION_GRANTED
    }

    private fun isXiaomiDevice(): Boolean {
        return "xiaomi".equals(Build.MANUFACTURER, ignoreCase = true)
    }

    fun Context.hasAllPermissions(): Boolean {
        return if (isXiaomiDevice()) {
            hasUsageAccessPermissions() && hasDrawOverAppsPermission() && isShowOverlayFromBackgroundPermissionEnable() && checkNotificationPermissionGrant(
                this
            )
        } else {
            hasUsageAccessPermissions() && hasDrawOverAppsPermission() && checkNotificationPermissionGrant(
                this
            )
        }
    }

    fun Context.hasDrawOverAppsPermission(): Boolean {
        return Settings.canDrawOverlays(this)
    }

    fun Context.hasUsageAccessPermissions(): Boolean {
        return try {
            val appOps = getSystemService(APP_OPS_SERVICE) as AppOpsManager
            val appInfo = packageManager.getApplicationInfo(packageName, 0)
            val mode = appOps.checkOpNoThrow(
                AppOpsManager.OPSTR_GET_USAGE_STATS,
                appInfo.uid,
                appInfo.packageName
            )
            mode == AppOpsManager.MODE_ALLOWED
        } catch (_: Exception) {
            false
        }
    }

    fun checkNotificationPermissionGrant(context: Context): Boolean {
        return if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            ContextCompat.checkSelfPermission(
                context, Manifest.permission.POST_NOTIFICATIONS
            ) == PackageManager.PERMISSION_GRANTED
        } else true
    }

    fun Context.isNotificationListenerEnabled(): Boolean {
        val packageName: String = packageName
        val flat =
            Settings.Secure.getString(contentResolver, "enabled_notification_listeners")
        return flat?.contains(packageName) == true
    }

    // ✅ Permission Request Launchers

    fun Context.askForDrawOverAppPermission() {
        val intent = Intent(
            Settings.ACTION_MANAGE_OVERLAY_PERMISSION,
            "package:$packageName".toUri()
        )
        launchIntentSafely(intent, "Overlay permission activity not found")
    }

    fun Context.askForUsageAccessPermissions() {
        val intent = Intent(Settings.ACTION_USAGE_ACCESS_SETTINGS).apply {
            flags = Intent.FLAG_ACTIVITY_NEW_TASK
        }
        launchIntentSafely(intent, "Usage access settings activity not found")
    }

    fun Context.askForNotificationAccessPermission() {
        val intent = Intent(Settings.ACTION_NOTIFICATION_LISTENER_SETTINGS).apply {
            flags = Intent.FLAG_ACTIVITY_NEW_TASK
        }
        launchIntentSafely(intent, "Notification access settings activity not found")
    }

    fun Context.askForXiaomiPermission() {
        val intent = Intent("miui.intent.action.APP_PERM_EDITOR")
        intent.setClassName(
            "com.miui.securitycenter",
            "com.miui.permcenter.permissions.PermissionsEditorActivity"
        )
        intent.putExtra("extra_pkgname", this.packageName)
        launchIntentSafely(intent, "Start from background activity not found")
    }

    fun askForManagePermission(context: Activity, callback: (Permission) -> Unit) {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
            val intent = Intent(Settings.ACTION_MANAGE_APP_ALL_FILES_ACCESS_PERMISSION)
                .apply {
                    data = "package:${context.packageName}".toUri()
                }
            callback(Permission.PROTECTED)
            context.launchIntentSafely(
                intent,
                "Unable to open file access settings on your device."
            )
        } else {
            callback(Permission.SIMPLE)
        }
    }

    private fun Context.launchIntentSafely(intent: Intent, errorMsg: String) {
        try {
            if (intent.resolveActivity(packageManager) != null) startActivity(intent)
            else Toast.makeText(this, errorMsg, Toast.LENGTH_SHORT).show()
        } catch (_: Exception) {
            Toast.makeText(this, errorMsg, Toast.LENGTH_SHORT).show()
        }
    }

    private fun goToAppSettings(context: Context) {
        val intent = Intent(Settings.ACTION_APPLICATION_DETAILS_SETTINGS).apply {
            data = "package:${context.packageName}".toUri()
        }
        context.launchIntentSafely(intent, "Settings screen not found")
    }

    fun showNotificationPermissionDialog(
        context: Activity,
        showPermissionLauncher: (Intent) -> Unit
    ) {
        val dialog = Dialog(context)
        dialog.setCancelable(false)
        dialog.setContentView(R.layout.dialog_no_notification_permission)
        dialog.window?.setBackgroundDrawable(Color.TRANSPARENT.toDrawable())
        dialog.window?.setLayout(
            ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT
        )
        val allowBtn: TextView = dialog.findViewById(R.id.btn_allow)
        val close: ImageView = dialog.findViewById(R.id.img_cross)

        allowBtn.setOnClickListener {
            if (!context.isFinishing && !context.isDestroyed && dialog.isShowing) {
                dialog.dismiss()
            }
            Intent().apply {
                action = Settings.ACTION_APPLICATION_DETAILS_SETTINGS
                data = Uri.fromParts(
                    "package", BuildConfig.APPLICATION_ID, null
                )
                flags = Intent.FLAG_ACTIVITY_CLEAR_TASK
            }.also {
                if (it.resolveActivity(context.packageManager) != null) {
                    showPermissionLauncher(it)
                } else {
                    Toast.makeText(context, "Settings screen not found!", Toast.LENGTH_SHORT).show()
                }
            }
        }
        close.setOnClickListener {
            if (!context.isFinishing && !context.isDestroyed && dialog.isShowing) {
                dialog.cancel()
            }
        }

        if (!context.isFinishing && !context.isDestroyed && !dialog.isShowing) {
            dialog.show()
        }

    }

}