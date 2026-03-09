package com.applock.password.fingerprint.pattern.media.vault.gss.core.base.permissions

import android.Manifest
import android.app.Activity
import android.os.Build
import android.os.Bundle
import android.view.View
import androidx.activity.result.contract.ActivityResultContracts
import com.applock.password.fingerprint.pattern.media.vault.gss.core.ads.AdKeys.NOT_SHOW_OPEN_AD
import com.applock.password.fingerprint.pattern.media.vault.gss.core.base.permissions.components.OnPermissionResult
import com.applock.password.fingerprint.pattern.media.vault.gss.core.base.permissions.components.Permission
import com.applock.password.fingerprint.pattern.media.vault.gss.core.base.permissions.components.PermissionData.askForDrawOverAppPermission
import com.applock.password.fingerprint.pattern.media.vault.gss.core.base.permissions.components.PermissionData.askForManagePermission
import com.applock.password.fingerprint.pattern.media.vault.gss.core.base.permissions.components.PermissionData.askForNotificationAccessPermission
import com.applock.password.fingerprint.pattern.media.vault.gss.core.base.permissions.components.PermissionData.askForUsageAccessPermissions
import com.applock.password.fingerprint.pattern.media.vault.gss.core.base.permissions.components.PermissionData.askForXiaomiPermission
import com.applock.password.fingerprint.pattern.media.vault.gss.core.base.permissions.components.PermissionData.hasDrawOverAppsPermission
import com.applock.password.fingerprint.pattern.media.vault.gss.core.base.permissions.components.PermissionData.hasManagePermissions
import com.applock.password.fingerprint.pattern.media.vault.gss.core.base.permissions.components.PermissionData.hasUsageAccessPermissions
import com.applock.password.fingerprint.pattern.media.vault.gss.core.base.permissions.components.PermissionData.isNotificationListenerEnabled
import com.applock.password.fingerprint.pattern.media.vault.gss.core.base.permissions.components.PermissionData.isShowOverlayFromBackgroundPermissionEnable
import com.applock.password.fingerprint.pattern.media.vault.gss.core.base.permissions.components.PermissionType
import com.applock.password.fingerprint.pattern.media.vault.gss.core.utils.goForPermission
import com.google.android.material.bottomsheet.BottomSheetDialogFragment
import dagger.hilt.android.AndroidEntryPoint

@AndroidEntryPoint
abstract class BasePermissionFragment : BottomSheetDialogFragment() {

    private var permissionType: PermissionType? = null
    private var permissionAsked = false
    private var listener: OnPermissionResult? = null
    private var mContext: Activity? = null

    /**
     * Launcher for runtime permissions only
     */
    private val permissionLauncher =
        registerForActivityResult(ActivityResultContracts.RequestMultiplePermissions()) { results ->
            val allGranted = results.values.all { it }
            val permanentlyDenied = results.entries.any { (perm, granted) ->
                !granted && !shouldShowRequestPermissionRationale(perm)
            }
            when {
                allGranted -> listener?.onAllowed()
                permanentlyDenied -> listener?.onPermanentlyDenied()
                else -> listener?.onNotAllowed()
            }
        }

    override fun onViewCreated(view: View, savedInstanceState: Bundle?) {
        super.onViewCreated(view, savedInstanceState)
    }

    /**
     * Entry point: Ask for permission by type
     */
    fun askForPermission(context: Activity?, type: PermissionType, callback: OnPermissionResult) {
        permissionType = type
        listener = callback
        mContext = context

        when (type) {
            PermissionType.USAGE -> handleUsageAccessPermission()
            PermissionType.OVERLAY -> handleOverlayPermission()
            PermissionType.NOTIFICATION -> handleNotificationPermission()
            PermissionType.ALL_FILES -> goForFilesPermission()
            PermissionType.XIAOMI -> requestXiaomiPermission()
            PermissionType.NOTIFICATION_ACCESS -> goForNotificationAccess()
        }
    }

    // region --- Permission Handlers ---

    // Request Xiaomi-specific permission
    fun requestXiaomiPermission() {
        mContext?.let {
            if (it.isShowOverlayFromBackgroundPermissionEnable()) {
                listener?.onAllowed()
            } else {
                permissionAsked = true
                goForPermission = true
                NOT_SHOW_OPEN_AD = true
                it.askForXiaomiPermission()
            }
        }
    }

    private fun handleUsageAccessPermission() {
        mContext?.let {
            if (it.hasUsageAccessPermissions()) {
                listener?.onAllowed()
            } else {
                permissionAsked = true
                goForPermission = true
                NOT_SHOW_OPEN_AD = true
                it.askForUsageAccessPermissions()
            }
        }
    }

    private fun handleOverlayPermission() {
        mContext?.let {
            if (it.hasDrawOverAppsPermission()) {
                listener?.onAllowed()
            } else {
                permissionAsked = true
                goForPermission = true
                NOT_SHOW_OPEN_AD = true
                it.askForDrawOverAppPermission()
            }
        }
    }

    private fun handleNotificationPermission() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            requestRuntimePermissions(arrayOf(Manifest.permission.POST_NOTIFICATIONS))
        } else {
            listener?.onAllowed()
        }
    }

    // endregion

    private fun requestRuntimePermissions(permissions: Array<String>) {
        permissionLauncher.launch(permissions)
    }

    private fun goForFilesPermission() {
        mContext?.let {
            permissionAsked = true
            goForPermission = true
            NOT_SHOW_OPEN_AD = true
            askForManagePermission(it) { type ->
                if (type == Permission.SIMPLE) {
                    permissionLauncher.launch(arrayOf(Manifest.permission.WRITE_EXTERNAL_STORAGE))
                }
            }
        }
    }

    private fun goForNotificationAccess() {
        mContext?.let {
            permissionAsked = true
            goForPermission = true
            NOT_SHOW_OPEN_AD = true
            it.askForNotificationAccessPermission()
        }
    }

    override fun onResume() {
        super.onResume()
        if (!permissionAsked) return
        permissionAsked = false
        when (permissionType) {
            PermissionType.USAGE ->
                if (mContext?.hasUsageAccessPermissions()
                        ?: false
                ) listener?.onAllowed() else listener?.onNotAllowed()

            PermissionType.OVERLAY ->
                if (mContext?.hasDrawOverAppsPermission()
                        ?: false
                ) listener?.onAllowed() else listener?.onNotAllowed()

            PermissionType.ALL_FILES ->
                if (mContext?.hasManagePermissions()
                        ?: false
                ) listener?.onAllowed() else listener?.onNotAllowed()

            PermissionType.XIAOMI ->
                if (mContext?.isShowOverlayFromBackgroundPermissionEnable()
                        ?: false
                ) listener?.onAllowed() else listener?.onNotAllowed()

            PermissionType.NOTIFICATION_ACCESS ->
                if (mContext?.isNotificationListenerEnabled()
                        ?: false
                ) listener?.onAllowed() else listener?.onNotAllowed()

            else -> Unit
        }
    }

    override fun onDestroy() {
        super.onDestroy()
        permissionType = null
        listener = null
    }

}
