package com.applock.password.fingerprint.pattern.media.vault.gss.presentation.ui.fragments.bottom_sheets

import android.Manifest
import android.app.Dialog
import android.content.Intent
import android.net.Uri
import android.os.Build
import android.os.Bundle
import android.provider.Settings
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.widget.Toast
import androidx.activity.result.contract.ActivityResultContracts
import androidx.core.app.ActivityCompat
import com.applock.password.fingerprint.pattern.media.vault.gss.BuildConfig
import com.applock.password.fingerprint.pattern.media.vault.gss.core.ads.AdKeys.NOT_SHOW_OPEN_AD
import com.applock.password.fingerprint.pattern.media.vault.gss.core.base.permissions.BasePermissionFragment
import com.applock.password.fingerprint.pattern.media.vault.gss.core.base.permissions.components.OnPermissionResult
import com.applock.password.fingerprint.pattern.media.vault.gss.core.base.permissions.components.PermissionData.checkNotificationPermissionGrant
import com.applock.password.fingerprint.pattern.media.vault.gss.core.base.permissions.components.PermissionData.hasAllPermissions
import com.applock.password.fingerprint.pattern.media.vault.gss.core.base.permissions.components.PermissionData.hasDrawOverAppsPermission
import com.applock.password.fingerprint.pattern.media.vault.gss.core.base.permissions.components.PermissionData.hasUsageAccessPermissions
import com.applock.password.fingerprint.pattern.media.vault.gss.core.base.permissions.components.PermissionData.isShowOverlayFromBackgroundPermissionEnable
import com.applock.password.fingerprint.pattern.media.vault.gss.core.base.permissions.components.PermissionType
import com.applock.password.fingerprint.pattern.media.vault.gss.core.utils.goForPermission
import com.applock.password.fingerprint.pattern.media.vault.gss.core.utils.makeGone
import com.applock.password.fingerprint.pattern.media.vault.gss.core.utils.makeVisible
import com.applock.password.fingerprint.pattern.media.vault.gss.core.utils.setLog
import com.applock.password.fingerprint.pattern.media.vault.gss.core.utils.setSafeOnClickListener
import com.applock.password.fingerprint.pattern.media.vault.gss.databinding.FragmentPermissionBottomSheetBinding
import com.applock.password.fingerprint.pattern.media.vault.gss.presentation.ui.fragments.bottom_sheets.components.PermissionBSDismissListener
import com.google.android.material.bottomsheet.BottomSheetDialog

class PermissionBottomSheet : BasePermissionFragment() {

    private var _binding: FragmentPermissionBottomSheetBinding? = null
    private val binding get() = _binding!!

    private val permissionType: PermissionType by lazy {
        val name = requireArguments().getString(ARG_PERMISSION_TYPE)
        PermissionType.valueOf(name!!)
    }

    private val notificationPermissionLauncher = registerForActivityResult(
        ActivityResultContracts.RequestPermission()
    ) {
        if (checkNotificationPermissionGrant(requireContext())) {
            setLog("App_Locker", "Granted Notification Permission: notificationPermissionLauncher!")
            binding.switchNotifications.isChecked = true
            binding.switchNotifications.isEnabled = false
            if (requireContext().hasAllPermissions()) {
                setLog(
                    "App_Locker",
                    "Granted all permissions: Notification notificationPermissionLauncher!"
                )
                (parentFragment as? PermissionBSDismissListener)?.onOverlayPermissionsGranted()
                (activity as? PermissionBSDismissListener)?.onOverlayPermissionsGranted()
                dismiss()
            }
        }
    }

    private var nPermissionLauncher =
        registerForActivityResult(ActivityResultContracts.StartActivityForResult()) {
            if (checkNotificationPermissionGrant(requireContext())) {
                setLog("App_Locker", "Granted Notification Permission: nPermissionLauncher!")
                binding.switchNotifications.isChecked = true
                binding.switchNotifications.isEnabled = false
                if (requireContext().hasAllPermissions()) {
                    setLog(
                        "App_Locker",
                        "Granted all permissions: Notification nPermissionLauncher!"
                    )
                    (parentFragment as? PermissionBSDismissListener)?.onOverlayPermissionsGranted()
                    (activity as? PermissionBSDismissListener)?.onOverlayPermissionsGranted()
                    dismiss()
                }
            }
        }

    companion object {
        private const val ARG_PERMISSION_TYPE = "arg_permission_type"

        fun newInstance(permissionType: PermissionType): PermissionBottomSheet {
            val fragment = PermissionBottomSheet()
            val bundle = Bundle()
            bundle.putString(ARG_PERMISSION_TYPE, permissionType.name)
            fragment.arguments = bundle
            return fragment
        }
    }

    override fun onCreateDialog(savedInstanceState: Bundle?): Dialog {
        val dialog = super.onCreateDialog(savedInstanceState)

        // Make Background Transparent so Only Layout Shows
        dialog.setOnShowListener { dialog ->
            val bottomSheetDialog = dialog as BottomSheetDialog
            val bottomSheet =
                bottomSheetDialog.findViewById<View>(com.google.android.material.R.id.design_bottom_sheet)
            bottomSheet?.setBackgroundResource(android.R.color.transparent)
        }

        return dialog
    }

    override fun onCreateView(
        inflater: LayoutInflater,
        container: ViewGroup?,
        savedInstanceState: Bundle?
    ): View {
        _binding = FragmentPermissionBottomSheetBinding.inflate(inflater, container, false)
        return binding.root
    }

    override fun onViewCreated(view: View, savedInstanceState: Bundle?) {
        super.onViewCreated(view, savedInstanceState)

        with(binding) {
            setupUIVisibility()

            ivCross.setOnClickListener {
                dismiss()
            }

            switchOverApps.setSafeOnClickListener {
                switchOverApps.isChecked = false
                askForPermission(
                    requireActivity(),
                    PermissionType.OVERLAY,
                    object : OnPermissionResult {
                        override fun onAllowed() {
                            switchOverApps.isChecked = true
                            switchOverApps.isEnabled = false
                            if (requireContext().hasAllPermissions()) {
                                setLog("App_Locker", "Granted all permissions: Overlay!")
                                (parentFragment as? PermissionBSDismissListener)?.onOverlayPermissionsGranted()
                                (activity as? PermissionBSDismissListener)?.onOverlayPermissionsGranted()
                                dismiss()
                            }
                        }

                        override fun onNotAllowed() {
                            switchOverApps.isChecked = false
                        }
                    })
            }

            switchUsageAccess.setSafeOnClickListener {
                switchUsageAccess.isChecked = false
                askForPermission(
                    requireActivity(),
                    PermissionType.USAGE,
                    object : OnPermissionResult {
                        override fun onAllowed() {
                            switchUsageAccess.isChecked = true
                            switchUsageAccess.isEnabled = false
                            if (requireContext().hasAllPermissions()) {
                                setLog("App_Locker", "Granted all permissions: Usage!")
                                (parentFragment as? PermissionBSDismissListener)?.onOverlayPermissionsGranted()
                                (activity as? PermissionBSDismissListener)?.onOverlayPermissionsGranted()
                                dismiss()
                            }
                        }

                        override fun onNotAllowed() {
                            switchUsageAccess.isChecked = false
                        }
                    })
            }

            switchNotifications.setSafeOnClickListener {
                switchNotifications.isChecked = false
                checkNotificationPermission()
            }

            switchFilesAccess.setSafeOnClickListener {
                switchFilesAccess.isChecked = false
                askForPermission(
                    requireActivity(),
                    PermissionType.ALL_FILES,
                    object : OnPermissionResult {
                        override fun onAllowed() {
                            switchFilesAccess.isChecked = true
                            switchFilesAccess.isEnabled = false
                            setLog("App_Locker", "Granted all files access!")
                            (activity as? PermissionBSDismissListener)?.onFilesPermissionsGranted()
                            dismiss()
                        }

                        override fun onNotAllowed() {
                            switchFilesAccess.isChecked = false
                        }
                    })
            }

            switchNotificationAccess.setSafeOnClickListener {
                switchNotificationAccess.isChecked = false
                askForPermission(
                    requireActivity(),
                    PermissionType.NOTIFICATION_ACCESS,
                    object : OnPermissionResult {
                        override fun onAllowed() {
                            switchNotificationAccess.isChecked = true
                            switchNotificationAccess.isEnabled = false
                            setLog("App_Locker", "Granted notification access!")
                            (activity as? PermissionBSDismissListener)?.onNotificationAccessGranted()
                            dismiss()
                        }

                        override fun onNotAllowed() {
                            switchNotificationAccess.isChecked = false
                        }
                    })
            }

            switchBackgroundStart.setSafeOnClickListener {
                switchBackgroundStart.isChecked = false
                askForPermission(
                    requireActivity(),
                    PermissionType.XIAOMI,
                    object : OnPermissionResult {
                        override fun onAllowed() {
                            switchBackgroundStart.isChecked = true
                            switchBackgroundStart.isEnabled = false
                            if (requireContext().hasAllPermissions()) {
                                setLog(
                                    "App_Locker",
                                    "Granted all permissions: Start From Background!"
                                )
                                (parentFragment as? PermissionBSDismissListener)?.onOverlayPermissionsGranted()
                                (activity as? PermissionBSDismissListener)?.onOverlayPermissionsGranted()
                                dismiss()
                            }
                        }

                        override fun onNotAllowed() {
                            switchBackgroundStart.isChecked = false
                        }
                    })
            }

        }

    }

    // Check if it's a Xiaomi device
    private fun isXiaomiDevice(): Boolean {
        return "xiaomi".equals(Build.MANUFACTURER, ignoreCase = true)
    }

    private fun setupUIVisibility() {
        with(binding) {

            when (permissionType) {
                PermissionType.OVERLAY -> {

                    lyFilesAccess.makeGone()
                    lyNotificationAccess.makeGone()

                    if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
                        lyNotifications.makeVisible()
                        if (checkNotificationPermissionGrant(requireContext())) {
                            switchNotifications.isChecked = true
                            switchNotifications.isEnabled = false
                        }
                    } else {
                        lyNotifications.makeGone()
                    }

                    if (isXiaomiDevice()) {
                        lyBackgroundStart.makeVisible()
                    } else {
                        lyBackgroundStart.makeGone()
                    }

                    if (requireContext().hasDrawOverAppsPermission()) {
                        switchOverApps.isChecked = true
                        switchOverApps.isEnabled = false
                    }

                    if (requireContext().hasUsageAccessPermissions()) {
                        switchUsageAccess.isChecked = true
                        switchUsageAccess.isEnabled = false
                    }

                    if (requireContext().isShowOverlayFromBackgroundPermissionEnable()) {
                        switchBackgroundStart.isChecked = true
                        switchBackgroundStart.isEnabled = false
                    }

                }

                PermissionType.ALL_FILES -> {

                    lyUsageAccess.makeGone()
                    lyDisplayOverApps.makeGone()
                    lyNotifications.makeGone()
                    lyBackgroundStart.makeGone()
                    lyNotificationAccess.makeGone()

                }

                PermissionType.NOTIFICATION_ACCESS -> {

                    lyUsageAccess.makeGone()
                    lyDisplayOverApps.makeGone()
                    lyNotifications.makeGone()
                    lyBackgroundStart.makeGone()
                    lyFilesAccess.makeGone()

                }

                else -> {}
            }
        }
    }

    private fun checkNotificationPermission() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            goForPermission = true
            NOT_SHOW_OPEN_AD = true
            if (!ActivityCompat.shouldShowRequestPermissionRationale(
                    requireActivity(),
                    Manifest.permission.POST_NOTIFICATIONS
                )
            ) {
                setLog("Permission_Check", "No need to show rationale")
                try {
                    notificationPermissionLauncher.launch(Manifest.permission.POST_NOTIFICATIONS)
                } catch (_: Exception) {
                }
            } else {
                setLog("Permission_Check", "Need to show rationale")
                Intent().apply {
                    action = Settings.ACTION_APPLICATION_DETAILS_SETTINGS
                    data = Uri.fromParts(
                        "package", BuildConfig.APPLICATION_ID, null
                    )
                    flags = Intent.FLAG_ACTIVITY_CLEAR_TASK
                }.also {
                    if (it.resolveActivity(requireContext().packageManager) != null) {
                        nPermissionLauncher.launch(it)
                    } else {
                        Toast.makeText(
                            requireContext(),
                            "Settings screen not found!",
                            Toast.LENGTH_SHORT
                        )
                            .show()
                    }
                }
            }
        }
    }

    override fun onDestroyView() {
        super.onDestroyView()
        _binding = null
    }

}