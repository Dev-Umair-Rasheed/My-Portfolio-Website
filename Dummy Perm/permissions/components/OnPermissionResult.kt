package com.applock.password.fingerprint.pattern.media.vault.gss.core.base.permissions.components

interface OnPermissionResult {
    fun onAllowed()
    fun onNotAllowed() {}
    fun onPermanentlyDenied() {}
}