package com.bioauth.phone_auth_native

import android.app.Activity
import android.Manifest
import android.content.pm.PackageManager
import android.os.Build
import androidx.biometric.BiometricManager
import androidx.biometric.BiometricPrompt
import androidx.core.app.ActivityCompat
import androidx.core.content.ContextCompat
import androidx.fragment.app.FragmentActivity
import io.flutter.embedding.engine.plugins.FlutterPlugin
import io.flutter.embedding.engine.plugins.activity.ActivityAware
import io.flutter.embedding.engine.plugins.activity.ActivityPluginBinding
import io.flutter.plugin.common.MethodCall
import io.flutter.plugin.common.MethodChannel
import java.security.Signature

class PhoneAuthNativePlugin :
    FlutterPlugin,
    MethodChannel.MethodCallHandler,
    ActivityAware {
    private lateinit var channel: MethodChannel
    private lateinit var keyStore: DeviceKeyStore
    private lateinit var biometricManager: BiometricManager
    private lateinit var bleController: BleController
    private var activity: Activity? = null
    private var activityBinding: ActivityPluginBinding? = null
    private var biometricPrompt: BiometricPrompt? = null
    private var pendingResult: MethodChannel.Result? = null
    private var pendingPermissionResult: MethodChannel.Result? = null

    override fun onAttachedToEngine(binding: FlutterPlugin.FlutterPluginBinding) {
        keyStore = DeviceKeyStore(binding.applicationContext)
        biometricManager = BiometricManager.from(binding.applicationContext)
        bleController = BleController(binding.applicationContext, binding.binaryMessenger)
        channel = MethodChannel(binding.binaryMessenger, CHANNEL)
        channel.setMethodCallHandler(this)
    }

    override fun onMethodCall(call: MethodCall, result: MethodChannel.Result) {
        when (call.method) {
            "generateKey" -> generateKey(result)
            "getPublicKey" -> publicKey(result)
            "generateSessionIdentityKey" -> generateSessionIdentityKey(result)
            "getSessionIdentityPublicKey" -> sessionIdentityPublicKey(result)
            "signSessionIdentity" -> signSessionIdentity(call.arguments, result)
            "verifySessionIdentity" -> verifySessionIdentity(call.arguments, result)
            "getSecurityCapabilities" -> result.success(securityCapabilities())
            "requestBlePermissions" -> requestBlePermissions(result)
            "sign" -> sign(call.arguments, result)
            else -> if (!bleController.handle(call, result)) result.notImplemented()
        }
    }

    private fun generateKey(result: MethodChannel.Result) {
        if (strongBiometricStatus() != BiometricManager.BIOMETRIC_SUCCESS) {
            result.error("biometric_unavailable", "Strong biometric enrollment is required", null)
            return
        }
        runCatching { keyStore.generateKey() }
            .onSuccess { result.success(publicKeyResponse(it)) }
            .onFailure { result.error("key_generation_failed", "Unable to generate device key", null) }
    }

    private fun publicKey(result: MethodChannel.Result) {
        runCatching { keyStore.publicKey() }
            .onSuccess { result.success(publicKeyResponse(it)) }
            .onFailure { result.error("key_not_found", "Device signing key does not exist", null) }
    }

    private fun generateSessionIdentityKey(result: MethodChannel.Result) {
        runCatching { keyStore.generateSessionIdentityKey() }
            .onSuccess { result.success(publicKeyResponse(it)) }
            .onFailure { result.error("key_generation_failed", "Unable to generate session identity key", null) }
    }

    private fun sessionIdentityPublicKey(result: MethodChannel.Result) {
        runCatching { keyStore.sessionIdentityPublicKey() }
            .onSuccess { result.success(publicKeyResponse(it)) }
            .onFailure { result.error("key_not_found", "Session identity key does not exist", null) }
    }

    private fun signSessionIdentity(arguments: Any?, result: MethodChannel.Result) {
        val map = arguments as? Map<*, *>
        val transcript = map?.get("transcript") as? ByteArray
        if (transcript == null || transcript.isEmpty() || transcript.size > 8192) {
            result.error("invalid_arguments", "Transcript must contain 1..8192 bytes", null)
            return
        }
        runCatching { keyStore.signSessionIdentity(transcript) }
            .onSuccess {
                result.success(mapOf("signature" to it, "algorithm" to DeviceKeyStore.SIGNATURE_ALGORITHM))
            }.onFailure {
                result.error("signing_failed", "Unable to sign session transcript", null)
            }
    }

    private fun verifySessionIdentity(arguments: Any?, result: MethodChannel.Result) {
        val map = arguments as? Map<*, *>
        val publicKey = map?.get("publicKey") as? ByteArray
        val transcript = map?.get("transcript") as? ByteArray
        val signature = map?.get("signature") as? ByteArray
        if (publicKey == null || transcript == null || signature == null || transcript.isEmpty()) {
            result.error("invalid_arguments", "Public key, transcript and signature are required", null)
            return
        }
        runCatching { keyStore.verifySessionIdentity(publicKey, transcript, signature) }
            .onSuccess(result::success)
            .onFailure { result.error("verification_failed", "Invalid session identity material", null) }
    }

    private fun sign(arguments: Any?, result: MethodChannel.Result) {
        if (pendingResult != null) {
            result.error("operation_in_progress", "Another biometric operation is active", null)
            return
        }
        if (strongBiometricStatus() != BiometricManager.BIOMETRIC_SUCCESS) {
            result.error("biometric_unavailable", "Strong biometrics are unavailable", null)
            return
        }
        val fragmentActivity = activity as? FragmentActivity
        if (fragmentActivity == null) {
            result.error("activity_unavailable", "A foreground FragmentActivity is required", null)
            return
        }
        val request = runCatching { SignArguments.parse(arguments) }.getOrElse {
            result.error("invalid_arguments", it.message, null)
            return
        }
        val signature = runCatching { keyStore.initializedSignature() }.getOrElse {
            result.error("key_not_found", "Device signing key does not exist", null)
            return
        }

        pendingResult = result
        biometricPrompt = BiometricPrompt(
            fragmentActivity,
            ContextCompat.getMainExecutor(fragmentActivity),
            biometricCallback(request.payload),
        ).also { prompt ->
            val promptInfo = BiometricPrompt.PromptInfo.Builder()
                .setTitle(request.title)
                .setSubtitle(request.subtitle)
                .setDescription(request.description)
                .setAllowedAuthenticators(BiometricManager.Authenticators.BIOMETRIC_STRONG)
                .setNegativeButtonText("Cancelar")
                .setConfirmationRequired(true)
                .build()
            prompt.authenticate(promptInfo, BiometricPrompt.CryptoObject(signature))
        }
    }

    private fun requestBlePermissions(result: MethodChannel.Result) {
        val currentActivity = activity
        if (currentActivity == null) {
            result.error("activity_unavailable", "A foreground activity is required", null)
            return
        }
        if (pendingPermissionResult != null) {
            result.error("operation_in_progress", "A permission request is active", null)
            return
        }
        val required = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
            arrayOf(Manifest.permission.BLUETOOTH_SCAN, Manifest.permission.BLUETOOTH_CONNECT)
        } else {
            arrayOf(Manifest.permission.ACCESS_FINE_LOCATION)
        }
        if (required.all {
                ContextCompat.checkSelfPermission(currentActivity, it) == PackageManager.PERMISSION_GRANTED
            }
        ) {
            result.success(true)
            return
        }
        pendingPermissionResult = result
        ActivityCompat.requestPermissions(currentActivity, required, BLE_PERMISSION_REQUEST)
    }

    private fun onRequestPermissionsResult(
        requestCode: Int,
        permissions: Array<out String>,
        grantResults: IntArray,
    ): Boolean {
        if (requestCode != BLE_PERMISSION_REQUEST) return false
        val result = pendingPermissionResult ?: return false
        pendingPermissionResult = null
        result.success(grantResults.isNotEmpty() && grantResults.all { it == PackageManager.PERMISSION_GRANTED })
        return true
    }

    private fun biometricCallback(payload: ByteArray) =
        object : BiometricPrompt.AuthenticationCallback() {
            override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
                val signature = result.cryptoObject?.signature
                if (signature == null) {
                    finishWithError("crypto_unavailable", "Authenticated signature is unavailable")
                    return
                }
                runCatching { signPayload(signature, payload) }
                    .onSuccess { bytes ->
                        finishWithSuccess(
                            mapOf(
                                "signature" to bytes,
                                "algorithm" to DeviceKeyStore.SIGNATURE_ALGORITHM,
                            ),
                        )
                    }.onFailure {
                        finishWithError("signing_failed", "Unable to sign canonical payload")
                    }
            }

            override fun onAuthenticationError(errorCode: Int, errString: CharSequence) {
                finishWithError(
                    if (errorCode == BiometricPrompt.ERROR_NEGATIVE_BUTTON ||
                        errorCode == BiometricPrompt.ERROR_USER_CANCELED
                    ) {
                        "authentication_cancelled"
                    } else {
                        "authentication_failed"
                    },
                    "Biometric authentication did not complete",
                )
            }
        }

    private fun signPayload(signature: Signature, payload: ByteArray): ByteArray {
        signature.update(payload)
        return signature.sign()
    }

    private fun securityCapabilities(): Map<String, Any> {
        val security = runCatching { keyStore.keySecurity() }
            .getOrDefault(DeviceKeyStore.KeySecurity(false, false, false))
        val biometricCode = strongBiometricStatus()
        return mapOf(
            "keyExists" to security.keyExists,
            "hardwareBacked" to security.hardwareBacked,
            "strongBoxBacked" to security.strongBoxBacked,
            "strongBiometrics" to (biometricCode == BiometricManager.BIOMETRIC_SUCCESS),
            "biometricAvailability" to biometricAvailability(biometricCode),
        )
    }

    private fun strongBiometricStatus(): Int =
        biometricManager.canAuthenticate(BiometricManager.Authenticators.BIOMETRIC_STRONG)

    private fun biometricAvailability(code: Int): String =
        when (code) {
            BiometricManager.BIOMETRIC_SUCCESS -> "available"
            BiometricManager.BIOMETRIC_ERROR_NONE_ENROLLED -> "noneEnrolled"
            BiometricManager.BIOMETRIC_ERROR_HW_UNAVAILABLE -> "temporarilyUnavailable"
            BiometricManager.BIOMETRIC_ERROR_NO_HARDWARE -> "unsupported"
            else -> "unavailable"
        }

    private fun publicKeyResponse(bytes: ByteArray): Map<String, Any> =
        mapOf("publicKey" to bytes, "algorithm" to DeviceKeyStore.PUBLIC_KEY_ALGORITHM)

    private fun finishWithSuccess(value: Any) {
        val result = pendingResult ?: return
        pendingResult = null
        biometricPrompt = null
        result.success(value)
    }

    private fun finishWithError(code: String, message: String) {
        val result = pendingResult ?: return
        pendingResult = null
        biometricPrompt = null
        result.error(code, message, null)
    }

    private fun cancelPendingOperation() {
        biometricPrompt?.cancelAuthentication()
        finishWithError("activity_unavailable", "Biometric activity detached")
        pendingPermissionResult?.error(
            "activity_unavailable",
            "Permission activity detached",
            null,
        )
        pendingPermissionResult = null
    }

    override fun onAttachedToActivity(binding: ActivityPluginBinding) {
        activityBinding = binding
        activity = binding.activity
        binding.addRequestPermissionsResultListener(::onRequestPermissionsResult)
    }

    override fun onDetachedFromActivityForConfigChanges() {
        cancelPendingOperation()
        activityBinding?.removeRequestPermissionsResultListener(::onRequestPermissionsResult)
        activityBinding = null
        activity = null
    }

    override fun onReattachedToActivityForConfigChanges(binding: ActivityPluginBinding) {
        activityBinding = binding
        activity = binding.activity
        binding.addRequestPermissionsResultListener(::onRequestPermissionsResult)
    }

    override fun onDetachedFromActivity() {
        cancelPendingOperation()
        activityBinding?.removeRequestPermissionsResultListener(::onRequestPermissionsResult)
        activityBinding = null
        activity = null
    }

    override fun onDetachedFromEngine(binding: FlutterPlugin.FlutterPluginBinding) {
        cancelPendingOperation()
        bleController.dispose()
        channel.setMethodCallHandler(null)
    }

    companion object {
        private const val CHANNEL = "phone_auth_native"
        private const val BLE_PERMISSION_REQUEST = 5710
    }
}
