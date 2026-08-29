package com.bioauth.phone_auth_native

import android.app.Activity
import android.Manifest
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.os.Build
import android.os.Handler
import android.os.Looper
import androidx.biometric.BiometricManager
import androidx.biometric.BiometricPrompt
import androidx.core.app.ActivityCompat
import androidx.core.app.NotificationManagerCompat
import androidx.core.content.ContextCompat
import androidx.core.app.NotificationCompat
import androidx.fragment.app.FragmentActivity
import io.flutter.embedding.engine.plugins.FlutterPlugin
import io.flutter.embedding.engine.plugins.activity.ActivityAware
import io.flutter.embedding.engine.plugins.activity.ActivityPluginBinding
import io.flutter.plugin.common.MethodCall
import io.flutter.plugin.common.MethodChannel
import java.security.Signature
import javax.crypto.Cipher

class PhoneAuthNativePlugin :
    FlutterPlugin,
    MethodChannel.MethodCallHandler,
    ActivityAware {
    private lateinit var channel: MethodChannel
    private lateinit var vaultChannel: MethodChannel
    private lateinit var keyStore: DeviceKeyStore
    private lateinit var lockerKeyStore: LockerKeyStore
    private lateinit var biometricManager: BiometricManager
    private lateinit var bleController: BleController
    private lateinit var passkeyStore: PasskeyStore
    private lateinit var webAuthnKeyStore: WebAuthnKeyStore
    private lateinit var vaultStoreChannel: VaultStoreChannel
    private lateinit var applicationContext: Context
    private var activity: Activity? = null
    private var activityBinding: ActivityPluginBinding? = null
    private var biometricPrompt: BiometricPrompt? = null
    private var pendingResult: MethodChannel.Result? = null
    private var pendingPermissionResult: MethodChannel.Result? = null
    private var pendingBackgroundSessionResult: MethodChannel.Result? = null

    override fun onAttachedToEngine(binding: FlutterPlugin.FlutterPluginBinding) {
        applicationContext = binding.applicationContext
        keyStore = DeviceKeyStore(binding.applicationContext)
        lockerKeyStore = LockerKeyStore(binding.applicationContext)
        biometricManager = BiometricManager.from(binding.applicationContext)
        bleController = BleController(binding.applicationContext, binding.binaryMessenger)
        passkeyStore = PasskeyStore(binding.applicationContext)
        webAuthnKeyStore = WebAuthnKeyStore(binding.applicationContext)
        vaultStoreChannel = VaultStoreChannel(
            BiometricManager.from(binding.applicationContext),
            VaultKeyStore(binding.applicationContext),
            VaultFileStorage(binding.applicationContext),
        )
        channel = MethodChannel(binding.binaryMessenger, CHANNEL)
        channel.setMethodCallHandler(this)
        vaultChannel = MethodChannel(binding.binaryMessenger, VAULT_CHANNEL)
        vaultChannel.setMethodCallHandler(vaultStoreChannel)
    }

    override fun onMethodCall(call: MethodCall, result: MethodChannel.Result) {
        when (call.method) {
            "generateKey" -> generateKey(call.arguments, result)
            "getPublicKey" -> publicKey(call.arguments, result)
            "generateSessionIdentityKey" -> generateSessionIdentityKey(result)
            "getSessionIdentityPublicKey" -> sessionIdentityPublicKey(result)
            "signSessionIdentity" -> signSessionIdentity(call.arguments, result)
            "verifySessionIdentity" -> verifySessionIdentity(call.arguments, result)
            "getSecurityCapabilities" -> result.success(securityCapabilities())
            "requestBlePermissions" -> requestBlePermissions(result)
            "setBackgroundSessionsEnabled" -> setBackgroundSessionsEnabled(call.arguments, result)
            "performWebAuthn" -> performWebAuthn(call.arguments, result)
            "cancelWebAuthn" -> cancelWebAuthn(call.arguments, result)
            "listPasskeys" -> listPasskeys(result)
            "deletePasskey" -> deletePasskey(call.arguments, result)
            "sign" -> sign(call.arguments, result)
            "lockerKeyStatus" -> lockerKeyStatus(result)
            "generateLockerKey" -> generateLockerKey(result)
            "lockerWrapKey" -> lockerWrapKey(call.arguments, result)
            "lockerUnwrapKey" -> lockerUnwrapKey(call.arguments, result)
            else -> if (!bleController.handle(call, result)) result.notImplemented()
        }
    }

    private fun generateKey(arguments: Any?, result: MethodChannel.Result) {
        if (strongBiometricStatus() != BiometricManager.BIOMETRIC_SUCCESS) {
            result.error("biometric_unavailable", "Strong biometric enrollment is required", null)
            return
        }
        runCatching { keyStore.generateKey(purposeOf(arguments)) }
            .onSuccess { result.success(publicKeyResponse(it)) }
            .onFailure { result.error("key_generation_failed", "Unable to generate device key", null) }
    }

    private fun publicKey(arguments: Any?, result: MethodChannel.Result) {
        runCatching { keyStore.publicKey(purposeOf(arguments)) }
            .onSuccess { result.success(publicKeyResponse(it)) }
            .onFailure { result.error("key_not_found", "Device signing key does not exist", null) }
    }

    // Absent means authorization, so every caller written before purposes had
    // their own keys keeps reaching the key it enrolled. An unrecognised name
    // is refused by the store rather than mapped to a new alias.
    private fun purposeOf(arguments: Any?): String =
        (arguments as? Map<*, *>)?.get("purpose") as? String ?: DeviceKeyStore.AUTHORIZATION

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

    // Every purpose signs the same way through the same prompt, and differs
    // only in which key the CryptoObject carries. One path on purpose: a
    // second copy is a second place for the prompt's guarantees to drift.
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
        val initialized = runCatching {
            keyStore.initializedSignature(purposeOf(arguments))
        }.getOrElse {
            result.error("key_not_found", "Signing key does not exist", null)
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
            prompt.authenticate(promptInfo, BiometricPrompt.CryptoObject(initialized))
        }
    }

    private fun listPasskeys(result: MethodChannel.Result) {
        runCatching {
            val records = passkeyStore.all()
            val aliases = webAuthnKeyStore.aliases()
            passkeyInventory(records, aliases, webAuthnKeyStore::isUsable)
        }.onSuccess(result::success)
            .onFailure { result.error("passkey_store_failed", "Unable to read passkeys", null) }
    }

    private fun deletePasskey(arguments: Any?, result: MethodChannel.Result) {
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
        val map = arguments as? Map<*, *>
        val kind = map?.get("kind") as? String
        val identifier = map?.get("identifier") as? String
        val target = runCatching {
            require(identifier != null)
            when (kind) {
                "credential" -> {
                    val id = WebAuthnRequestParser.decode(identifier, "credentialId")
                    val record = requireNotNull(passkeyStore.find(id)) { "Passkey not found" }
                    Pair("${record.rpId} · ${record.userName}") {
                        val current = requireNotNull(passkeyStore.find(id)) { "Passkey not found" }
                        webAuthnKeyStore.delete(current.keyAlias)
                        passkeyStore.delete(id)
                    }
                }
                "orphan" -> {
                    require(identifier.startsWith(WebAuthnKeyStore.ALIAS_PREFIX))
                    require(identifier in webAuthnKeyStore.aliases())
                    require(passkeyStore.all().none { it.keyAlias == identifier })
                    Pair("Chave órfã") {
                        require(passkeyStore.all().none { it.keyAlias == identifier })
                        webAuthnKeyStore.delete(identifier)
                    }
                }
                else -> throw IllegalArgumentException("Invalid passkey kind")
            }
        }.getOrElse {
            result.error("invalid_arguments", "Passkey no longer exists", null)
            return
        }

        pendingResult = result
        biometricPrompt = BiometricPrompt(
            fragmentActivity,
            ContextCompat.getMainExecutor(fragmentActivity),
            deletionCallback(target.second),
        ).also { prompt ->
            prompt.authenticate(
                BiometricPrompt.PromptInfo.Builder()
                    .setTitle("Excluir passkey")
                    .setSubtitle(target.first)
                    .setDescription("A chave e os metadados serão removidos deste telefone")
                    .setAllowedAuthenticators(BiometricManager.Authenticators.BIOMETRIC_STRONG)
                    .setNegativeButtonText("Cancelar")
                    .setConfirmationRequired(true)
                    .build(),
            )
        }
    }

    private fun lockerKeyStatus(result: MethodChannel.Result) {
        val security = runCatching { lockerKeyStore.keySecurity() }
            .getOrDefault(LockerKeyStore.Security(false, false, false))
        result.success(
            mapOf(
                "keyExists" to security.keyExists,
                "hardwareBacked" to security.hardwareBacked,
                "strongBoxBacked" to security.strongBoxBacked,
                "strongBiometrics" to (strongBiometricStatus() == BiometricManager.BIOMETRIC_SUCCESS),
            ),
        )
    }

    private fun generateLockerKey(result: MethodChannel.Result) {
        if (strongBiometricStatus() != BiometricManager.BIOMETRIC_SUCCESS) {
            result.error("biometric_unavailable", "Strong biometric enrollment is required", null)
            return
        }
        runCatching { lockerKeyStore.ensureKey() }
            .onSuccess { lockerKeyStatus(result) }
            .onFailure { result.error("key_generation_failed", "Unable to generate the file locker key", null) }
    }

    /** `locker.create`: wrap a data key the desktop just generated. */
    private fun lockerWrapKey(arguments: Any?, result: MethodChannel.Result) {
        val map = arguments as? Map<*, *>
        val binding = map?.get("binding") as? ByteArray
        val credentialId = map?.get("credentialId") as? String
        val dataKey = map?.get("dataKey") as? ByteArray
        val prompt = lockerPrompt(map) ?: run {
            result.error("invalid_arguments", "A computer name and a file name are required", null)
            return
        }
        if (binding == null || binding.size != LockerKeyStore.BINDING_BYTES ||
            credentialId.isNullOrBlank() ||
            dataKey == null || dataKey.size != LockerKeyStore.DATA_KEY_BYTES
        ) {
            result.error("invalid_arguments", "A binding, a credential and a 32 byte key are required", null)
            return
        }
        runCipherOperation(
            result,
            title = "Trancar arquivo",
            subtitle = prompt.first,
            description = "${prompt.second} quer trancar este arquivo",
            cipherOf = { lockerKeyStore.wrapCipher() },
        ) { cipher ->
            mapOf("wrapper" to lockerKeyStore.wrap(cipher, binding, credentialId, dataKey))
        }
    }

    /** `locker.unlock` and `locker.rekey`: hand back a data key. */
    private fun lockerUnwrapKey(arguments: Any?, result: MethodChannel.Result) {
        val map = arguments as? Map<*, *>
        val binding = map?.get("binding") as? ByteArray
        val credentialId = map?.get("credentialId") as? String
        val wrapper = map?.get("wrapper") as? ByteArray
        val rekeying = map?.get("rekeying") as? Boolean ?: false
        val prompt = lockerPrompt(map) ?: run {
            result.error("invalid_arguments", "A computer name and a file name are required", null)
            return
        }
        if (binding == null || binding.size != LockerKeyStore.BINDING_BYTES ||
            credentialId.isNullOrBlank() ||
            wrapper == null || wrapper.isEmpty() || wrapper.size > MAX_LOCKER_WRAPPER_BYTES
        ) {
            result.error("invalid_arguments", "A binding, a credential and a wrapper are required", null)
            return
        }
        runCipherOperation(
            result,
            title = if (rekeying) "Trocar a chave do cofre" else "Abrir arquivo",
            subtitle = prompt.first,
            // Re-keying is not unlocking, and the phone says which one it is.
            description = if (rekeying) {
                "${prompt.second} quer ligar este arquivo a uma chave nova"
            } else {
                "${prompt.second} quer abrir este arquivo"
            },
            cipherOf = { lockerKeyStore.unwrapCipher(wrapper) },
        ) { cipher ->
            mapOf("dataKey" to lockerKeyStore.unwrap(cipher, binding, credentialId, wrapper))
        }
    }

    /** The file name and the computer name, both of which the user sees. */
    private fun lockerPrompt(map: Map<*, *>?): Pair<String, String>? {
        val fileName = map?.get("fileName") as? String
        val verifierName = map?.get("verifierName") as? String
        if (fileName.isNullOrBlank() || verifierName.isNullOrBlank()) return null
        return fileName to verifierName
    }

    /**
     * Runs one biometric-gated cipher operation.
     *
     * The cipher is initialised before the prompt, because that is what arms
     * the per-use authentication requirement, and finished after it, because
     * that is what proves the user was there for this operation.
     */
    private fun runCipherOperation(
        result: MethodChannel.Result,
        title: String,
        subtitle: String,
        description: String,
        cipherOf: () -> Cipher,
        complete: (Cipher) -> Map<String, Any>,
    ) {
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
        val cipher = runCatching(cipherOf).getOrElse {
            result.error("key_not_found", "The file locker key is unavailable", null)
            return
        }

        pendingResult = result
        biometricPrompt = BiometricPrompt(
            fragmentActivity,
            ContextCompat.getMainExecutor(fragmentActivity),
            object : BiometricPrompt.AuthenticationCallback() {
                override fun onAuthenticationSucceeded(authentication: BiometricPrompt.AuthenticationResult) {
                    val authenticated = authentication.cryptoObject?.cipher
                    if (authenticated == null) {
                        finishWithError("crypto_unavailable", "Authenticated cipher is unavailable")
                        return
                    }
                    runCatching { complete(authenticated) }
                        .onSuccess { finishWithSuccess(it) }
                        // Deliberately one message for every failure: which
                        // byte was wrong is not something to tell a caller.
                        .onFailure { finishWithError("locker_failed", "Unable to complete the locker operation") }
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
            },
        ).also { prompt ->
            val promptInfo = BiometricPrompt.PromptInfo.Builder()
                .setTitle(title)
                .setSubtitle(subtitle)
                .setDescription(description)
                .setAllowedAuthenticators(BiometricManager.Authenticators.BIOMETRIC_STRONG)
                .setNegativeButtonText("Cancelar")
                .setConfirmationRequired(true)
                .build()
            prompt.authenticate(promptInfo, BiometricPrompt.CryptoObject(cipher))
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

    private fun setBackgroundSessionsEnabled(arguments: Any?, result: MethodChannel.Result) {
        val enabled = (arguments as? Map<*, *>)?.get("enabled") as? Boolean
        if (enabled == null) {
            result.error("invalid_arguments", "enabled must be a boolean", null)
            return
        }
        if (!enabled) {
            applicationContext.stopService(Intent(applicationContext, BackgroundSessionService::class.java))
            result.success(true)
            return
        }
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU &&
            ContextCompat.checkSelfPermission(
                applicationContext,
                Manifest.permission.POST_NOTIFICATIONS,
            ) != PackageManager.PERMISSION_GRANTED
        ) {
            val currentActivity = activity
            if (currentActivity == null) {
                result.error("activity_unavailable", "A foreground activity is required", null)
                return
            }
            if (pendingBackgroundSessionResult != null) {
                result.error("operation_in_progress", "A permission request is active", null)
                return
            }
            pendingBackgroundSessionResult = result
            ActivityCompat.requestPermissions(
                currentActivity,
                arrayOf(Manifest.permission.POST_NOTIFICATIONS),
                NOTIFICATION_PERMISSION_REQUEST,
            )
            return
        }
        if (!backgroundNotificationAvailable()) {
            result.error(
                "background_sessions_unavailable",
                "Background session notifications are disabled",
                null,
            )
            return
        }
        if (BackgroundSessionService.running) {
            result.success(true)
            return
        }
        startBackgroundSessionService(result)
    }

    private fun startBackgroundSessionService(result: MethodChannel.Result) {
        runCatching {
            ContextCompat.startForegroundService(
                applicationContext,
                Intent(applicationContext, BackgroundSessionService::class.java),
            )
        }.onSuccess { waitForBackgroundSessionService(result, 0) }
            .onFailure {
                result.error(
                    "background_sessions_unavailable",
                    "Unable to start background sessions",
                    null,
                )
            }
    }

    private fun waitForBackgroundSessionService(result: MethodChannel.Result, attempt: Int) {
        if (BackgroundSessionService.running) {
            result.success(true)
        } else if (attempt >= 20) {
            result.error(
                "background_sessions_unavailable",
                "Foreground session service did not start",
                null,
            )
        } else {
            Handler(Looper.getMainLooper()).postDelayed(
                { waitForBackgroundSessionService(result, attempt + 1) },
                50,
            )
        }
    }

    private fun backgroundNotificationAvailable(): Boolean {
        if (!NotificationManagerCompat.from(applicationContext).areNotificationsEnabled()) return false
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.O) return true
        val channel = applicationContext.getSystemService(NotificationManager::class.java)
            .getNotificationChannel(BackgroundSessionService.CHANNEL_ID)
        return channel == null || channel.importance != NotificationManager.IMPORTANCE_NONE
    }

    private fun performWebAuthn(arguments: Any?, result: MethodChannel.Result) {
        val map = arguments as? Map<*, *>
        val requestId = map?.get("requestId") as? String
        val operation = map?.get("operation") as? String
        val origin = map?.get("origin") as? String
        val optionsJson = map?.get("optionsJson") as? String
        if (requestId == null || requestId.length !in 1..64 ||
            requestId.any { !it.isLetterOrDigit() && it != '-' } ||
            operation !in setOf(WebAuthnRelayActivity.OP_CREATE, WebAuthnRelayActivity.OP_GET) ||
            origin == null || origin.length !in 8..2048 ||
            optionsJson == null || optionsJson.length !in 2..65536
        ) {
            result.error("invalid_arguments", "Invalid desktop passkey request", null)
            return
        }
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU &&
            ContextCompat.checkSelfPermission(
                applicationContext,
                Manifest.permission.POST_NOTIFICATIONS,
            ) != PackageManager.PERMISSION_GRANTED
        ) {
            result.error(
                "background_sessions_unavailable",
                "Notification permission is required for desktop passkeys",
                null,
            )
            return
        }
        if (!BackgroundSessionService.running || !backgroundNotificationAvailable()) {
            result.error(
                "background_sessions_unavailable",
                "Foreground session service is not running",
                null,
            )
            return
        }

        val manager = applicationContext.getSystemService(NotificationManager::class.java)
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            manager.createNotificationChannel(
                NotificationChannel(
                    WEBAUTHN_CHANNEL,
                    "Solicitacoes de passkey",
                    NotificationManager.IMPORTANCE_HIGH,
                ),
            )
            if (manager.getNotificationChannel(WEBAUTHN_CHANNEL).importance == NotificationManager.IMPORTANCE_NONE) {
                result.error("background_sessions_unavailable", "Passkey notifications are disabled", null)
                return
            }
        }
        if (!WebAuthnRelayCoordinator.add(requestId, result)) {
            result.error("operation_in_progress", "Passkey request already exists", null)
            return
        }
        val intent = Intent(applicationContext, WebAuthnRelayActivity::class.java).apply {
            putExtra(WebAuthnRelayActivity.EXTRA_REQUEST_ID, requestId)
            putExtra(WebAuthnRelayActivity.EXTRA_OPERATION, operation)
            putExtra(WebAuthnRelayActivity.EXTRA_ORIGIN, origin)
            putExtra(WebAuthnRelayActivity.EXTRA_OPTIONS, optionsJson)
        }
        val pendingIntent = PendingIntent.getActivity(
            applicationContext,
            WebAuthnRelayCoordinator.notificationId(requestId),
            intent,
            PendingIntent.FLAG_ONE_SHOT or PendingIntent.FLAG_IMMUTABLE,
        )
        val icon = applicationContext.applicationInfo.icon.takeIf { it != 0 }
            ?: android.R.drawable.ic_lock_idle_lock
        manager.notify(
            WebAuthnRelayCoordinator.notificationId(requestId),
            NotificationCompat.Builder(applicationContext, WEBAUTHN_CHANNEL)
                .setSmallIcon(icon)
                .setContentTitle("Passkey solicitada no computador")
                .setContentText(origin)
                .setStyle(NotificationCompat.BigTextStyle().bigText("Toque para revisar e autenticar: $origin"))
                .setContentIntent(pendingIntent)
                .setAutoCancel(true)
                .setCategory(NotificationCompat.CATEGORY_EVENT)
                .setPriority(NotificationCompat.PRIORITY_HIGH)
                .build(),
        )
        Handler(Looper.getMainLooper()).postDelayed({
            manager.cancel(WebAuthnRelayCoordinator.notificationId(requestId))
            WebAuthnRelayCoordinator.cancel(
                requestId,
                "Desktop passkey request expired",
            )
        }, WEBAUTHN_TIMEOUT_MS)
    }

    private fun cancelWebAuthn(arguments: Any?, result: MethodChannel.Result) {
        val requestId = (arguments as? Map<*, *>)?.get("requestId") as? String
        if (requestId == null || requestId.length !in 1..64 ||
            requestId.any { !it.isLetterOrDigit() && it != '-' }
        ) {
            result.error("invalid_arguments", "Invalid desktop passkey request id", null)
            return
        }
        applicationContext.getSystemService(NotificationManager::class.java)
            .cancel(WebAuthnRelayCoordinator.notificationId(requestId))
        WebAuthnRelayCoordinator.cancel(requestId, "Desktop cancelled the passkey request")
        result.success(null)
    }

    private fun onRequestPermissionsResult(
        requestCode: Int,
        permissions: Array<out String>,
        grantResults: IntArray,
    ): Boolean {
        if (requestCode == NOTIFICATION_PERMISSION_REQUEST) {
            val result = pendingBackgroundSessionResult ?: return false
            pendingBackgroundSessionResult = null
            if (grantResults.singleOrNull() == PackageManager.PERMISSION_GRANTED) {
                startBackgroundSessionService(result)
            } else {
                result.success(false)
            }
            return true
        }
        if (requestCode != BLE_PERMISSION_REQUEST) return false
        val result = pendingPermissionResult ?: return false
        pendingPermissionResult = null
        pendingBackgroundSessionResult?.error(
            "activity_unavailable",
            "Permission activity detached",
            null,
        )
        pendingBackgroundSessionResult = null
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

    private fun deletionCallback(delete: () -> Unit) =
        object : BiometricPrompt.AuthenticationCallback() {
            override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
                runCatching(delete)
                    .onSuccess { finishWithSuccess(true) }
                    .onFailure { finishWithError("passkey_delete_failed", "Unable to delete passkey") }
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
        vaultStoreChannel.attach(binding.activity)
        binding.addRequestPermissionsResultListener(::onRequestPermissionsResult)
    }

    override fun onDetachedFromActivityForConfigChanges() {
        cancelPendingOperation()
        vaultStoreChannel.detach()
        activityBinding?.removeRequestPermissionsResultListener(::onRequestPermissionsResult)
        activityBinding = null
        activity = null
    }

    override fun onReattachedToActivityForConfigChanges(binding: ActivityPluginBinding) {
        activityBinding = binding
        activity = binding.activity
        vaultStoreChannel.attach(binding.activity)
        binding.addRequestPermissionsResultListener(::onRequestPermissionsResult)
    }

    override fun onDetachedFromActivity() {
        cancelPendingOperation()
        vaultStoreChannel.detach()
        activityBinding?.removeRequestPermissionsResultListener(::onRequestPermissionsResult)
        activityBinding = null
        activity = null
    }

    override fun onDetachedFromEngine(binding: FlutterPlugin.FlutterPluginBinding) {
        cancelPendingOperation()
        vaultStoreChannel.detach()
        bleController.dispose()
        channel.setMethodCallHandler(null)
        vaultChannel.setMethodCallHandler(null)
    }

    companion object {
        private const val CHANNEL = "phone_auth_native"
        private const val VAULT_CHANNEL = "bioauth/vault_store"
        private const val BLE_PERMISSION_REQUEST = 5710
        private const val NOTIFICATION_PERMISSION_REQUEST = 5711
        private const val WEBAUTHN_CHANNEL = "bioauth_webauthn_requests"
        private const val WEBAUTHN_TIMEOUT_MS = 90_000L

        /** Mirrors the protocol's wrapper bound, so an oversized blob is
         * refused before a key is even touched. */
        private const val MAX_LOCKER_WRAPPER_BYTES = 512
    }
}

internal fun passkeyInventory(
    records: List<PasskeyRecord>,
    aliases: Set<String>,
    isUsable: (String) -> Boolean,
): List<Map<String, Any>> {
    val referenced = records.mapTo(mutableSetOf()) { it.keyAlias }
    return records.map { record ->
        val status = when {
            record.keyAlias !in aliases -> "missingKey"
            !isUsable(record.keyAlias) -> "invalidKey"
            else -> "available"
        }
        mapOf(
            "kind" to "credential",
            "identifier" to WebAuthnRequestParser.base64Url(record.credentialId),
            "rpId" to record.rpId,
            "userName" to record.userName,
            "userDisplayName" to record.userDisplayName,
            "createdAtMillis" to record.createdAtMillis,
            "status" to status,
        )
    } + (aliases - referenced).map { alias ->
        mapOf(
            "kind" to "orphan",
            "identifier" to alias,
            "rpId" to "",
            "userName" to "",
            "userDisplayName" to "",
            "createdAtMillis" to 0L,
            "status" to "orphanKey",
        )
    }
}
