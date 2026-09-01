package com.bioauth.phone_auth_native

import android.Manifest
import android.annotation.SuppressLint
import android.bluetooth.BluetoothAdapter
import android.bluetooth.BluetoothDevice
import android.bluetooth.BluetoothGatt
import android.bluetooth.BluetoothGattCallback
import android.bluetooth.BluetoothGattCharacteristic
import android.bluetooth.BluetoothGattDescriptor
import android.bluetooth.BluetoothManager
import android.bluetooth.BluetoothProfile
import android.bluetooth.BluetoothStatusCodes
import android.bluetooth.le.ScanCallback
import android.bluetooth.le.ScanFilter
import android.bluetooth.le.ScanResult
import android.bluetooth.le.ScanSettings
import android.content.Context
import android.content.pm.PackageManager
import android.os.Build
import android.os.Handler
import android.os.Looper
import android.os.ParcelUuid
import androidx.core.content.ContextCompat
import io.flutter.plugin.common.BinaryMessenger
import io.flutter.plugin.common.EventChannel
import io.flutter.plugin.common.MethodCall
import io.flutter.plugin.common.MethodChannel
import java.util.UUID

@Suppress("DEPRECATION")
@SuppressLint("MissingPermission")
internal class BleController(
    private val context: Context,
    messenger: BinaryMessenger,
) {
    private val adapter: BluetoothAdapter?
        get() = (context.getSystemService(Context.BLUETOOTH_SERVICE) as BluetoothManager).adapter
    private val main = Handler(Looper.getMainLooper())
    private var scanSink: EventChannel.EventSink? = null
    private var eventSink: EventChannel.EventSink? = null
    // Written from the GATT callback thread and read from the main one, so
    // both need a happens-before edge of their own; `closeGatt` runs on either.
    @Volatile
    private var gatt: BluetoothGatt? = null

    @Volatile
    private var requestCharacteristic: BluetoothGattCharacteristic? = null

    // Claimed and released under [connectLock], for the reason spelled out in
    // [PendingGattOp]: connecting is settled from four places across two
    // threads -- the deadline on the main looper, and the connection-state,
    // service-discovery and descriptor-write callbacks on a binder thread --
    // and reading the field, finding it set and clearing it was three steps.
    // Two of them arriving together replied twice to one `MethodChannel`
    // request, which throws, and the deadline firing as the link finally
    // answers is exactly when they arrive together.
    private val connectLock = Any()
    private var pendingConnect: MethodChannel.Result? = null

    // Both carry a deadline. Only connecting had one, and it is the operations
    // *after* connecting that hold the radio: see [PendingGattOp]. The MTU
    // failing does not take the link down, because the Dart side is written to
    // carry on at the 23-byte minimum -- but a write whose completion never
    // arrives means the stack's one operation slot is stuck, so every later
    // write on this link would wait behind it. That link is finished; saying so
    // is what lets the next connection have the client back.
    private val pendingMtu = PendingGattOp(
        errorCode = "mtu_failed",
        timeoutMs = OPERATION_TIMEOUT_MS,
        schedule = { runnable, delay -> main.postDelayed(runnable, delay) },
        unschedule = { runnable -> main.removeCallbacks(runnable) },
    )
    private val pendingWrite = PendingGattOp(
        errorCode = "write_failed",
        timeoutMs = OPERATION_TIMEOUT_MS,
        schedule = { runnable, delay -> main.postDelayed(runnable, delay) },
        unschedule = { runnable -> main.removeCallbacks(runnable) },
        onExpired = { closeGatt(emitDisconnected = true) },
    )
    private var expectedService: UUID? = null
    private var expectedRequestCharacteristic: UUID? = null
    private var expectedResponseCharacteristic: UUID? = null
    private val connectTimeout = Runnable {
        // Only tears the link down if this deadline is what actually claimed
        // the reply. Asking whether one was pending and then failing it was
        // two steps, and a connection completing in between them left this
        // closing a GATT that had just come up -- `removeCallbacks` cannot
        // recall a runnable that is already running, and the callback that
        // completed it runs on a binder thread.
        val result = takeConnect() ?: return@Runnable
        main.post { result.error("connection_failed", "BLE connection timed out", null) }
        closeGatt(emitDisconnected = true)
    }

    init {
        EventChannel(messenger, SCAN_CHANNEL).setStreamHandler(
            object : EventChannel.StreamHandler {
                override fun onListen(arguments: Any?, events: EventChannel.EventSink) {
                    scanSink = events
                }

                override fun onCancel(arguments: Any?) {
                    scanSink = null
                }
            },
        )
        EventChannel(messenger, EVENT_CHANNEL).setStreamHandler(
            object : EventChannel.StreamHandler {
                override fun onListen(arguments: Any?, events: EventChannel.EventSink) {
                    eventSink = events
                }

                override fun onCancel(arguments: Any?) {
                    eventSink = null
                }
            },
        )
    }

    fun handle(call: MethodCall, result: MethodChannel.Result): Boolean {
        when (call.method) {
            "bleStartScan" -> startScan(call, result)
            "bleStopScan" -> stopScan(result)
            "bleConnect" -> connect(call, result)
            "bleRequestMtu" -> requestMtu(call, result)
            "bleWrite" -> write(call, result)
            "bleDisconnect" -> disconnect(result)
            else -> return false
        }
        return true
    }

    private fun startScan(call: MethodCall, result: MethodChannel.Result) {
        if (!hasBlePermissions()) {
            result.error("permission_denied", "Bluetooth permission is required", null)
            return
        }
        val bluetoothAdapter = adapter
        if (bluetoothAdapter == null || !bluetoothAdapter.isEnabled) {
            result.error("bluetooth_unavailable", "Bluetooth is unavailable or disabled", null)
            return
        }
        val service = parseUuid(call.argument<String>("serviceUuid"), result) ?: return
        val filter = ScanFilter.Builder().setServiceUuid(ParcelUuid(service)).build()
        val settings = ScanSettings.Builder()
            .setScanMode(ScanSettings.SCAN_MODE_LOW_LATENCY)
            .build()
        runCatching {
            bluetoothAdapter.bluetoothLeScanner.startScan(listOf(filter), settings, scanCallback)
        }.onSuccess {
            result.success(null)
        }.onFailure {
            result.error("scan_failed", "Unable to start BLE scan", null)
        }
    }

    private fun stopScan(result: MethodChannel.Result) {
        if (hasBlePermissions()) {
            runCatching { adapter?.bluetoothLeScanner?.stopScan(scanCallback) }
        }
        result.success(null)
    }

    private fun connect(call: MethodCall, result: MethodChannel.Result) {
        if (!hasBlePermissions()) {
            result.error("permission_denied", "Bluetooth permission is required", null)
            return
        }
        if (pendingConnect != null || gatt != null) {
            result.error("operation_in_progress", "A BLE connection is already active", null)
            return
        }
        val connectionId = call.argument<String>("connectionId")
        if (connectionId.isNullOrBlank()) {
            result.error("invalid_arguments", "Missing BLE connection id", null)
            return
        }
        expectedService = parseUuid(call.argument("serviceUuid"), result) ?: return
        expectedRequestCharacteristic =
            parseUuid(call.argument("requestCharacteristicUuid"), result) ?: return
        expectedResponseCharacteristic =
            parseUuid(call.argument("responseCharacteristicUuid"), result) ?: return
        val device = runCatching { adapter?.getRemoteDevice(connectionId) }.getOrNull()
        if (device == null) {
            result.error("invalid_arguments", "Invalid BLE connection id", null)
            return
        }

        if (!armConnect(result)) {
            result.error("operation_in_progress", "A BLE connection is already active", null)
            return
        }
        gatt = device.connectGatt(context, false, gattCallback, BluetoothDevice.TRANSPORT_LE)
        if (gatt == null) {
            failConnect("Unable to start BLE connection")
            return
        }
        main.postDelayed(connectTimeout, CONNECT_TIMEOUT_MS)
    }

    private fun requestMtu(call: MethodCall, result: MethodChannel.Result) {
        if (!requireBlePermissions(result)) return
        val requested = call.argument<Int>("mtu")
        val currentGatt = gatt
        if (requested == null || requested !in 23..517 || currentGatt == null) {
            result.error("invalid_arguments", "Invalid MTU or disconnected BLE link", null)
            return
        }
        if (!pendingMtu.arm(result)) {
            result.error("operation_in_progress", "An MTU request is active", null)
            return
        }
        if (!currentGatt.requestMtu(requested)) {
            pendingMtu.fail("Unable to request BLE MTU")
        }
    }

    private fun write(call: MethodCall, result: MethodChannel.Result) {
        if (!requireBlePermissions(result)) return
        val value = call.argument<ByteArray>("value")
        val currentGatt = gatt
        val characteristic = requestCharacteristic
        if (value == null || value.isEmpty() || currentGatt == null || characteristic == null) {
            result.error("invalid_arguments", "Invalid BLE write", null)
            return
        }
        if (!pendingWrite.arm(result)) {
            result.error("operation_in_progress", "A BLE write is active", null)
            return
        }
        val started = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            currentGatt.writeCharacteristic(
                characteristic,
                value,
                BluetoothGattCharacteristic.WRITE_TYPE_DEFAULT,
            ) == BluetoothStatusCodes.SUCCESS
        } else {
            characteristic.writeType = BluetoothGattCharacteristic.WRITE_TYPE_DEFAULT
            characteristic.value = value
            currentGatt.writeCharacteristic(characteristic)
        }
        if (!started) {
            pendingWrite.fail("Unable to start BLE write")
        }
    }

    private fun disconnect(result: MethodChannel.Result) {
        closeGatt(emitDisconnected = true)
        result.success(null)
    }

    private val scanCallback =
        object : ScanCallback() {
            override fun onScanResult(callbackType: Int, result: ScanResult) {
                val name = result.scanRecord?.deviceName ?: runCatching { result.device.name }.getOrNull() ?: ""
                emitScan(
                    mapOf(
                        "connectionId" to result.device.address,
                        "name" to name,
                        "rssi" to result.rssi,
                    ),
                )
            }

            override fun onScanFailed(errorCode: Int) {
                main.post { scanSink?.error("scan_failed", "BLE scan failed", errorCode) }
            }
        }

    private val gattCallback =
        object : BluetoothGattCallback() {
            override fun onConnectionStateChange(gatt: BluetoothGatt, status: Int, newState: Int) {
                if (status == BluetoothGatt.GATT_SUCCESS && newState == BluetoothProfile.STATE_CONNECTED) {
                    if (!runCatching { gatt.discoverServices() }.getOrDefault(false)) {
                        failConnect("Unable to discover BLE services")
                    }
                    return
                }
                if (newState == BluetoothProfile.STATE_DISCONNECTED || status != BluetoothGatt.GATT_SUCCESS) {
                    failConnect("BLE connection closed")
                    closeGatt(emitDisconnected = true)
                }
            }

            override fun onServicesDiscovered(gatt: BluetoothGatt, status: Int) {
                if (status != BluetoothGatt.GATT_SUCCESS) {
                    failConnect("BLE service discovery failed")
                    return
                }
                val service = gatt.getService(expectedService)
                val request = service?.getCharacteristic(expectedRequestCharacteristic)
                val response = service?.getCharacteristic(expectedResponseCharacteristic)
                val descriptor = response?.getDescriptor(CLIENT_CONFIGURATION)
                if (request == null || response == null || descriptor == null ||
                    !runCatching { gatt.setCharacteristicNotification(response, true) }.getOrDefault(false)
                ) {
                    failConnect("PhoneAuth BLE characteristics are unavailable")
                    return
                }
                requestCharacteristic = request
                val started = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
                    runCatching {
                        gatt.writeDescriptor(descriptor, BluetoothGattDescriptor.ENABLE_NOTIFICATION_VALUE) ==
                            BluetoothStatusCodes.SUCCESS
                    }.getOrDefault(false)
                } else {
                    descriptor.value = BluetoothGattDescriptor.ENABLE_NOTIFICATION_VALUE
                    runCatching { gatt.writeDescriptor(descriptor) }.getOrDefault(false)
                }
                if (!started) failConnect("Unable to enable BLE notifications")
            }

            override fun onDescriptorWrite(gatt: BluetoothGatt, descriptor: BluetoothGattDescriptor, status: Int) {
                if (descriptor.uuid != CLIENT_CONFIGURATION) return
                if (status == BluetoothGatt.GATT_SUCCESS) {
                    takeConnect()?.let { result ->
                        main.removeCallbacks(connectTimeout)
                        main.post { result.success(null) }
                    }
                } else {
                    failConnect("Unable to enable BLE notifications")
                }
            }

            override fun onMtuChanged(gatt: BluetoothGatt, mtu: Int, status: Int) {
                pendingMtu.settle { result ->
                    main.post {
                        if (status == BluetoothGatt.GATT_SUCCESS) result.success(mtu)
                        else result.error("mtu_failed", "BLE MTU negotiation failed", null)
                    }
                }
            }

            override fun onCharacteristicWrite(
                gatt: BluetoothGatt,
                characteristic: BluetoothGattCharacteristic,
                status: Int,
            ) {
                pendingWrite.settle { result ->
                    main.post {
                        if (status == BluetoothGatt.GATT_SUCCESS) result.success(null)
                        else result.error("write_failed", "BLE write failed", null)
                    }
                }
            }

            override fun onCharacteristicChanged(
                gatt: BluetoothGatt,
                characteristic: BluetoothGattCharacteristic,
                value: ByteArray,
            ) {
                emitEvent(mapOf("type" to "notification", "value" to value.copyOf()))
            }

            @Deprecated("Deprecated by Android")
            override fun onCharacteristicChanged(
                gatt: BluetoothGatt,
                characteristic: BluetoothGattCharacteristic,
            ) {
                emitEvent(
                    mapOf(
                        "type" to "notification",
                        "value" to characteristic.value.copyOf(),
                    ),
                )
            }
        }

    /** Claims the connect reply, or false when one is already in flight. */
    private fun armConnect(result: MethodChannel.Result): Boolean =
        synchronized(connectLock) {
            if (pendingConnect != null) return false
            pendingConnect = result
            true
        }

    /** The connect reply, to exactly one caller. */
    private fun takeConnect(): MethodChannel.Result? =
        synchronized(connectLock) {
            val result = pendingConnect
            pendingConnect = null
            result
        }

    private fun failConnect(message: String) {
        val result = takeConnect() ?: return
        main.removeCallbacks(connectTimeout)
        main.post { result.error("connection_failed", message, null) }
    }

    private fun closeGatt(emitDisconnected: Boolean) {
        main.removeCallbacks(connectTimeout)
        takeConnect()?.let { result ->
            main.post { result.error("disconnected", "BLE disconnected", null) }
        }
        val current = gatt
        gatt = null
        requestCharacteristic = null
        runCatching { current?.disconnect() }
        runCatching { current?.close() }
        // Posted, not settled here: this runs from the GATT callback thread as
        // well as from the main one, and a reply has to go back on the main
        // looper.
        val disconnected = { result: MethodChannel.Result ->
            main.post { result.error("disconnected", "BLE disconnected", null) }
            Unit
        }
        pendingMtu.settle(disconnected)
        pendingWrite.settle(disconnected)
        if (emitDisconnected) emitEvent(mapOf("type" to "disconnected"))
    }

    private fun parseUuid(value: String?, result: MethodChannel.Result): UUID? =
        runCatching { UUID.fromString(value) }.getOrElse {
            result.error("invalid_arguments", "Invalid BLE UUID", null)
            null
        }

    private fun hasBlePermissions(): Boolean {
        val permissions = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
            arrayOf(Manifest.permission.BLUETOOTH_SCAN, Manifest.permission.BLUETOOTH_CONNECT)
        } else {
            arrayOf(Manifest.permission.ACCESS_FINE_LOCATION)
        }
        return permissions.all {
            ContextCompat.checkSelfPermission(context, it) == PackageManager.PERMISSION_GRANTED
        }
    }

    private fun requireBlePermissions(result: MethodChannel.Result): Boolean {
        if (hasBlePermissions()) return true
        result.error("permission_denied", "Bluetooth permission is required", null)
        return false
    }

    private fun emitScan(value: Any) = main.post { scanSink?.success(value) }

    private fun emitEvent(value: Any) = main.post { eventSink?.success(value) }

    fun dispose() {
        if (hasBlePermissions()) {
            runCatching { adapter?.bluetoothLeScanner?.stopScan(scanCallback) }
        }
        closeGatt(emitDisconnected = false)
        scanSink = null
        eventSink = null
    }

    companion object {
        private const val SCAN_CHANNEL = "phone_auth_native/ble_scan"
        private const val EVENT_CHANNEL = "phone_auth_native/ble_events"
        private const val CONNECT_TIMEOUT_MS = 15_000L

        // One GATT operation on a live link is milliseconds; this is sized to
        // sit well above the stack's own supervision timeout so it can only
        // fire for a callback that is never coming, never for a slow one.
        private const val OPERATION_TIMEOUT_MS = 10_000L
        private val CLIENT_CONFIGURATION = UUID.fromString("00002902-0000-1000-8000-00805f9b34fb")
    }
}
