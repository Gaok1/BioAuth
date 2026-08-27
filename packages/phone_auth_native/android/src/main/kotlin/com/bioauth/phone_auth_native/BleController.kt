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
    private var gatt: BluetoothGatt? = null
    private var requestCharacteristic: BluetoothGattCharacteristic? = null
    private var pendingConnect: MethodChannel.Result? = null
    private var pendingMtu: MethodChannel.Result? = null
    private var pendingWrite: MethodChannel.Result? = null
    private var expectedService: UUID? = null
    private var expectedRequestCharacteristic: UUID? = null
    private var expectedResponseCharacteristic: UUID? = null
    private val connectTimeout = Runnable {
        if (pendingConnect != null) {
            failConnect("BLE connection timed out")
            closeGatt(emitDisconnected = true)
        }
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

        pendingConnect = result
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
        if (pendingMtu != null) {
            result.error("operation_in_progress", "An MTU request is active", null)
            return
        }
        pendingMtu = result
        if (!currentGatt.requestMtu(requested)) {
            pendingMtu = null
            result.error("mtu_failed", "Unable to request BLE MTU", null)
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
        if (pendingWrite != null) {
            result.error("operation_in_progress", "A BLE write is active", null)
            return
        }
        pendingWrite = result
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
            pendingWrite = null
            result.error("write_failed", "Unable to start BLE write", null)
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
                    finishResult(pendingConnect) { pendingConnect = null }
                } else {
                    failConnect("Unable to enable BLE notifications")
                }
            }

            override fun onMtuChanged(gatt: BluetoothGatt, mtu: Int, status: Int) {
                val result = pendingMtu ?: return
                pendingMtu = null
                main.post {
                    if (status == BluetoothGatt.GATT_SUCCESS) result.success(mtu)
                    else result.error("mtu_failed", "BLE MTU negotiation failed", null)
                }
            }

            override fun onCharacteristicWrite(
                gatt: BluetoothGatt,
                characteristic: BluetoothGattCharacteristic,
                status: Int,
            ) {
                val result = pendingWrite ?: return
                pendingWrite = null
                main.post {
                    if (status == BluetoothGatt.GATT_SUCCESS) result.success(null)
                    else result.error("write_failed", "BLE write failed", null)
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

    private fun failConnect(message: String) {
        val result = pendingConnect ?: return
        pendingConnect = null
        main.removeCallbacks(connectTimeout)
        main.post { result.error("connection_failed", message, null) }
    }

    private fun finishResult(result: MethodChannel.Result?, clear: () -> Unit) {
        if (result == null) return
        clear()
        main.removeCallbacks(connectTimeout)
        main.post { result.success(null) }
    }

    private fun closeGatt(emitDisconnected: Boolean) {
        main.removeCallbacks(connectTimeout)
        pendingConnect?.let {
            main.post { it.error("disconnected", "BLE disconnected", null) }
        }
        pendingConnect = null
        val current = gatt
        gatt = null
        requestCharacteristic = null
        runCatching { current?.disconnect() }
        runCatching { current?.close() }
        pendingMtu?.let { main.post { it.error("disconnected", "BLE disconnected", null) } }
        pendingWrite?.let { main.post { it.error("disconnected", "BLE disconnected", null) } }
        pendingMtu = null
        pendingWrite = null
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
        private val CLIENT_CONFIGURATION = UUID.fromString("00002902-0000-1000-8000-00805f9b34fb")
    }
}
