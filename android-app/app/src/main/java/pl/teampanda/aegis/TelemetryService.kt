package pl.teampanda.aegis

import android.annotation.SuppressLint
import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.Service
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.content.pm.ServiceInfo
import android.location.Location
import android.location.LocationManager
import android.net.wifi.ScanResult
import android.net.wifi.WifiManager
import android.os.Build
import android.os.Handler
import android.os.IBinder
import android.os.Looper
import android.os.SystemClock
import org.json.JSONArray
import org.json.JSONObject
import java.io.File
import java.net.HttpURLConnection
import java.net.URL
import java.util.concurrent.Executors

/**
 * Foreground Service typu "location": dziala przy zgaszonym ekranie.
 * Android pozwala na 4 skany Wi-Fi na 2 minuty (aplikacja na ekranie), dlatego skanujemy co 30 s
 * i wysylamy tylko wyniki nowsze niz poprzednia wysylka (ScanResult.timestamp).
 * Brak sieci = pomiary trafiaja do kolejki offline i wysylaja sie pozniej.
 */
class TelemetryService : Service() {
    companion object {
        const val SCAN_INTERVAL_MS = 30_000L
        const val CHANNEL = "aegis"
        @Volatile var running = false
        @Volatile var lastStatus = "zatrzymany"
        /** Ostatnie RSSI per BSSID dla trybu ciepło-zimno. */
        val lastRssi = java.util.concurrent.ConcurrentHashMap<String, Int>()
    }

    private val main = Handler(Looper.getMainLooper())
    private val io = Executors.newSingleThreadExecutor()
    private lateinit var wifi: WifiManager
    private lateinit var prefs: Prefs
    private var lastSentScanMicros = 0L
    private val queueFile by lazy { File(filesDir, "offline_queue.jsonl") }

    private val receiver = object : BroadcastReceiver() {
        override fun onReceive(c: Context, i: Intent) = collectAndSend()
    }

    private val loop = object : Runnable {
        override fun run() {
            // startScan() moze zwrocic false (throttling) - i tak czytamy scanResults
            @Suppress("DEPRECATION")
            if (!wifi.startScan()) collectAndSend()
            main.postDelayed(this, SCAN_INTERVAL_MS)
        }
    }

    override fun onCreate() {
        super.onCreate()
        wifi = applicationContext.getSystemService(Context.WIFI_SERVICE) as WifiManager
        prefs = Prefs(this)
        val nm = getSystemService(NotificationManager::class.java)
        nm.createNotificationChannel(NotificationChannel(CHANNEL, "Aegis telemetria", NotificationManager.IMPORTANCE_LOW))
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        val n = Notification.Builder(this, CHANNEL)
            .setContentTitle("Aegis: skan Wi-Fi aktywny")
            .setContentText("Pomiary co 30 s do ${prefs.serverUrl}")
            .setSmallIcon(android.R.drawable.ic_menu_mylocation)
            .setOngoing(true).build()
        if (Build.VERSION.SDK_INT >= 29) startForeground(1, n, ServiceInfo.FOREGROUND_SERVICE_TYPE_LOCATION)
        else startForeground(1, n)
        if (!running) {
            running = true
            registerReceiver(receiver, IntentFilter(WifiManager.SCAN_RESULTS_AVAILABLE_ACTION))
            main.post(loop)
        }
        return START_STICKY
    }

    override fun onDestroy() {
        running = false
        lastStatus = "zatrzymany"
        main.removeCallbacks(loop)
        runCatching { unregisterReceiver(receiver) }
        super.onDestroy()
    }

    override fun onBind(intent: Intent?): IBinder? = null

    @SuppressLint("MissingPermission")
    private fun bestLocation(): Location? {
        val lm = getSystemService(Context.LOCATION_SERVICE) as LocationManager
        return listOf(LocationManager.GPS_PROVIDER, LocationManager.NETWORK_PROVIDER)
            .mapNotNull { runCatching { lm.getLastKnownLocation(it) }.getOrNull() }
            .maxByOrNull { it.time }
    }

    @SuppressLint("MissingPermission")
    private fun collectAndSend() {
        val results: List<ScanResult> = runCatching { wifi.scanResults }.getOrDefault(emptyList())
        results.forEach { lastRssi[it.BSSID.lowercase()] = it.level }
        val fresh = results.filter { it.timestamp > lastSentScanMicros }
        if (fresh.isEmpty()) { lastStatus = "brak nowych wynikow (limit skanow Androida)"; return }
        lastSentScanMicros = fresh.maxOf { it.timestamp }
        val bootWallMs = System.currentTimeMillis() - SystemClock.elapsedRealtime()

        val networks = JSONArray()
        fresh.forEach { r ->
            networks.put(JSONObject().apply {
                @Suppress("DEPRECATION")
                put("ssid", r.SSID ?: "")
                put("bssid", r.BSSID)
                put("rssi_dbm", r.level)
                put("frequency_mhz", r.frequency)
                put("channel", freqToChannel(r.frequency))
                put("security", r.capabilities)
                put("timestamp", (bootWallMs + r.timestamp / 1000) / 1000.0)
            })
        }
        val loc = JSONObject()
        bestLocation()?.let {
            loc.put("lat", it.latitude); loc.put("lng", it.longitude)
            loc.put("accuracy", it.accuracy.toDouble()); loc.put("time", it.time)
        }
        // miejsce z kodu QR jest wazne 30 minut (potem trzeba zeskanowac kolejna sale)
        val qrValid = System.currentTimeMillis() - prefs.locationSetAt < 30 * 60_000
        if (qrValid && prefs.building.isNotBlank()) {
            loc.put("building", prefs.building); loc.put("floor", prefs.floor); loc.put("room", prefs.room)
            loc.put("source", "qr")
        } else loc.put("source", "gps")

        val payload = JSONObject().apply {
            put("sensor_id", prefs.sensorId); put("location", loc); put("networks", networks)
        }.toString()
        io.execute { send(payload, fresh.size) }
    }

    private fun send(payload: String, count: Int) {
        val pending = mutableListOf<String>()
        if (queueFile.exists()) pending += queueFile.readLines().filter { it.isNotBlank() }
        pending += payload
        val failed = mutableListOf<String>()
        var lastCode = 0
        for (p in pending) {
            lastCode = runCatching { post(p) }.getOrDefault(-1)
            if (lastCode !in 200..299) failed += p
        }
        queueFile.writeText(failed.takeLast(500).joinToString("\n"))
        lastStatus = if (failed.isEmpty()) "wyslano $count AP (HTTP $lastCode)"
        else "offline: ${failed.size} paczek w kolejce (HTTP $lastCode)"
    }

    private fun post(body: String): Int {
        val c = URL("${prefs.serverUrl}/api/mobile-telemetry").openConnection() as HttpURLConnection
        c.requestMethod = "POST"
        c.connectTimeout = 8000; c.readTimeout = 15000
        c.doOutput = true
        c.setRequestProperty("Content-Type", "application/json")
        c.setRequestProperty("Authorization", "Bearer ${prefs.token}")
        c.outputStream.use { it.write(body.toByteArray()) }
        val code = c.responseCode
        c.disconnect()
        return code
    }

    private fun freqToChannel(f: Int): Int = when (f) {
        in 2412..2472 -> (f - 2407) / 5
        2484 -> 14
        in 5150..5895 -> (f - 5000) / 5
        in 5955..7115 -> (f - 5950) / 5
        else -> 0
    }
}
