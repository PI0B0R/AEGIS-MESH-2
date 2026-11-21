package pl.teampanda.aegis

import android.Manifest
import android.annotation.SuppressLint
import android.content.Intent
import android.content.pm.PackageManager
import android.graphics.Color
import android.net.Uri
import android.net.wifi.WifiManager
import android.os.Build
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.text.InputType
import android.view.Gravity
import android.view.ViewGroup.LayoutParams.MATCH_PARENT
import android.view.ViewGroup.LayoutParams.WRAP_CONTENT
import android.webkit.GeolocationPermissions
import android.webkit.WebChromeClient
import android.webkit.WebView
import android.webkit.WebViewClient
import android.widget.Button
import android.widget.EditText
import android.widget.LinearLayout
import android.widget.TextView
import android.widget.Toast
import androidx.appcompat.app.AlertDialog
import androidx.appcompat.app.AppCompatActivity
import androidx.core.app.ActivityCompat
import androidx.core.content.ContextCompat

/** Terminal operatora: pasek sterowania + dashboard AEGIS-MESH w WebView. */
class MainActivity : AppCompatActivity() {
    private lateinit var prefs: Prefs
    private lateinit var web: WebView
    private lateinit var status: TextView
    private lateinit var toggle: Button
    private val ui = Handler(Looper.getMainLooper())

    private val refresh = object : Runnable {
        override fun run() {
            val loc = if (prefs.building.isNotBlank()) " · ${prefs.building} p.${prefs.floor} s.${prefs.room}" else " · miejsce: brak (zeskanuj QR)"
            status.text = "Telemetria: ${TelemetryService.lastStatus}$loc"
            toggle.text = if (TelemetryService.running) "Stop" else "Start"
            ui.postDelayed(this, 2000)
        }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        prefs = Prefs(this)
        val root = LinearLayout(this).apply { orientation = LinearLayout.VERTICAL }
        val bar = LinearLayout(this).apply { orientation = LinearLayout.HORIZONTAL; setPadding(12, 12, 12, 4); gravity = Gravity.CENTER_VERTICAL }
        toggle = Button(this).apply { text = "Start"; setOnClickListener { toggleTelemetry() } }
        val settings = Button(this).apply { text = "Ustawienia"; setOnClickListener { showSettings() } }
        val hunt = Button(this).apply { text = "Ciepło-zimno"; setOnClickListener { askHunt() } }
        val place = Button(this).apply { text = "Sala"; setOnClickListener { askRoom() } }
        listOf(toggle, settings, hunt, place).forEach { bar.addView(it, LinearLayout.LayoutParams(0, WRAP_CONTENT, 1f)) }
        status = TextView(this).apply { setPadding(16, 0, 16, 8); textSize = 12f }
        web = WebView(this)
        root.addView(bar); root.addView(status)
        root.addView(web, LinearLayout.LayoutParams(MATCH_PARENT, 0, 1f))
        setContentView(root)
        setupWeb()
        requestPerms()
        handleDeepLink(intent)
        if (!prefs.configured) showSettings() else web.loadUrl(prefs.serverUrl)
        ui.post(refresh)
    }

    override fun onNewIntent(intent: Intent) {
        super.onNewIntent(intent)
        handleDeepLink(intent)
    }

    /** aegis://loc?b=B1&f=2&r=204 z kodu QR na drzwiach sali. */
    private fun handleDeepLink(i: Intent?) {
        val u: Uri = i?.data ?: return
        if (u.scheme == "aegis" && u.host == "loc") {
            setRoom(u.getQueryParameter("b") ?: "", u.getQueryParameter("f") ?: "", u.getQueryParameter("r") ?: "")
        }
    }

    private fun setRoom(b: String, f: String, r: String) {
        prefs.building = b; prefs.floor = f; prefs.room = r
        prefs.locationSetAt = System.currentTimeMillis()
        Toast.makeText(this, "Miejsce pomiaru: $b, piętro $f, sala $r", Toast.LENGTH_SHORT).show()
    }

    @SuppressLint("SetJavaScriptEnabled")
    private fun setupWeb() {
        web.settings.javaScriptEnabled = true
        web.settings.domStorageEnabled = true
        web.settings.setGeolocationEnabled(true)
        web.webViewClient = WebViewClient()
        web.webChromeClient = object : WebChromeClient() {
            override fun onGeolocationPermissionsShowPrompt(origin: String, cb: GeolocationPermissions.Callback) {
                cb.invoke(origin, true, false)
            }
        }
    }

    private fun requestPerms() {
        val perms = mutableListOf(Manifest.permission.ACCESS_FINE_LOCATION, Manifest.permission.ACCESS_COARSE_LOCATION)
        if (Build.VERSION.SDK_INT >= 33) {
            perms += Manifest.permission.NEARBY_WIFI_DEVICES
            perms += Manifest.permission.POST_NOTIFICATIONS
        }
        val missing = perms.filter { ContextCompat.checkSelfPermission(this, it) != PackageManager.PERMISSION_GRANTED }
        if (missing.isNotEmpty()) ActivityCompat.requestPermissions(this, missing.toTypedArray(), 1)
    }

    private fun toggleTelemetry() {
        val svc = Intent(this, TelemetryService::class.java)
        if (TelemetryService.running) { stopService(svc); return }
        if (!prefs.configured) { showSettings(); return }
        if (ContextCompat.checkSelfPermission(this, Manifest.permission.ACCESS_FINE_LOCATION) != PackageManager.PERMISSION_GRANTED) {
            requestPerms(); return
        }
        ContextCompat.startForegroundService(this, svc)
    }

    private fun field(hint: String, value: String, password: Boolean = false) = EditText(this).apply {
        this.hint = hint; setText(value)
        if (password) inputType = InputType.TYPE_CLASS_TEXT or InputType.TYPE_TEXT_VARIATION_PASSWORD
    }

    private fun showSettings() {
        val url = field("https://<serwer> lub http://192.168.x.x:8000", prefs.serverUrl)
        val token = field("token API czujnika (rola sensor)", prefs.token, password = true)
        val sensor = field("ID czujnika", prefs.sensorId)
        val box = LinearLayout(this).apply { orientation = LinearLayout.VERTICAL; setPadding(40, 20, 40, 0); addView(url); addView(token); addView(sensor) }
        AlertDialog.Builder(this).setTitle("Połączenie z AEGIS-MESH").setView(box)
            .setPositiveButton("Zapisz") { _, _ ->
                prefs.serverUrl = url.text.toString(); prefs.token = token.text.toString(); prefs.sensorId = sensor.text.toString()
                if (prefs.configured) web.loadUrl(prefs.serverUrl)
            }.setNegativeButton("Anuluj", null).show()
    }

    private fun askRoom() {
        val b = field("budynek", prefs.building); val f = field("piętro", prefs.floor); val r = field("sala", prefs.room)
        val box = LinearLayout(this).apply { orientation = LinearLayout.VERTICAL; setPadding(40, 20, 40, 0); addView(b); addView(f); addView(r) }
        AlertDialog.Builder(this).setTitle("Miejsce pomiaru (albo zeskanuj QR aparatem)").setView(box)
            .setPositiveButton("Ustaw") { _, _ -> setRoom(b.text.toString(), f.text.toString(), r.text.toString()) }
            .setNegativeButton("Anuluj", null).show()
    }

    /** Tryb ciepło-zimno: wybrany BSSID, siła sygnału na żywo, idziemy tam, gdzie rośnie. */
    private fun askHunt() {
        val b = field("BSSID, np. de:ad:be:ef:00:10", "")
        AlertDialog.Builder(this).setTitle("Szukaj urządzenia").setView(b)
            .setPositiveButton("Szukaj") { _, _ -> hunt(b.text.toString().trim().lowercase()) }.show()
    }

    private fun hunt(bssid: String) {
        if (!TelemetryService.running) toggleTelemetry()
        val big = TextView(this).apply { textSize = 48f; gravity = Gravity.CENTER; setPadding(0, 40, 0, 10) }
        val hint = TextView(this).apply { textSize = 18f; gravity = Gravity.CENTER; setPadding(0, 0, 0, 40) }
        val box = LinearLayout(this).apply { orientation = LinearLayout.VERTICAL; addView(big); addView(hint) }
        val wifi = applicationContext.getSystemService(WIFI_SERVICE) as WifiManager
        var prev: Int? = null
        val tick = object : Runnable {
            @SuppressLint("MissingPermission")
            override fun run() {
                @Suppress("DEPRECATION") wifi.startScan()
                runCatching { wifi.scanResults }.getOrNull()?.forEach { TelemetryService.lastRssi[it.BSSID.lowercase()] = it.level }
                val now = TelemetryService.lastRssi[bssid]
                if (now == null) { big.text = "—"; hint.text = "brak sygnału" }
                else {
                    big.text = "$now dBm"
                    val color = when { now > -50 -> Color.rgb(200, 40, 40); now > -65 -> Color.rgb(220, 120, 20); now > -75 -> Color.rgb(200, 170, 20); else -> Color.rgb(40, 90, 200) }
                    big.setTextColor(color)
                    hint.text = when { prev == null -> "idź powoli i obserwuj"; now > prev!! + 2 -> "cieplej ↑"; now < prev!! - 2 -> "zimniej ↓"; else -> "bez zmian" }
                    prev = now
                }
                ui.postDelayed(this, 3000)
            }
        }
        val dlg = AlertDialog.Builder(this).setTitle(bssid).setView(box).setPositiveButton("Koniec", null).create()
        dlg.setOnDismissListener { ui.removeCallbacks(tick) }
        dlg.show()
        ui.post(tick)
        Toast.makeText(this, "Wskazówka: wyłącz 'ograniczanie skanowania Wi-Fi' w opcjach programisty", Toast.LENGTH_LONG).show()
    }

    @Deprecated("Deprecated in Java")
    @Suppress("DEPRECATION")
    override fun onBackPressed() {
        if (web.canGoBack()) web.goBack() else super.onBackPressed()
    }
}
