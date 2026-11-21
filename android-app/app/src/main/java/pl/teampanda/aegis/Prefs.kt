package pl.teampanda.aegis

import android.content.Context

/** Ustawienia: adres serwera, token czujnika (rola "sensor") i biezace miejsce z kodu QR. */
class Prefs(ctx: Context) {
    private val p = ctx.getSharedPreferences("aegis", Context.MODE_PRIVATE)

    var serverUrl: String
        get() = p.getString("server", "") ?: ""
        set(v) = p.edit().putString("server", v.trimEnd('/')).apply()

    var token: String
        get() = p.getString("token", "") ?: ""
        set(v) = p.edit().putString("token", v.trim()).apply()

    var sensorId: String
        get() = p.getString("sensor", "PHONE-APK-01") ?: "PHONE-APK-01"
        set(v) = p.edit().putString("sensor", v).apply()

    var building: String
        get() = p.getString("b", "") ?: ""
        set(v) = p.edit().putString("b", v).apply()
    var floor: String
        get() = p.getString("f", "") ?: ""
        set(v) = p.edit().putString("f", v).apply()
    var room: String
        get() = p.getString("r", "") ?: ""
        set(v) = p.edit().putString("r", v).apply()
    var locationSetAt: Long
        get() = p.getLong("locAt", 0)
        set(v) = p.edit().putLong("locAt", v).apply()

    val configured get() = serverUrl.startsWith("http") && token.isNotBlank()
}
