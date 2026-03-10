package com.cyberspy.app.network

import android.content.Context
import android.content.SharedPreferences

/**
 * AppPreferences — Stores user settings locally using SharedPreferences.
 *
 * Currently stores:
 * - Backend server URL (entered by the user in the Settings screen)
 */
object AppPreferences {

    private const val PREFS_NAME = "cyberspy_prefs"
    private const val KEY_BACKEND_URL = "backend_url"
    private const val KEY_VICTIM_STATE = "victim_state"

    // Default: localhost for emulator, user updates for real device
    private const val DEFAULT_URL = "http://10.0.2.2:8000"

    private fun prefs(context: Context): SharedPreferences =
        context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)

    fun getBackendUrl(context: Context): String =
        prefs(context).getString(KEY_BACKEND_URL, DEFAULT_URL) ?: DEFAULT_URL

    fun setBackendUrl(context: Context, url: String) {
        prefs(context).edit().putString(KEY_BACKEND_URL, url.trimEnd('/')).apply()
    }

    fun getVictimState(context: Context): String =
        prefs(context).getString(KEY_VICTIM_STATE, "KA") ?: "KA"

    fun setVictimState(context: Context, state: String) {
        prefs(context).edit().putString(KEY_VICTIM_STATE, state.uppercase()).apply()
    }
}
