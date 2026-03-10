package com.cyberspy.app.network

import android.content.Context
import com.google.gson.Gson
import com.google.gson.GsonBuilder
import okhttp3.MultipartBody
import okhttp3.OkHttpClient
import okhttp3.RequestBody
import okhttp3.logging.HttpLoggingInterceptor
import retrofit2.Response
import retrofit2.Retrofit
import retrofit2.converter.gson.GsonConverterFactory
import retrofit2.http.*
import java.util.concurrent.TimeUnit

// ============================================================
//  DATA CLASSES (matching the backend Pydantic schemas)
// ============================================================

data class DeviceRegisterRequest(
    val device_id: String,
    val device_fingerprint: String,
    val device_model: String,
    val android_version: String,
)

data class DeviceRegisterResponse(
    val access_token: String,
    val token_type: String,
    val device_id: String,
    val expires_in_hours: Int,
)

data class EvidenceSubmitResponse(
    val case_id: String,
    val status: String,
    val evidence_hash: String,
    val message: String,
)

data class CaseStatusResponse(
    val case_id: String,
    val status: String,
    val threat_level: String?,
    val summary: String?,
    val authority_crn: String?,
    val dispatched_to: String?,
)

data class ThreatSnapshot(
    val threat_level: String,
    val summary: String,
    val iocs: List<IOC>,
    val attack_type: String,
    val confidence: Float,
)

data class IOC(
    val type: String,
    val value: String,
    val note: String,
)

// ============================================================
//  RETROFIT API INTERFACE
// ============================================================

interface CyberSpyApi {

    @POST("api/v1/auth/device-register")
    suspend fun registerDevice(
        @Body request: DeviceRegisterRequest,
    ): Response<DeviceRegisterResponse>

    @Multipart
    @POST("api/v1/evidence/submit")
    suspend fun submitEvidence(
        @Header("Authorization") bearerToken: String,
        @Part evidenceFile: MultipartBody.Part,
        @Part("device_logs") deviceLogs: RequestBody,
        @Part("victim_state") victimState: RequestBody,
    ): Response<EvidenceSubmitResponse>

    @GET("api/v1/case/{case_id}/status")
    suspend fun getCaseStatus(
        @Header("Authorization") bearerToken: String,
        @Path("case_id") caseId: String,
    ): Response<CaseStatusResponse>

    @GET("health")
    suspend fun healthCheck(): Response<Map<String, String>>
}

// ============================================================
//  RETROFIT CLIENT FACTORY
// ============================================================

object ApiClient {

    private var baseUrl: String = "http://10.0.2.2:8000"
    private var retrofit: Retrofit? = null
    private var api: CyberSpyApi? = null

    private val gson: Gson = GsonBuilder().setLenient().create()

    private fun buildClient(): OkHttpClient {
        val logging = HttpLoggingInterceptor().apply {
            level = HttpLoggingInterceptor.Level.BODY
        }
        return OkHttpClient.Builder()
            .connectTimeout(15, TimeUnit.SECONDS)
            .readTimeout(30, TimeUnit.SECONDS)
            .writeTimeout(30, TimeUnit.SECONDS)
            .addInterceptor(logging)
            .build()
    }

    /**
     * Initialize the client with the user's configured backend URL.
     * Call this at app start and whenever the URL changes.
     */
    fun initialize(context: Context) {
        val url = AppPreferences.getBackendUrl(context)
        if (url != baseUrl || retrofit == null) {
            baseUrl = if (url.endsWith("/")) url else "$url/"
            retrofit = Retrofit.Builder()
                .baseUrl(baseUrl)
                .client(buildClient())
                .addConverterFactory(GsonConverterFactory.create(gson))
                .build()
            api = retrofit!!.create(CyberSpyApi::class.java)
        }
    }

    fun getApi(context: Context): CyberSpyApi {
        if (api == null) initialize(context)
        return api!!
    }
}
