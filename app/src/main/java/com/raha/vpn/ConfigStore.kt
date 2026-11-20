package com.raha.vpn

import android.content.Context
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.Base64
import java.nio.charset.StandardCharsets
import java.security.KeyStore
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

/**
 * Stores imported share links encrypted with an Android Keystore AES-GCM key.
 * Raw links may contain passwords and must never be written to logs.
 */
class ConfigStore(context: Context) {
    private val preferences = context.applicationContext.getSharedPreferences(
        "raha_secure_configs", Context.MODE_PRIVATE
    )

    @Synchronized
    fun load(): List<String> {
        return preferences.getStringSet(KEY_CONFIGS, emptySet())
            .orEmpty()
            .mapNotNull { encoded ->
                runCatching { decrypt(encoded) }.getOrNull()
            }
    }

    @Synchronized
    fun add(rawConfig: String) {
        val normalized = rawConfig.trim()
        require(isSupported(normalized)) { "Unsupported configuration scheme" }
        val current = preferences.getStringSet(KEY_CONFIGS, emptySet()).orEmpty().toMutableSet()
        val alreadySaved = current.any { encoded -> runCatching { decrypt(encoded) == normalized }.getOrDefault(false) }
        if (alreadySaved) return
        current.add(encrypt(normalized))
        check(preferences.edit().putStringSet(KEY_CONFIGS, current).commit()) {
            "Could not save configuration"
        }
    }

    @Synchronized
    fun remove(rawConfig: String) {
        val current = preferences.getStringSet(KEY_CONFIGS, emptySet()).orEmpty()
        val remaining = current.filterTo(mutableSetOf()) { encoded ->
            runCatching { decrypt(encoded) }.getOrNull() != rawConfig
        }
        preferences.edit().putStringSet(KEY_CONFIGS, remaining).apply()
    }

    private fun encrypt(value: String): String {
        val cipher = Cipher.getInstance(TRANSFORMATION)
        cipher.init(Cipher.ENCRYPT_MODE, getOrCreateKey())
        val encrypted = cipher.doFinal(value.toByteArray(StandardCharsets.UTF_8))
        return Base64.encodeToString(cipher.iv + encrypted, Base64.NO_WRAP)
    }

    private fun decrypt(encoded: String): String {
        val combined = Base64.decode(encoded, Base64.NO_WRAP)
        require(combined.size > IV_LENGTH)
        val iv = combined.copyOfRange(0, IV_LENGTH)
        val encrypted = combined.copyOfRange(IV_LENGTH, combined.size)
        val cipher = Cipher.getInstance(TRANSFORMATION)
        cipher.init(Cipher.DECRYPT_MODE, getOrCreateKey(), GCMParameterSpec(TAG_BITS, iv))
        return String(cipher.doFinal(encrypted), StandardCharsets.UTF_8)
    }

    private fun getOrCreateKey(): SecretKey {
        val keyStore = KeyStore.getInstance(ANDROID_KEY_STORE).apply { load(null) }
        (keyStore.getKey(KEY_ALIAS, null) as? SecretKey)?.let { return it }
        val generator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, ANDROID_KEY_STORE)
        generator.init(
            KeyGenParameterSpec.Builder(
                KEY_ALIAS,
                KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT
            )
                .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                .setRandomizedEncryptionRequired(true)
                .setKeySize(256)
                .build()
        )
        return generator.generateKey()
    }

    companion object {
        private const val KEY_CONFIGS = "encrypted_share_links"
        private const val KEY_ALIAS = "raha_vpn_config_key_v1"
        private const val ANDROID_KEY_STORE = "AndroidKeyStore"
        private const val TRANSFORMATION = "AES/GCM/NoPadding"
        private const val IV_LENGTH = 12
        private const val TAG_BITS = 128

        internal fun normalizeObfs4Bridge(value: String): String {
            val withoutBridgePrefix = value.trim()
                .replaceFirst(Regex("^Bridge\\s+", RegexOption.IGNORE_CASE), "")
                .trim()
            return withoutBridgePrefix.replaceFirst(
                Regex("^obfs4\\s+", RegexOption.IGNORE_CASE),
                "obfs4 "
            )
        }

        private const val MAX_CONFIG_CHARS = 128 * 1024

        fun isSupported(value: String): Boolean {
            if (value.length > MAX_CONFIG_CHARS) return false
            val normalized = normalizeObfs4Bridge(value)
            if (normalized.contains("[Interface]", ignoreCase = true) && normalized.contains("[Peer]", ignoreCase = true)) {
                return runCatching { SingBoxConfigBuilder.build(normalized); true }.getOrDefault(false)
            }
            if (normalized.startsWith("obfs4 ")) {
                val bridge = normalized.replaceFirst(Regex("^obfs4\\s+", RegexOption.IGNORE_CASE), "").trim()
                return Regex(
                    """^(?:\[[0-9a-fA-F:]+\]|[a-zA-Z0-9.-]+):[0-9]{1,5} [0-9a-fA-F]{40} cert=[A-Za-z0-9+/]+={0,2} iat-mode=[012]$"""
                ).matches(bridge) &&
                    run {
                        val endpoint = bridge.substringBefore(' ')
                        val portText = if (endpoint.startsWith("[")) {
                            endpoint.substringAfter("]:", "")
                        } else {
                            endpoint.substringAfterLast(':', "")
                        }
                        portText.toIntOrNull() in 1..65535
                    }
            }
            val scheme = normalized.substringBefore("://", "").lowercase()
            if (scheme !in setOf("vmess", "vless", "trojan", "ss", "hysteria2", "hy2", "tuic")) return false
            // Reject known schemes when the actual tunnel builder cannot parse the link.
            return runCatching { SingBoxConfigBuilder.build(normalized); true }.getOrDefault(false)
        }
    }
}
