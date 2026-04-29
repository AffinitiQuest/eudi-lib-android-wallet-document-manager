/*
 * Copyright (c) 2024-2025 European Commission
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package eu.europa.ec.eudi.wallet.document

import com.nimbusds.jose.jwk.JWK
import com.nimbusds.jose.util.Base64URL
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.Json
import org.multipaz.securearea.KeyUnlockData
import java.security.MessageDigest
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale
import java.util.TimeZone

private val BASE58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"

private fun base58Encode(input: ByteArray): String {
    var num = java.math.BigInteger(1, input)
    val sb = StringBuilder()
    val base = java.math.BigInteger.valueOf(58)
    while (num.signum() > 0) {
        val divRem = num.divideAndRemainder(base)
        sb.append(BASE58_ALPHABET[divRem[1].toInt()])
        num = divRem[0]
    }
    for (byte in input) {
        if (byte == 0.toByte()) sb.append(BASE58_ALPHABET[0]) else break
    }
    return sb.reverse().toString()
}

private fun JsonElement.sortedKeys(): JsonElement = when (this) {
    is JsonObject -> JsonObject(keys.sorted().associateWith { key -> getValue(key).sortedKeys() })
    is JsonArray -> JsonArray(map { it.sortedKeys() })
    else -> this
}

/**
 * Generates an LDP-VC Verifiable Presentation with an ecdsa-jcs-2019 Data Integrity proof.
 *
 * The signing input follows the ecdsa-jcs-2019 spec:
 *   SHA-256(JCS(proofOptions)) || SHA-256(JCS(vp))
 *
 * @param nonce The challenge value. For BLE: hex(SHA-256(sessionTranscript)). For OID4VP: request nonce.
 * @param aud The audience/domain string (e.g. "ble" for proximity, client_id for OID4VP).
 * @param keyUnlockData Optional key unlock data if the credential key is protected.
 * @return The signed VP JSON string.
 */
suspend fun IssuedDocument.generateLdpVcVp(
    nonce: String,
    aud: String,
    keyUnlockData: KeyUnlockData? = null
): String {
    val credential = findCredential() ?: throw IllegalStateException("No credential found")
    val ecPublicKey = credential.secureArea.getKeyInfo(credential.alias).publicKey
    val jwkJson = (JWK.parseFromPEMEncodedObjects(ecPublicKey.toPem()) as JWK).toJSONString()
    val holderDid = "did:jwk:${Base64URL.encode(jwkJson.encodeToByteArray())}#0"

    val rawVcJson = String(credential.issuerProvidedData)
    val credentialJson = Json.parseToJsonElement(rawVcJson).sortedKeys()

    val now = SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss'Z'", Locale.US).run {
        timeZone = TimeZone.getTimeZone("UTC")
        format(Date())
    }

    val vp = JsonObject(sortedMapOf(
        "@context" to JsonArray(listOf(JsonPrimitive("https://www.w3.org/2018/credentials/v1"))),
        "type" to JsonArray(listOf(JsonPrimitive("VerifiablePresentation"))),
        "verifiableCredential" to JsonArray(listOf(credentialJson))
    ))

    val proofOptions = JsonObject(sortedMapOf(
        "challenge" to JsonPrimitive(nonce),
        "created" to JsonPrimitive(now),
        "cryptosuite" to JsonPrimitive("ecdsa-jcs-2019"),
        "domain" to JsonPrimitive(aud),
        "proofPurpose" to JsonPrimitive("authentication"),
        "type" to JsonPrimitive("DataIntegrityProof"),
        "verificationMethod" to JsonPrimitive(holderDid)
    ))

    val sha256 = MessageDigest.getInstance("SHA-256")
    val proofHash = sha256.digest(proofOptions.toString().encodeToByteArray())
    sha256.reset()
    val vpHash = sha256.digest(vp.toString().encodeToByteArray())
    val signingInput = proofHash + vpHash

    val signatureBytes = signConsumingCredential(signingInput, keyUnlockData).getOrThrow().toCoseEncoded()
    val proofValue = "z" + base58Encode(signatureBytes)

    val proof = JsonObject(sortedMapOf(
        "challenge" to JsonPrimitive(nonce),
        "created" to JsonPrimitive(now),
        "cryptosuite" to JsonPrimitive("ecdsa-jcs-2019"),
        "domain" to JsonPrimitive(aud),
        "proofPurpose" to JsonPrimitive("authentication"),
        "proofValue" to JsonPrimitive(proofValue),
        "type" to JsonPrimitive("DataIntegrityProof"),
        "verificationMethod" to JsonPrimitive(holderDid)
    ))

    val vpWithProof = JsonObject(sortedMapOf(
        "@context" to JsonArray(listOf(JsonPrimitive("https://www.w3.org/2018/credentials/v1"))),
        "proof" to proof,
        "type" to JsonArray(listOf(JsonPrimitive("VerifiablePresentation"))),
        "verifiableCredential" to JsonArray(listOf(credentialJson))
    ))

    return vpWithProof.toString()
}
