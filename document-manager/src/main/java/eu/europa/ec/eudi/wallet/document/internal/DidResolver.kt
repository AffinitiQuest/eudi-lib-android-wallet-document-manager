package eu.europa.ec.eudi.wallet.document.internal

import eu.europa.ec.eudi.sdjwt.vc.KtorHttpClientFactory
import io.ktor.client.*
import io.ktor.client.request.*
import io.ktor.client.statement.*
import io.ktor.http.*
import java.security.KeyFactory
import java.security.PublicKey
import java.security.spec.X509EncodedKeySpec
import java.util.Base64
import kotlinx.serialization.*
import kotlinx.serialization.json.*
import org.multipaz.crypto.EcCurve
import java.security.interfaces.ECPublicKey

@Serializable
data class DidDocument(
    val id: String,
    val verificationMethod: List<VerificationMethod>
)

@Serializable
data class VerificationMethod(
    val id: String,
    val type: String,
    val controller: String,
    val publicKeyJwk: JsonObject? = null,
    val publicKeyMultibase: String? = null
)

/**
 * Determines the EcCurve enum value from a Java PublicKey
 * Note: This assumes multipaz EcCurve includes Ed25519 support
 */
fun PublicKey.getEcCurveOrNull(): EcCurve? {
    return when {
        this.algorithm == "Ed25519" -> {
            // Ed25519 is COSE curve 6
            // Check if EcCurve.ED25519 or similar exists
            EcCurve.entries.find { it.coseCurveIdentifier == 6 }
        }
        this is ECPublicKey -> {
            val fieldSize = this.params.curve.field.fieldSize
            val a = this.params.curve.a

            when (fieldSize) {
                256 -> EcCurve.entries.find { it.coseCurveIdentifier == 1 } // P-256
                384 -> EcCurve.entries.find { it.coseCurveIdentifier == 2 } // P-384
                521 -> EcCurve.entries.find { it.coseCurveIdentifier == 3 } // P-521
                else -> null
            }
        }
        else -> null
    }
}

fun PublicKey.getEcCurve(): EcCurve {
    return getEcCurveOrNull()
        ?: throw IllegalArgumentException("Unsupported key type or curve: ${this.algorithm}")
}

class DidKeyResolver(
    private var ktorHttpClientFactory: KtorHttpClientFactory = { HttpClient() }
) {
    private val json = Json { ignoreUnknownKeys = true }

    /**
     * Resolves a public key from a JWT KID that can be either did:key or did:web
     */
    suspend fun resolvePublicKey(kid: String): PublicKey {
        return when {
            kid.startsWith("did:key:") -> resolveDidKey(kid)
            kid.startsWith("did:web:") -> resolveDidWeb(kid)
            else -> throw IllegalArgumentException("Unsupported DID method: $kid")
        }
    }

    /**
     * Resolves a did:key DID to a public key
     * Format: did:key:z6Mk... (multibase encoded public key)
     */
    private fun resolveDidKey(kid: String): PublicKey {
        val didParts = kid.split("#")
        val did = didParts[0]

        // Extract the multibase encoded key (after "did:key:")
        val multibaseKey = did.removePrefix("did:key:")

        if (!multibaseKey.startsWith("z")) {
            throw IllegalArgumentException("Expected base58btc encoding (starting with 'z')")
        }

        // Decode base58btc (z prefix)
        val decoded = decodeBase58(multibaseKey.substring(1))

        // For Ed25519 keys, the multicodec prefix is 0xed01
        // For P-256 keys, the multicodec prefix is 0x1200
        // For secp256k1 keys, the multicodec prefix is 0xe701

        val (keyType, publicKeyBytes) = when {
            decoded.size > 2 && decoded[0] == 0xed.toByte() && decoded[1] == 0x01.toByte() -> {
                "Ed25519" to decoded.drop(2).toByteArray()
            }
            decoded.size > 2 && decoded[0] == 0x12.toByte() && decoded[1] == 0x00.toByte() -> {
                "EC" to decoded.drop(2).toByteArray()
            }
            decoded.size > 2 && decoded[0] == 0xe7.toByte() && decoded[1] == 0x01.toByte() -> {
                "EC" to decoded.drop(2).toByteArray()
            }
            else -> throw IllegalArgumentException("Unsupported multicodec prefix")
        }

        return when (keyType) {
            "Ed25519" -> {
                // Ed25519 public key - need to wrap in X.509 format
                val x509Bytes = wrapEd25519PublicKey(publicKeyBytes)
                val keySpec = X509EncodedKeySpec(x509Bytes)
                KeyFactory.getInstance("Ed25519").generatePublic(keySpec)
            }
            "EC" -> {
                // EC public key
                val x509Bytes = wrapECPublicKey(publicKeyBytes)
                val keySpec = X509EncodedKeySpec(x509Bytes)
                KeyFactory.getInstance("EC").generatePublic(keySpec)
            }
            else -> throw IllegalArgumentException("Unsupported key type: $keyType")
        }
    }

    /**
     * Resolves a did:web DID to a public key
     * Format: did:web:example.com[:path][:to][:did.json][#key-id]
     */
    private suspend fun resolveDidWeb(kid: String): PublicKey {
        val didParts = kid.split("#")
        val did = didParts[0]
        val fragment = didParts.getOrNull(1)

        // Convert DID to HTTPS URL
        val url = didWebToUrl(did)

        // Fetch the DID document
        val response: HttpResponse = ktorHttpClientFactory().get(url) {
            headers {
                append(HttpHeaders.Accept, "application/did+json, application/json")
            }
        }

        if (response.status != HttpStatusCode.OK) {
            throw RuntimeException("Failed to fetch DID document: ${response.status}")
        }

        val responseBody = response.bodyAsText()
        val didDocument = json.decodeFromString<DidDocument>(responseBody)

        // Find the verification method
        val verificationMethodId = fragment?.let { "$did#$it" } ?: didDocument.verificationMethod.firstOrNull()?.id
        ?: throw IllegalArgumentException("No verification method found")

        val verificationMethod = didDocument.verificationMethod.find { it.id == verificationMethodId }
            ?: throw IllegalArgumentException("Verification method not found: $verificationMethodId")

        // Extract public key from verification method
        return when {
            verificationMethod.publicKeyJwk != null -> {
                extractPublicKeyFromJwk(verificationMethod.publicKeyJwk)
            }
            verificationMethod.publicKeyMultibase != null -> {
                val multibase = verificationMethod.publicKeyMultibase
                if (!multibase.startsWith("z")) {
                    throw IllegalArgumentException("Expected base58btc encoding")
                }
                val decoded = decodeBase58(multibase.substring(1))

                when (verificationMethod.type) {
                    "Ed25519VerificationKey2020" -> {
                        val x509Bytes = wrapEd25519PublicKey(decoded)
                        val keySpec = X509EncodedKeySpec(x509Bytes)
                        KeyFactory.getInstance("Ed25519").generatePublic(keySpec)
                    }
                    "EcdsaSecp256r1VerificationKey2019" -> {
                        val x509Bytes = wrapECPublicKey(decoded)
                        val keySpec = X509EncodedKeySpec(x509Bytes)
                        KeyFactory.getInstance("EC").generatePublic(keySpec)
                    }
                    else -> throw IllegalArgumentException("Unsupported verification method type: ${verificationMethod.type}")
                }
            }
            else -> throw IllegalArgumentException("No public key found in verification method")
        }
    }

    private fun didWebToUrl(did: String): String {
        val didWithoutPrefix = did.removePrefix("did:web:")
        val parts = didWithoutPrefix.split(":")

        val domain = parts[0].replace("%3A", ":")
        val path = if (parts.size > 1) {
            "/" + parts.drop(1).joinToString("/")
        } else {
            "/.well-known"
        }

        return "https://$domain$path/did.json"
    }

    private fun extractPublicKeyFromJwk(jwk: JsonObject): PublicKey {
        val kty = jwk["kty"]?.jsonPrimitive?.content
            ?: throw IllegalArgumentException("Missing kty in JWK")

        return when (kty) {
            "OKP" -> {
                val crv = jwk["crv"]?.jsonPrimitive?.content
                val x = jwk["x"]?.jsonPrimitive?.content
                    ?: throw IllegalArgumentException("Missing x in JWK")

                if (crv != "Ed25519") {
                    throw IllegalArgumentException("Unsupported curve: $crv")
                }

                val publicKeyBytes = Base64.getUrlDecoder().decode(x)
                val x509Bytes = wrapEd25519PublicKey(publicKeyBytes)
                val keySpec = X509EncodedKeySpec(x509Bytes)
                KeyFactory.getInstance("Ed25519").generatePublic(keySpec)
            }
            "EC" -> {
                val crv = jwk["crv"]?.jsonPrimitive?.content
                val x = jwk["x"]?.jsonPrimitive?.content
                    ?: throw IllegalArgumentException("Missing x in JWK")
                val y = jwk["y"]?.jsonPrimitive?.content
                    ?: throw IllegalArgumentException("Missing y in JWK")

                val xBytes = Base64.getUrlDecoder().decode(x)
                val yBytes = Base64.getUrlDecoder().decode(y)

                // Uncompressed EC point: 0x04 || x || y
                val publicKeyBytes = byteArrayOf(0x04) + xBytes + yBytes
                val x509Bytes = wrapECPublicKey(publicKeyBytes)
                val keySpec = X509EncodedKeySpec(x509Bytes)
                KeyFactory.getInstance("EC").generatePublic(keySpec)
            }
            "RSA" -> {
                val n = jwk["n"]?.jsonPrimitive?.content
                    ?: throw IllegalArgumentException("Missing n in JWK")
                val e = jwk["e"]?.jsonPrimitive?.content
                    ?: throw IllegalArgumentException("Missing e in JWK")

                val modulus = Base64.getUrlDecoder().decode(n)
                val exponent = Base64.getUrlDecoder().decode(e)

                val spec = java.security.spec.RSAPublicKeySpec(
                    java.math.BigInteger(1, modulus),
                    java.math.BigInteger(1, exponent)
                )
                KeyFactory.getInstance("RSA").generatePublic(spec)
            }
            else -> throw IllegalArgumentException("Unsupported key type: $kty")
        }
    }

    private fun wrapEd25519PublicKey(publicKeyBytes: ByteArray): ByteArray {
        // X.509 SubjectPublicKeyInfo wrapper for Ed25519
        val oid = byteArrayOf(
            0x30, 0x05, // SEQUENCE
            0x06, 0x03, // OID
            0x2b, 0x65.toByte(), 0x70 // 1.3.101.112 (Ed25519)
        )
        val bitString = byteArrayOf(0x03, (publicKeyBytes.size + 1).toByte(), 0x00) + publicKeyBytes
        val length = oid.size + bitString.size
        return byteArrayOf(0x30, length.toByte()) + oid + bitString
    }

    private fun wrapECPublicKey(publicKeyBytes: ByteArray): ByteArray {
        // X.509 SubjectPublicKeyInfo wrapper for P-256
        val oid = byteArrayOf(
            0x30, 0x13, // SEQUENCE
            0x06, 0x07, // OID
            0x2a, 0x86.toByte(), 0x48, 0xce.toByte(), 0x3d, 0x02, 0x01, // 1.2.840.10045.2.1 (ecPublicKey)
            0x06, 0x08, // OID
            0x2a, 0x86.toByte(), 0x48, 0xce.toByte(), 0x3d, 0x03, 0x01, 0x07 // 1.2.840.10045.3.1.7 (P-256)
        )
        val bitString = byteArrayOf(0x03, (publicKeyBytes.size + 1).toByte(), 0x00) + publicKeyBytes
        val length = oid.size + bitString.size
        return byteArrayOf(0x30, length.toByte()) + oid + bitString
    }

    private fun decodeBase58(input: String): ByteArray {
        val alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
        var decoded = java.math.BigInteger.ZERO

        for (char in input) {
            val digit = alphabet.indexOf(char)
            if (digit < 0) throw IllegalArgumentException("Invalid Base58 character: $char")
            decoded = decoded.multiply(java.math.BigInteger.valueOf(58))
                .add(java.math.BigInteger.valueOf(digit.toLong()))
        }

        val bytes = decoded.toByteArray()

        // Count leading zeros
        val leadingZeros = input.takeWhile { it == '1' }.length

        // Remove sign byte if present
        val withoutSign = if (bytes.isNotEmpty() && bytes[0] == 0.toByte() && bytes.size > 1) {
            bytes.drop(1).toByteArray()
        } else {
            bytes
        }

        return ByteArray(leadingZeros) + withoutSign
    }

    fun close() {
        ktorHttpClientFactory().close()
    }
}

// Usage example
suspend fun main() {
    val resolver = DidKeyResolver()

    try {
        // Example with did:key
        val didKeyKid = "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK#z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK"
        val publicKey1 = resolver.resolvePublicKey(didKeyKid)
        println("Resolved did:key: ${publicKey1.algorithm}")

        // Example with did:web
        val didWebKid = "did:web:example.com#key-1"
        val publicKey2 = resolver.resolvePublicKey(didWebKid)
        println("Resolved did:web: ${publicKey2.algorithm}")
    } finally {
        resolver.close()
    }
}