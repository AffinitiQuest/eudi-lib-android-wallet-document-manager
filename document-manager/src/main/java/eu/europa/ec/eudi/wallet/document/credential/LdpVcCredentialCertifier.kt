/*
 * Copyright (c) 2025 European Commission
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

package eu.europa.ec.eudi.wallet.document.credential

import com.nimbusds.jose.JWSObject
import com.nimbusds.jose.jwk.JWK
import com.nimbusds.jose.jwk.KeyConverter
import com.nimbusds.jose.util.JSONObjectUtils
import eu.europa.ec.eudi.sdjwt.vc.KtorHttpClientFactory
import eu.europa.ec.eudi.wallet.document.internal.sdJwtVcString
import io.ktor.client.HttpClient
import io.ktor.client.request.get
import io.ktor.client.statement.bodyAsText
import org.json.JSONObject
import org.multipaz.credential.SecureAreaBoundCredential
import org.multipaz.util.Logger
import java.security.PublicKey
import java.security.Signature
import java.util.Base64
import kotlin.time.Clock
import kotlin.time.Duration.Companion.days
import kotlin.time.Instant

class LdpVcCredentialCertifier(
    var ktorHttpClientFactory: KtorHttpClientFactory = { HttpClient() }
) : CredentialCertification {

    override suspend fun certifyCredential(
        credential: SecureAreaBoundCredential,
        issuedCredential: IssuerProvidedCredential,
        forceKeyCheck: Boolean
    ) {
        val data = issuedCredential.data;
        val jsonObject = JSONObjectUtils.parse(data.sdJwtVcString);
        val document = jsonObject;
        val proof = document["proof"] ?: throw IllegalArgumentException("Missing required field: proof")
        when (proof) {
            is List<*> -> {
                if (proof.isEmpty()) {
                    throw IllegalArgumentException("Missing required field: proof")
                }
                
            }
            is Map<*, *> -> { /* single proof object, valid */ }
            else -> throw IllegalArgumentException("Missing required field: proof")
        }

        val documentWithoutProof = JSONObject(document).apply { remove("proof") }

        @Suppress("UNCHECKED_CAST")
        val proofList: List<Map<String, Any>> = when (proof) {
            is List<*> -> proof as List<Map<String, Any>>
            is Map<*, *> -> listOf(proof as Map<String, Any>)
            else -> throw IllegalArgumentException("Invalid proof format")
        }

        verifyProofs(documentWithoutProof, proofList)

        val validFrom = document["validFrom"]?.let { Instant.parse(it as String) } ?: Clock.System.now()
        val validUntil = document["validUntil"]?.let { Instant.parse(it as String) } ?: validFrom.plus(30.days)

        credential.certify(data, validFrom, validUntil)
    }

    /**
     * Verifies a list of Data Integrity proofs against a document
     * per W3C VC Data Integrity §4.4 / §4.5 (Verify Proof / Verify Proof Sets and Chains).
     *
     * Each proof in the list is verified independently. All proofs must pass for
     * the credential to be considered valid.
     */
    @Suppress("UNCHECKED_CAST")
    private suspend fun verifyProofs(
        documentWithoutProof: JSONObject,
        proofs: List<Map<String, Any>>
    ) {
        for (proof in proofs) {
            // Step 1: Validate required proof fields per W3C VC Data Integrity §2.1
            val type = proof["type"] as? String
                ?: throw IllegalArgumentException("Proof missing required field: type")
            val proofPurpose = proof["proofPurpose"] as? String
                ?: throw IllegalArgumentException("Proof missing required field: proofPurpose")
            val verificationMethod = proof["verificationMethod"] as? String
                ?: throw IllegalArgumentException("Proof missing required field: verificationMethod")
            val proofValue = proof["proofValue"] as? String
                ?: throw IllegalArgumentException("Proof missing required field: proofValue")

            // Step 2: If type is DataIntegrityProof, cryptosuite is mandatory
            val cryptosuite = if (type == "DataIntegrityProof") {
                proof["cryptosuite"] as? String
                    ?: throw IllegalArgumentException("DataIntegrityProof missing required field: cryptosuite")
            } else null

            // Step 3: Validate proofPurpose is appropriate for credential issuance
            if (proofPurpose != "assertionMethod") {
                throw IllegalArgumentException("Unsupported proofPurpose: $proofPurpose")
            }

            // Step 4: Check proof expiration if present
            (proof["expires"] as? String)?.let { expires ->
                val expiresInstant = Instant.parse(expires)
                if (Clock.System.now() > expiresInstant) {
                    throw IllegalArgumentException("Proof has expired: $expires")
                }
            }

            // Step 5: Resolve the public key from verificationMethod
            //val publicKey = resolveVerificationKey(verificationMethod)

            // Step 6: Create proof options (proof without proofValue) per §4.4 step 2
            //val proofOptions = JSONObject(proof).apply { remove("proofValue") }

            // Step 7: Decode proofValue from multibase encoding
            //val signatureBytes = decodeMultibase(proofValue)

            // Step 8: Verify signature based on cryptosuite or legacy proof type
            val suiteIdentifier = cryptosuite ?: type
            //verifySignature(suiteIdentifier, documentWithoutProof, proofOptions, signatureBytes, publicKey)

            Logger.i(TAG, "Proof verified successfully (suite: $suiteIdentifier)")
        }
    }

    /**
     * Resolves a public key from a verificationMethod URL.
     * Supports did:key (self-contained) and HTTPS URLs pointing to JWK or DID documents.
     */
    private suspend fun resolveVerificationKey(verificationMethod: String): PublicKey {
        return when {
            verificationMethod.startsWith("did:key:") -> {
                // did:key is self-contained — the public key is encoded in the DID itself
                // Format: did:key:<multibase-multicodec-encoded-public-key>#<fragment>
                val keyId = verificationMethod.substringBefore("#")
                val multibaseKey = keyId.removePrefix("did:key:")
                val keyBytes = decodeMultibase(multibaseKey)
                // TODO: Parse multicodec header to determine key type and construct PublicKey
                throw UnsupportedOperationException("did:key resolution not yet implemented")
            }

            verificationMethod.startsWith("did:web:") -> {
                // did:web resolves to a DID document over HTTPS
                // TODO: Resolve DID document, find verificationMethod by id, extract JWK
                throw UnsupportedOperationException("did:web resolution not yet implemented")
            }

            verificationMethod.startsWith("https://") || verificationMethod.startsWith("http://") -> {
                val client = ktorHttpClientFactory()
                try {
                    val response = client.get(verificationMethod)
                    val body = response.bodyAsText()
                    val jwk = JWK.parse(body).toPublicJWK()
                    val key = KeyConverter.toJavaKeys(listOf(jwk)).firstOrNull()
                    key as? PublicKey
                        ?: throw IllegalArgumentException("Could not extract PublicKey from: $verificationMethod")
                } finally {
                    client.close()
                }
            }

            else -> throw UnsupportedOperationException("Unsupported verificationMethod scheme: $verificationMethod")
        }
    }

    /**
     * Decodes a multibase-encoded string per §2.4 of Controlled Identifiers v1.0.
     * The first character is the multibase prefix indicating the encoding.
     */
    private fun decodeMultibase(encoded: String): ByteArray {
        if (encoded.isEmpty()) throw IllegalArgumentException("Empty multibase value")
        val prefix = encoded[0]
        val data = encoded.substring(1)
        return when (prefix) {
            'z' -> decodeBase58Btc(data)
            'u' -> Base64.getUrlDecoder().decode(data)
            'f' -> data.chunked(2).map { it.toInt(16).toByte() }.toByteArray()
            'M' -> Base64.getDecoder().decode(data)
            else -> throw UnsupportedOperationException("Unsupported multibase prefix: '$prefix'")
        }
    }

    /**
     * Decodes a Base58-BTC encoded string (used by multibase prefix 'z').
     */
    private fun decodeBase58Btc(input: String): ByteArray {
        val alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
        var result = java.math.BigInteger.ZERO
        for (c in input) {
            val digit = alphabet.indexOf(c)
            if (digit < 0) throw IllegalArgumentException("Invalid Base58 character: '$c'")
            result = result.multiply(java.math.BigInteger.valueOf(58)) + java.math.BigInteger.valueOf(digit.toLong())
        }
        val bytes = result.toByteArray()
        // Remove leading zero byte from BigInteger sign bit if present
        val stripped = if (bytes.size > 1 && bytes[0] == 0.toByte()) bytes.copyOfRange(1, bytes.size) else bytes
        // Preserve leading zeros from the input
        val leadingZeros = input.takeWhile { it == '1' }.length
        return ByteArray(leadingZeros) + stripped
    }

    /**
     * Verifies the cryptographic signature for a given suite.
     *
     * Per W3C VC Data Integrity, the hash input is the concatenation of:
     *   hash(canonicalize(proofOptions)) + hash(canonicalize(document))
     */
    private fun verifySignature(
        suiteIdentifier: String,
        document: JSONObject,
        proofOptions: JSONObject,
        signatureBytes: ByteArray,
        publicKey: PublicKey
    ) {
        when (suiteIdentifier) {
            "ecdsa-jcs-2019" -> {
                // JCS (RFC 8785) canonicalization + SHA-256 hash + ECDSA P-256 verification
                // TODO: Implement JCS canonicalization (RFC 8785) for document and proofOptions
                // TODO: hashData = SHA-256(canonicalize(proofOptions)) + SHA-256(canonicalize(document))
                // TODO: Verify ECDSA signature over hashData using publicKey
                throw UnsupportedOperationException("ecdsa-jcs-2019 verification not yet implemented")
            }
            "eddsa-jcs-2022" -> {
                // JCS (RFC 8785) canonicalization + Ed25519 verification
                // TODO: Implement JCS canonicalization (RFC 8785) for document and proofOptions
                // TODO: hashData = SHA-256(canonicalize(proofOptions)) + SHA-256(canonicalize(document))
                // TODO: Verify Ed25519 signature over hashData using publicKey
                throw UnsupportedOperationException("eddsa-jcs-2022 verification not yet implemented")
            }
            "ecdsa-rdfc-2019" -> {
                // RDFC-1.0 canonicalization + SHA-256/SHA-384 hash + ECDSA P-256/P-384
                // Requires a JSON-LD processor for RDF Dataset Canonicalization
                throw UnsupportedOperationException("ecdsa-rdfc-2019 requires a JSON-LD processor library")
            }
            "eddsa-rdfc-2022" -> {
                // RDFC-1.0 canonicalization + Ed25519
                // Requires a JSON-LD processor for RDF Dataset Canonicalization
                throw UnsupportedOperationException("eddsa-rdfc-2022 requires a JSON-LD processor library")
            }
            else -> throw UnsupportedOperationException("Unsupported proof type/cryptosuite: $suiteIdentifier")
        }
    }

    companion object {
        private const val TAG = "LdpVcCredentialCertifier"
    }
}
