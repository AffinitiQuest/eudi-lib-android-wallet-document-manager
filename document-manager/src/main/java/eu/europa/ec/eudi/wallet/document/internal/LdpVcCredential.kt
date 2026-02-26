package org.multipaz.sdjwt.credential

import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.add
import kotlinx.serialization.json.buildJsonArray
import kotlinx.serialization.json.jsonObject
import org.multipaz.claim.JsonClaim
import org.multipaz.credential.Credential
import org.multipaz.documenttype.DocumentTypeRepository

/**
 * A Linked Data Proof Verifiable Credential, according to the
 * [W3C Verifiable Credentials Data Model v2.0](https://www.w3.org/TR/vc-data-model-2.0/).
 *
 * An object that implements this interface must also be a [Credential].
 */
interface LdpVcCredential {
    /**
     * The credential types as defined by the `type` property of the VC.
     * For example: `["VerifiableCredential", "UniversityDegreeCredential"]`
     */
    val types: List<String>

    /**
     * The issuer-provided data associated with the credential, see [Credential.issuerProvidedData].
     *
     * This data must be the UTF-8 encoded JSON-LD document containing the Verifiable Credential.
     */
    val issuerProvidedData: ByteArray

    fun getClaimsImpl(
        documentTypeRepository: DocumentTypeRepository?
    ): List<JsonClaim> {
        val ret = mutableListOf<JsonClaim>()
        val json = issuerProvidedData.decodeToString()
        val document = Json.parseToJsonElement(json)
        if (document !is JsonObject) return ret

        val dt = documentTypeRepository?.getDocumentTypeForJson(types.last())
        val claims = document.jsonObject["credentialSubject"]
        if (claims is JsonObject) {
            for (claimKey in claims.jsonObject.keys) {
                val claim = claims[claimKey]
                if (claim != null) {
                    val attribute = dt?.jsonDocumentType?.claims?.get(claimKey)
                    ret.add(
                        JsonClaim(
                            displayName = attribute?.displayName ?: claimKey,
                            attribute = attribute,
                            claimPath = buildJsonArray { add(claimKey) },
                            value = claim
                        )
                    )
                }
            }
        }

        return ret
    }
}
