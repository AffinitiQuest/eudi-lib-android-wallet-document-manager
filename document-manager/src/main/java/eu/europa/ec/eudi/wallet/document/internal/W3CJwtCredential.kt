package org.multipaz.sdjwt.credential

import eu.europa.ec.eudi.sdjwt.Jwt
import eu.europa.ec.eudi.sdjwt.JwtBase64
import eu.europa.ec.eudi.sdjwt.VerificationError
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.add
import kotlinx.serialization.json.buildJsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import org.multipaz.claim.JsonClaim
import org.multipaz.credential.Credential
import org.multipaz.documenttype.DocumentTypeRepository
import org.multipaz.sdjwt.SdJwt

/**
 * A SD-JWT VC credential, according to [draft-ietf-oauth-sd-jwt-vc-03]
 * (https://datatracker.ietf.org/doc/draft-ietf-oauth-sd-jwt-vc/).
 *
 * An object that implements this interface must also be a [Credential]
 */
interface W3CJwtVcCredential {
    /**
     * The Verifiable Credential Type - or `vct` - as defined in section 3.2.2.1.1 of
     * [draft-ietf-oauth-sd-jwt-vc-03]
     * (https://datatracker.ietf.org/doc/draft-ietf-oauth-sd-jwt-vc/)
     */
    val types: List<String>

    /**
     * The issuer-provided data associated with the credential, see [Credential.issuerProvidedData].
     *
     * This data must be the encoded string containing the SD-JWT VC. The SD-JWT VC itself is by
     * disclosures: `<header>.<body>.<signature>~<Disclosure 1>~<Disclosure 2>~...~<Disclosure N>~`
     */
    val issuerProvidedData: ByteArray

    fun getClaimsImpl(
        documentTypeRepository: DocumentTypeRepository?
    ): List<JsonClaim> {
        val ret = mutableListOf<JsonClaim>()
        val jwt = issuerProvidedData.decodeToString()
        val ps = jwt.split(".")
        if (ps.size != 3) { return ret }
        val (h, p, s) = jwt.split(".")
        val decodedBody = Json.parseToJsonElement(p)
//        val issuerKey = sdJwt.x5c!!.certificates.first().ecPublicKey
//        val processedJwt = sdJwt.verify(issuerKey)

        // By design, we only include the top-level claims.
        val dt = documentTypeRepository?.getDocumentTypeForJson(types.last())
        val vc = decodedBody.jsonObject["vc"]
        val claims = vc?.jsonObject["credentialSubject"]
        if(claims is JsonObject) {
            for(claimKey in claims.jsonObject.keys) {
                val claim = claims[claimKey]
                if(claim != null) {
                    val attribute = dt?.jsonDocumentType?.claims?.get(claimKey)
                    ret.add(
                        JsonClaim(
                            displayName = dt?.jsonDocumentType?.claims?.get(claimKey)?.displayName
                                ?: claimKey,
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