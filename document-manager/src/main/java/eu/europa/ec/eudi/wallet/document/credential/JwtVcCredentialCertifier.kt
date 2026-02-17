package eu.europa.ec.eudi.wallet.document.credential

import com.nimbusds.jose.JWSObject
import eu.europa.ec.eudi.sdjwt.vc.KtorHttpClientFactory
import eu.europa.ec.eudi.wallet.document.internal.DidKeyResolver
import eu.europa.ec.eudi.wallet.document.internal.getEcCurve
import eu.europa.ec.eudi.wallet.document.internal.jwtVcString
import io.ktor.client.HttpClient
import org.multipaz.credential.SecureAreaBoundCredential
import org.multipaz.crypto.toEcPublicKey
import org.multipaz.util.validateJwt
import kotlin.time.Clock
import kotlin.time.Duration.Companion.days
import kotlin.time.Duration.Companion.hours
import kotlin.time.Instant

class JwtVcCredentialCertifier(
    var ktorHttpClientFactory: KtorHttpClientFactory = { HttpClient() }
) : CredentialCertification {
    override suspend fun certifyCredential(
        credential: SecureAreaBoundCredential,
        issuedCredential: IssuerProvidedCredential,
        forceKeyCheck: Boolean
    ) {
        val data = issuedCredential.data

        val jwsObject = JWSObject.parse(data.jwtVcString)
        val header = jwsObject.header
        val kid = header.keyID

        val publicKey = DidKeyResolver().resolvePublicKey(kid)
        val ecPublicKey = publicKey.toEcPublicKey(publicKey.getEcCurve())
        val jwtObject = validateJwt(
            data.jwtVcString,
            "Issued JWT",
            publicKey = ecPublicKey,
            algorithm = ecPublicKey.curve.defaultSigningAlgorithmFullySpecified,
            checks = emptyMap(),
            maxValidity = 876000.hours,
            clock = Clock.System,
        )

        val claims = jwsObject.payload.toJSONObject()

        // TODO what to do with validFrom and validUntil if they are not present in the JWT VC
        //  in nbf (or iat if no nbf) and exp claims that are optional

        val nbf = claims["nbf"]?.let { Instant.fromEpochSeconds(it as Long) }
        val iat = claims["iat"]?.let { Instant.fromEpochSeconds(it as Long) }
        val exp = claims["exp"]?.let { Instant.fromEpochSeconds(it as Long) }
        val validFrom = nbf ?: iat ?: Clock.System.now()
        val validUntil = exp ?: validFrom.plus(30.days)

        credential.certify(data, validFrom, validUntil)
    }
}