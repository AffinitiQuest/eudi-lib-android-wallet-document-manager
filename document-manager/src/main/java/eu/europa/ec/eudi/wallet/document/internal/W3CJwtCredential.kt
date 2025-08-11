package eu.europa.ec.eudi.wallet.document.internal

import com.android.identity.cbor.CborBuilder
import com.android.identity.cbor.DataItem
import com.android.identity.cbor.MapBuilder
import com.android.identity.credential.Credential
import com.android.identity.credential.SecureAreaBoundCredential
import com.android.identity.document.Document
import com.android.identity.securearea.CreateKeySettings
import com.android.identity.securearea.SecureArea

/**
 * A SD-JWT VC credential, according to [draft-ietf-oauth-sd-jwt-vc-03]
 * (https://datatracker.ietf.org/doc/draft-ietf-oauth-sd-jwt-vc/).
 */
class W3CJwtCredential : SecureAreaBoundCredential {
    companion object {
        private const val TAG = "W3CJwtCredential"
    }

    /**
     * The Verifiable Credential Type - or `vct` - as defined in section 3.2.2.1.1 of
     * [draft-ietf-oauth-sd-jwt-vc-03]
     * (https://datatracker.ietf.org/doc/draft-ietf-oauth-sd-jwt-vc/)
     */
    val types: List<String>

    /**
     * Constructs a new [W3CJwtCredential].
     *
     * @param document the document to add the credential to.
     * @param asReplacementFor the credential this credential will replace, if not null
     * @param domain the domain of the credential
     * @param secureArea the secure area for the authentication key associated with this credential.
     * @param createKeySettings the settings used to create new credentials.
     * @param vct the Verifiable Credential Type.
     */
    constructor(
        document: Document,
        asReplacementFor: Credential?,
        domain: String,
        secureArea: SecureArea,
        createKeySettings: CreateKeySettings,
        types: List<String>,
    ) : super(document, asReplacementFor, domain, secureArea, createKeySettings) {
        this.types = types
        // Only the leaf constructor should add the credential to the document.
        if (this::class == W3CJwtCredential::class) {
            addToDocument()
        }
    }

    /**
     * Constructs a Credential from serialized data.
     *
     * @param document the [Document] that the credential belongs to.
     * @param dataItem the serialized data.
     */
    constructor(
        document: Document,
        dataItem: DataItem,
    ) : super(document, dataItem) {
        val typesArray = dataItem["types"].asArray
        types = typesArray.map { it.asTstr }
    }

    override fun addSerializedData(builder: MapBuilder<CborBuilder>) {
        super.addSerializedData(builder)
        val arrayBuilder = builder.putArray("types")
        types.map { arrayBuilder.add(it) }
    }

}