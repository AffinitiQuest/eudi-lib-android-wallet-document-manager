package org.multipaz.sdjwt.credential

import org.multipaz.cbor.CborBuilder
import org.multipaz.cbor.DataItem
import org.multipaz.cbor.MapBuilder
import org.multipaz.claim.JsonClaim
import org.multipaz.credential.SecureAreaBoundCredential
import org.multipaz.document.Document
import org.multipaz.documenttype.DocumentTypeRepository
import org.multipaz.securearea.CreateKeySettings
import org.multipaz.securearea.SecureArea

/**
 * A Linked Data Proof Verifiable Credential bound to a key stored in a [SecureArea],
 * according to the [W3C Verifiable Credentials Data Model v2.0](https://www.w3.org/TR/vc-data-model-2.0/).
 */
class KeyBoundLdpVcCredential : SecureAreaBoundCredential, LdpVcCredential {
    companion object {
        private const val TAG = "LdpVcCredential"
        const val CREDENTIAL_TYPE: String = "KeyBoundLdpVcCredential"

        /**
         * Creates a batch of [KeyBoundLdpVcCredential] instances with keys created in a single batch operation.
         *
         * @param numberOfCredentials The number of credentials to create in the batch.
         * @param document The document to add the credentials to.
         * @param domain The domain for all credentials in the batch.
         * @param secureArea The secure area to use for creating keys.
         * @param types The credential types for all credentials in the batch.
         * @param createKeySettings The settings to use for key creation.
         * @return A pair containing the list of created credentials and an optional key attestation JWS.
         */
        suspend fun createBatch(
            numberOfCredentials: Int,
            document: Document,
            domain: String,
            secureArea: SecureArea,
            types: List<String>,
            createKeySettings: CreateKeySettings
        ): Pair<List<KeyBoundLdpVcCredential>, String?> {
            val batchResult = secureArea.batchCreateKey(numberOfCredentials, createKeySettings)
            val credentials = batchResult.keyInfos
                .map { it.alias }
                .map { keyAlias ->
                    KeyBoundLdpVcCredential(
                        document = document,
                        asReplacementForIdentifier = null,
                        domain = domain,
                        secureArea = secureArea,
                        types = types,
                    ).apply {
                        useExistingKey(keyAlias)
                    }
                }
            return Pair(credentials, batchResult.openid4vciKeyAttestationJws)
        }

        /**
         * Create a single [KeyBoundLdpVcCredential].
         *
         * @param document The document to add the credential to.
         * @param asReplacementForIdentifier the identifier for the credential this will replace when certified.
         * @param domain The domain for the credential.
         * @param secureArea The [SecureArea] to use for creating a key.
         * @param types The credential types.
         * @param createKeySettings The settings to use for key creation.
         * @return an uncertified credential which has been added to [document].
         */
        suspend fun create(
            document: Document,
            asReplacementForIdentifier: String?,
            domain: String,
            secureArea: SecureArea,
            types: List<String>,
            createKeySettings: CreateKeySettings
        ): KeyBoundLdpVcCredential {
            return KeyBoundLdpVcCredential(
                document,
                asReplacementForIdentifier,
                domain,
                secureArea,
                types
            ).apply {
                generateKey(createKeySettings)
            }
        }

        /**
         * Create a [KeyBoundLdpVcCredential] using a key that already exists.
         *
         * @param document The document to add the credential to.
         * @param asReplacementForIdentifier the identifier for the credential this will replace when certified.
         * @param domain The domain for the credential.
         * @param secureArea The [SecureArea] to use for creating a key.
         * @param types The credential types.
         * @param existingKeyAlias the alias for the existing key in [secureArea].
         * @return an uncertified credential which has been added to [document].
         */
        suspend fun createForExistingAlias(
            document: Document,
            asReplacementForIdentifier: String?,
            domain: String,
            secureArea: SecureArea,
            types: List<String>,
            existingKeyAlias: String,
        ): KeyBoundLdpVcCredential {
            return KeyBoundLdpVcCredential(
                document,
                asReplacementForIdentifier,
                domain,
                secureArea,
                types
            ).apply {
                useExistingKey(keyAlias = existingKeyAlias)
            }
        }
    }

    override lateinit var types: List<String>
        private set

    private constructor(
        document: Document,
        asReplacementForIdentifier: String?,
        domain: String,
        secureArea: SecureArea,
        types: List<String>,
    ) : super(document, asReplacementForIdentifier, domain, secureArea) {
        this.types = types
    }

    /**
     * Constructs a Credential from serialized data.
     *
     * [deserialize] providing serialized data must be called before using this object.
     *
     * @param document the [Document] that the credential belongs to.
     */
    constructor(
        document: Document
    ) : super(document) {
    }

    override suspend fun deserialize(dataItem: DataItem) {
        super.deserialize(dataItem)
        val typesArray = dataItem["ldpTypes"].asArray
        types = typesArray.map { it.asTstr }
    }

    override fun addSerializedData(builder: MapBuilder<CborBuilder>) {
        super.addSerializedData(builder)
        val arrayBuilder = builder.putArray("ldpTypes")
        types.map { arrayBuilder.add(it) }
    }

    override val credentialType: String
        get() = CREDENTIAL_TYPE

    override fun getClaims(documentTypeRepository: DocumentTypeRepository?): List<JsonClaim> {
        return getClaimsImpl(documentTypeRepository)
    }
}
