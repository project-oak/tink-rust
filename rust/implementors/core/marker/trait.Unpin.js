(function() {var implementors = {};
implementors["rinkey"] = [{"text":"impl Unpin for KeysetReader","synthetic":true,"types":[]},{"text":"impl Unpin for KeysetWriter","synthetic":true,"types":[]},{"text":"impl Unpin for KeyTemplate","synthetic":true,"types":[]},{"text":"impl Unpin for WrappingOptions","synthetic":true,"types":[]},{"text":"impl Unpin for InOptions","synthetic":true,"types":[]},{"text":"impl Unpin for OutOptions","synthetic":true,"types":[]},{"text":"impl Unpin for PublicKeysetOptions","synthetic":true,"types":[]},{"text":"impl Unpin for AddRotateOptions","synthetic":true,"types":[]},{"text":"impl Unpin for ConvertKeysetOptions","synthetic":true,"types":[]},{"text":"impl Unpin for CreateKeysetOptions","synthetic":true,"types":[]},{"text":"impl Unpin for KeyIdOptions","synthetic":true,"types":[]},{"text":"impl Unpin for KeysetFormat","synthetic":true,"types":[]},{"text":"impl Unpin for Command","synthetic":true,"types":[]}];
implementors["tink_aead"] = [{"text":"impl Unpin for KmsEnvelopeAead","synthetic":true,"types":[]},{"text":"impl Unpin for AesCtr","synthetic":true,"types":[]},{"text":"impl Unpin for AesGcm","synthetic":true,"types":[]},{"text":"impl Unpin for AesGcmSiv","synthetic":true,"types":[]},{"text":"impl Unpin for ChaCha20Poly1305","synthetic":true,"types":[]},{"text":"impl Unpin for EncryptThenAuthenticate","synthetic":true,"types":[]},{"text":"impl Unpin for XChaCha20Poly1305","synthetic":true,"types":[]}];
implementors["tink_awskms"] = [{"text":"impl Unpin for AwsClient","synthetic":true,"types":[]}];
implementors["tink_core"] = [{"text":"impl Unpin for Primitive","synthetic":true,"types":[]},{"text":"impl&lt;T&gt; Unpin for BinaryReader&lt;T&gt; <span class=\"where fmt-newline\">where<br>&nbsp;&nbsp;&nbsp;&nbsp;T: Unpin,&nbsp;</span>","synthetic":true,"types":[]},{"text":"impl&lt;T&gt; Unpin for BinaryWriter&lt;T&gt; <span class=\"where fmt-newline\">where<br>&nbsp;&nbsp;&nbsp;&nbsp;T: Unpin,&nbsp;</span>","synthetic":true,"types":[]},{"text":"impl Unpin for Handle","synthetic":true,"types":[]},{"text":"impl&lt;T&gt; Unpin for JsonReader&lt;T&gt; <span class=\"where fmt-newline\">where<br>&nbsp;&nbsp;&nbsp;&nbsp;T: Unpin,&nbsp;</span>","synthetic":true,"types":[]},{"text":"impl&lt;T&gt; Unpin for JsonWriter&lt;T&gt; <span class=\"where fmt-newline\">where<br>&nbsp;&nbsp;&nbsp;&nbsp;T: Unpin,&nbsp;</span>","synthetic":true,"types":[]},{"text":"impl Unpin for Manager","synthetic":true,"types":[]},{"text":"impl Unpin for MemReaderWriter","synthetic":true,"types":[]},{"text":"impl Unpin for Entry","synthetic":true,"types":[]},{"text":"impl Unpin for PrimitiveSet","synthetic":true,"types":[]},{"text":"impl&lt;P&gt; Unpin for TypedEntry&lt;P&gt; <span class=\"where fmt-newline\">where<br>&nbsp;&nbsp;&nbsp;&nbsp;P: Unpin,&nbsp;</span>","synthetic":true,"types":[]},{"text":"impl&lt;P&gt; Unpin for TypedPrimitiveSet&lt;P&gt; <span class=\"where fmt-newline\">where<br>&nbsp;&nbsp;&nbsp;&nbsp;P: Unpin,&nbsp;</span>","synthetic":true,"types":[]},{"text":"impl Unpin for HashFunc","synthetic":true,"types":[]},{"text":"impl Unpin for TinkError","synthetic":true,"types":[]}];
implementors["tink_daead"] = [{"text":"impl Unpin for AesSiv","synthetic":true,"types":[]}];
implementors["tink_gcpkms"] = [{"text":"impl Unpin for GcpClient","synthetic":true,"types":[]},{"text":"impl Unpin for GcpAead","synthetic":true,"types":[]},{"text":"impl Unpin for CloudKmsClient","synthetic":true,"types":[]}];
implementors["tink_mac"] = [{"text":"impl Unpin for AesCmac","synthetic":true,"types":[]},{"text":"impl Unpin for Hmac","synthetic":true,"types":[]}];
implementors["tink_prf"] = [{"text":"impl Unpin for Set","synthetic":true,"types":[]},{"text":"impl Unpin for AesCmacPrf","synthetic":true,"types":[]},{"text":"impl Unpin for HkdfPrf","synthetic":true,"types":[]},{"text":"impl Unpin for HmacPrf","synthetic":true,"types":[]}];
implementors["tink_proto"] = [{"text":"impl Unpin for AesCmacParams","synthetic":true,"types":[]},{"text":"impl Unpin for AesCmacKey","synthetic":true,"types":[]},{"text":"impl Unpin for AesCmacKeyFormat","synthetic":true,"types":[]},{"text":"impl Unpin for AesCmacPrfKey","synthetic":true,"types":[]},{"text":"impl Unpin for AesCmacPrfKeyFormat","synthetic":true,"types":[]},{"text":"impl Unpin for AesCtrParams","synthetic":true,"types":[]},{"text":"impl Unpin for AesCtrKeyFormat","synthetic":true,"types":[]},{"text":"impl Unpin for AesCtrKey","synthetic":true,"types":[]},{"text":"impl Unpin for HmacParams","synthetic":true,"types":[]},{"text":"impl Unpin for HmacKey","synthetic":true,"types":[]},{"text":"impl Unpin for HmacKeyFormat","synthetic":true,"types":[]},{"text":"impl Unpin for AesCtrHmacAeadKeyFormat","synthetic":true,"types":[]},{"text":"impl Unpin for AesCtrHmacAeadKey","synthetic":true,"types":[]},{"text":"impl Unpin for AesCtrHmacStreamingParams","synthetic":true,"types":[]},{"text":"impl Unpin for AesCtrHmacStreamingKeyFormat","synthetic":true,"types":[]},{"text":"impl Unpin for AesCtrHmacStreamingKey","synthetic":true,"types":[]},{"text":"impl Unpin for AesEaxParams","synthetic":true,"types":[]},{"text":"impl Unpin for AesEaxKeyFormat","synthetic":true,"types":[]},{"text":"impl Unpin for AesEaxKey","synthetic":true,"types":[]},{"text":"impl Unpin for AesGcmKeyFormat","synthetic":true,"types":[]},{"text":"impl Unpin for AesGcmKey","synthetic":true,"types":[]},{"text":"impl Unpin for AesGcmHkdfStreamingParams","synthetic":true,"types":[]},{"text":"impl Unpin for AesGcmHkdfStreamingKeyFormat","synthetic":true,"types":[]},{"text":"impl Unpin for AesGcmHkdfStreamingKey","synthetic":true,"types":[]},{"text":"impl Unpin for AesGcmSivKeyFormat","synthetic":true,"types":[]},{"text":"impl Unpin for AesGcmSivKey","synthetic":true,"types":[]},{"text":"impl Unpin for AesSivKeyFormat","synthetic":true,"types":[]},{"text":"impl Unpin for AesSivKey","synthetic":true,"types":[]},{"text":"impl Unpin for ChaCha20Poly1305KeyFormat","synthetic":true,"types":[]},{"text":"impl Unpin for ChaCha20Poly1305Key","synthetic":true,"types":[]},{"text":"impl Unpin for KeyTypeEntry","synthetic":true,"types":[]},{"text":"impl Unpin for RegistryConfig","synthetic":true,"types":[]},{"text":"impl Unpin for EcdsaParams","synthetic":true,"types":[]},{"text":"impl Unpin for EcdsaPublicKey","synthetic":true,"types":[]},{"text":"impl Unpin for EcdsaPrivateKey","synthetic":true,"types":[]},{"text":"impl Unpin for EcdsaKeyFormat","synthetic":true,"types":[]},{"text":"impl Unpin for KeyTemplate","synthetic":true,"types":[]},{"text":"impl Unpin for KeyData","synthetic":true,"types":[]},{"text":"impl Unpin for Keyset","synthetic":true,"types":[]},{"text":"impl Unpin for KeysetInfo","synthetic":true,"types":[]},{"text":"impl Unpin for EncryptedKeyset","synthetic":true,"types":[]},{"text":"impl Unpin for EciesHkdfKemParams","synthetic":true,"types":[]},{"text":"impl Unpin for EciesAeadDemParams","synthetic":true,"types":[]},{"text":"impl Unpin for EciesAeadHkdfParams","synthetic":true,"types":[]},{"text":"impl Unpin for EciesAeadHkdfPublicKey","synthetic":true,"types":[]},{"text":"impl Unpin for EciesAeadHkdfPrivateKey","synthetic":true,"types":[]},{"text":"impl Unpin for EciesAeadHkdfKeyFormat","synthetic":true,"types":[]},{"text":"impl Unpin for Ed25519KeyFormat","synthetic":true,"types":[]},{"text":"impl Unpin for Ed25519PublicKey","synthetic":true,"types":[]},{"text":"impl Unpin for Ed25519PrivateKey","synthetic":true,"types":[]},{"text":"impl Unpin for Empty","synthetic":true,"types":[]},{"text":"impl Unpin for HkdfPrfParams","synthetic":true,"types":[]},{"text":"impl Unpin for HkdfPrfKey","synthetic":true,"types":[]},{"text":"impl Unpin for HkdfPrfKeyFormat","synthetic":true,"types":[]},{"text":"impl Unpin for HmacPrfParams","synthetic":true,"types":[]},{"text":"impl Unpin for HmacPrfKey","synthetic":true,"types":[]},{"text":"impl Unpin for HmacPrfKeyFormat","synthetic":true,"types":[]},{"text":"impl Unpin for JwtHmacKey","synthetic":true,"types":[]},{"text":"impl Unpin for JwtHmacKeyFormat","synthetic":true,"types":[]},{"text":"impl Unpin for KmsAeadKeyFormat","synthetic":true,"types":[]},{"text":"impl Unpin for KmsAeadKey","synthetic":true,"types":[]},{"text":"impl Unpin for KmsEnvelopeAeadKeyFormat","synthetic":true,"types":[]},{"text":"impl Unpin for KmsEnvelopeAeadKey","synthetic":true,"types":[]},{"text":"impl Unpin for PrfBasedDeriverParams","synthetic":true,"types":[]},{"text":"impl Unpin for PrfBasedDeriverKeyFormat","synthetic":true,"types":[]},{"text":"impl Unpin for PrfBasedDeriverKey","synthetic":true,"types":[]},{"text":"impl Unpin for RsaSsaPkcs1Params","synthetic":true,"types":[]},{"text":"impl Unpin for RsaSsaPkcs1PublicKey","synthetic":true,"types":[]},{"text":"impl Unpin for RsaSsaPkcs1PrivateKey","synthetic":true,"types":[]},{"text":"impl Unpin for RsaSsaPkcs1KeyFormat","synthetic":true,"types":[]},{"text":"impl Unpin for RsaSsaPssParams","synthetic":true,"types":[]},{"text":"impl Unpin for RsaSsaPssPublicKey","synthetic":true,"types":[]},{"text":"impl Unpin for RsaSsaPssPrivateKey","synthetic":true,"types":[]},{"text":"impl Unpin for RsaSsaPssKeyFormat","synthetic":true,"types":[]},{"text":"impl Unpin for XChaCha20Poly1305KeyFormat","synthetic":true,"types":[]},{"text":"impl Unpin for XChaCha20Poly1305Key","synthetic":true,"types":[]},{"text":"impl Unpin for EllipticCurveType","synthetic":true,"types":[]},{"text":"impl Unpin for EcPointFormat","synthetic":true,"types":[]},{"text":"impl Unpin for HashType","synthetic":true,"types":[]},{"text":"impl Unpin for EcdsaSignatureEncoding","synthetic":true,"types":[]},{"text":"impl Unpin for KeyStatusType","synthetic":true,"types":[]},{"text":"impl Unpin for OutputPrefixType","synthetic":true,"types":[]},{"text":"impl Unpin for KeyMaterialType","synthetic":true,"types":[]},{"text":"impl Unpin for Key","synthetic":true,"types":[]},{"text":"impl Unpin for KeyInfo","synthetic":true,"types":[]}];
implementors["tink_signature"] = [{"text":"impl Unpin for EcdsaSigner","synthetic":true,"types":[]},{"text":"impl Unpin for EcdsaVerifier","synthetic":true,"types":[]},{"text":"impl Unpin for Ed25519Signer","synthetic":true,"types":[]},{"text":"impl Unpin for Ed25519Verifier","synthetic":true,"types":[]},{"text":"impl Unpin for SignatureEncoding","synthetic":true,"types":[]},{"text":"impl Unpin for EcdsaPrivateKey","synthetic":true,"types":[]},{"text":"impl Unpin for EcdsaPublicKey","synthetic":true,"types":[]}];
implementors["tink_streaming_aead"] = [{"text":"impl Unpin for AesCtrHmac","synthetic":true,"types":[]},{"text":"impl Unpin for AesGcmHkdf","synthetic":true,"types":[]},{"text":"impl Unpin for AesVariant","synthetic":true,"types":[]},{"text":"impl Unpin for Writer","synthetic":true,"types":[]},{"text":"impl Unpin for WriterParams","synthetic":true,"types":[]},{"text":"impl Unpin for Reader","synthetic":true,"types":[]},{"text":"impl Unpin for ReaderParams","synthetic":true,"types":[]}];
implementors["tink_testing_server"] = [{"text":"impl Unpin for Opt","synthetic":true,"types":[]},{"text":"impl Unpin for ServerInfoRequest","synthetic":true,"types":[]},{"text":"impl Unpin for ServerInfoResponse","synthetic":true,"types":[]},{"text":"impl Unpin for KeysetGenerateRequest","synthetic":true,"types":[]},{"text":"impl Unpin for KeysetGenerateResponse","synthetic":true,"types":[]},{"text":"impl Unpin for KeysetPublicRequest","synthetic":true,"types":[]},{"text":"impl Unpin for KeysetPublicResponse","synthetic":true,"types":[]},{"text":"impl Unpin for KeysetToJsonRequest","synthetic":true,"types":[]},{"text":"impl Unpin for KeysetToJsonResponse","synthetic":true,"types":[]},{"text":"impl Unpin for KeysetFromJsonRequest","synthetic":true,"types":[]},{"text":"impl Unpin for KeysetFromJsonResponse","synthetic":true,"types":[]},{"text":"impl Unpin for AeadEncryptRequest","synthetic":true,"types":[]},{"text":"impl Unpin for AeadEncryptResponse","synthetic":true,"types":[]},{"text":"impl Unpin for AeadDecryptRequest","synthetic":true,"types":[]},{"text":"impl Unpin for AeadDecryptResponse","synthetic":true,"types":[]},{"text":"impl Unpin for DeterministicAeadEncryptRequest","synthetic":true,"types":[]},{"text":"impl Unpin for DeterministicAeadEncryptResponse","synthetic":true,"types":[]},{"text":"impl Unpin for DeterministicAeadDecryptRequest","synthetic":true,"types":[]},{"text":"impl Unpin for DeterministicAeadDecryptResponse","synthetic":true,"types":[]},{"text":"impl Unpin for StreamingAeadEncryptRequest","synthetic":true,"types":[]},{"text":"impl Unpin for StreamingAeadEncryptResponse","synthetic":true,"types":[]},{"text":"impl Unpin for StreamingAeadDecryptRequest","synthetic":true,"types":[]},{"text":"impl Unpin for StreamingAeadDecryptResponse","synthetic":true,"types":[]},{"text":"impl Unpin for ComputeMacRequest","synthetic":true,"types":[]},{"text":"impl Unpin for ComputeMacResponse","synthetic":true,"types":[]},{"text":"impl Unpin for VerifyMacRequest","synthetic":true,"types":[]},{"text":"impl Unpin for VerifyMacResponse","synthetic":true,"types":[]},{"text":"impl Unpin for HybridEncryptRequest","synthetic":true,"types":[]},{"text":"impl Unpin for HybridEncryptResponse","synthetic":true,"types":[]},{"text":"impl Unpin for HybridDecryptRequest","synthetic":true,"types":[]},{"text":"impl Unpin for HybridDecryptResponse","synthetic":true,"types":[]},{"text":"impl Unpin for SignatureSignRequest","synthetic":true,"types":[]},{"text":"impl Unpin for SignatureSignResponse","synthetic":true,"types":[]},{"text":"impl Unpin for SignatureVerifyRequest","synthetic":true,"types":[]},{"text":"impl Unpin for SignatureVerifyResponse","synthetic":true,"types":[]},{"text":"impl Unpin for PrfSetKeyIdsRequest","synthetic":true,"types":[]},{"text":"impl Unpin for PrfSetKeyIdsResponse","synthetic":true,"types":[]},{"text":"impl Unpin for PrfSetComputeRequest","synthetic":true,"types":[]},{"text":"impl Unpin for PrfSetComputeResponse","synthetic":true,"types":[]},{"text":"impl Unpin for Result","synthetic":true,"types":[]},{"text":"impl Unpin for Result","synthetic":true,"types":[]},{"text":"impl Unpin for Result","synthetic":true,"types":[]},{"text":"impl Unpin for Result","synthetic":true,"types":[]},{"text":"impl Unpin for Result","synthetic":true,"types":[]},{"text":"impl Unpin for Result","synthetic":true,"types":[]},{"text":"impl Unpin for Result","synthetic":true,"types":[]},{"text":"impl Unpin for Result","synthetic":true,"types":[]},{"text":"impl Unpin for Result","synthetic":true,"types":[]},{"text":"impl Unpin for Result","synthetic":true,"types":[]},{"text":"impl Unpin for Result","synthetic":true,"types":[]},{"text":"impl Unpin for Result","synthetic":true,"types":[]},{"text":"impl Unpin for Result","synthetic":true,"types":[]},{"text":"impl Unpin for Result","synthetic":true,"types":[]},{"text":"impl Unpin for Output","synthetic":true,"types":[]},{"text":"impl Unpin for Result","synthetic":true,"types":[]},{"text":"impl Unpin for Result","synthetic":true,"types":[]},{"text":"impl&lt;T&gt; Unpin for MetadataClient&lt;T&gt; <span class=\"where fmt-newline\">where<br>&nbsp;&nbsp;&nbsp;&nbsp;T: Unpin,&nbsp;</span>","synthetic":true,"types":[]},{"text":"impl&lt;T&gt; Unpin for KeysetClient&lt;T&gt; <span class=\"where fmt-newline\">where<br>&nbsp;&nbsp;&nbsp;&nbsp;T: Unpin,&nbsp;</span>","synthetic":true,"types":[]},{"text":"impl&lt;T&gt; Unpin for AeadClient&lt;T&gt; <span class=\"where fmt-newline\">where<br>&nbsp;&nbsp;&nbsp;&nbsp;T: Unpin,&nbsp;</span>","synthetic":true,"types":[]},{"text":"impl&lt;T&gt; Unpin for DeterministicAeadClient&lt;T&gt; <span class=\"where fmt-newline\">where<br>&nbsp;&nbsp;&nbsp;&nbsp;T: Unpin,&nbsp;</span>","synthetic":true,"types":[]},{"text":"impl&lt;T&gt; Unpin for StreamingAeadClient&lt;T&gt; <span class=\"where fmt-newline\">where<br>&nbsp;&nbsp;&nbsp;&nbsp;T: Unpin,&nbsp;</span>","synthetic":true,"types":[]},{"text":"impl&lt;T&gt; Unpin for MacClient&lt;T&gt; <span class=\"where fmt-newline\">where<br>&nbsp;&nbsp;&nbsp;&nbsp;T: Unpin,&nbsp;</span>","synthetic":true,"types":[]},{"text":"impl&lt;T&gt; Unpin for HybridClient&lt;T&gt; <span class=\"where fmt-newline\">where<br>&nbsp;&nbsp;&nbsp;&nbsp;T: Unpin,&nbsp;</span>","synthetic":true,"types":[]},{"text":"impl&lt;T&gt; Unpin for SignatureClient&lt;T&gt; <span class=\"where fmt-newline\">where<br>&nbsp;&nbsp;&nbsp;&nbsp;T: Unpin,&nbsp;</span>","synthetic":true,"types":[]},{"text":"impl&lt;T&gt; Unpin for PrfSetClient&lt;T&gt; <span class=\"where fmt-newline\">where<br>&nbsp;&nbsp;&nbsp;&nbsp;T: Unpin,&nbsp;</span>","synthetic":true,"types":[]},{"text":"impl&lt;T&gt; Unpin for MetadataServer&lt;T&gt;","synthetic":true,"types":[]},{"text":"impl&lt;T&gt; Unpin for _Inner&lt;T&gt;","synthetic":true,"types":[]},{"text":"impl&lt;T&gt; Unpin for KeysetServer&lt;T&gt;","synthetic":true,"types":[]},{"text":"impl&lt;T&gt; Unpin for _Inner&lt;T&gt;","synthetic":true,"types":[]},{"text":"impl&lt;T&gt; Unpin for AeadServer&lt;T&gt;","synthetic":true,"types":[]},{"text":"impl&lt;T&gt; Unpin for _Inner&lt;T&gt;","synthetic":true,"types":[]},{"text":"impl&lt;T&gt; Unpin for DeterministicAeadServer&lt;T&gt;","synthetic":true,"types":[]},{"text":"impl&lt;T&gt; Unpin for _Inner&lt;T&gt;","synthetic":true,"types":[]},{"text":"impl&lt;T&gt; Unpin for StreamingAeadServer&lt;T&gt;","synthetic":true,"types":[]},{"text":"impl&lt;T&gt; Unpin for _Inner&lt;T&gt;","synthetic":true,"types":[]},{"text":"impl&lt;T&gt; Unpin for MacServer&lt;T&gt;","synthetic":true,"types":[]},{"text":"impl&lt;T&gt; Unpin for _Inner&lt;T&gt;","synthetic":true,"types":[]},{"text":"impl&lt;T&gt; Unpin for HybridServer&lt;T&gt;","synthetic":true,"types":[]},{"text":"impl&lt;T&gt; Unpin for _Inner&lt;T&gt;","synthetic":true,"types":[]},{"text":"impl&lt;T&gt; Unpin for SignatureServer&lt;T&gt;","synthetic":true,"types":[]},{"text":"impl&lt;T&gt; Unpin for _Inner&lt;T&gt;","synthetic":true,"types":[]},{"text":"impl&lt;T&gt; Unpin for PrfSetServer&lt;T&gt;","synthetic":true,"types":[]},{"text":"impl&lt;T&gt; Unpin for _Inner&lt;T&gt;","synthetic":true,"types":[]},{"text":"impl Unpin for AeadServerImpl","synthetic":true,"types":[]},{"text":"impl Unpin for DaeadServerImpl","synthetic":true,"types":[]},{"text":"impl Unpin for KeysetServerImpl","synthetic":true,"types":[]},{"text":"impl Unpin for MacServerImpl","synthetic":true,"types":[]},{"text":"impl Unpin for MetadataServerImpl","synthetic":true,"types":[]},{"text":"impl Unpin for PrfSetServerImpl","synthetic":true,"types":[]},{"text":"impl Unpin for SignatureServerImpl","synthetic":true,"types":[]},{"text":"impl Unpin for StreamingAeadServerImpl","synthetic":true,"types":[]}];
implementors["tink_tests"] = [{"text":"impl Unpin for SharedBuf","synthetic":true,"types":[]},{"text":"impl Unpin for WycheproofSuite","synthetic":true,"types":[]},{"text":"impl Unpin for WycheproofGroup","synthetic":true,"types":[]},{"text":"impl Unpin for WycheproofCase","synthetic":true,"types":[]},{"text":"impl Unpin for DummyAeadKeyManager","synthetic":true,"types":[]},{"text":"impl Unpin for DummyAead","synthetic":true,"types":[]},{"text":"impl Unpin for DummyMac","synthetic":true,"types":[]},{"text":"impl Unpin for DummyKmsClient","synthetic":true,"types":[]},{"text":"impl Unpin for IoFailure","synthetic":true,"types":[]},{"text":"impl Unpin for WycheproofResult","synthetic":true,"types":[]}];
if (window.register_implementors) {window.register_implementors(implementors);} else {window.pending_implementors = implementors;}})()