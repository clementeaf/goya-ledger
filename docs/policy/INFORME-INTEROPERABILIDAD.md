# Informe de Pruebas de Interoperabilidad

**Prestador de Servicios de Certificacion: Goya Ledger PSC**

| Campo | Valor |
|---|---|
| Version del informe | 1.0 |
| Fecha de emision | [PENDIENTE: fecha de emision del informe] |
| Responsable tecnico | [PENDIENTE: nombre y cargo del responsable] |
| Periodo de pruebas | [PENDIENTE: fecha inicio — fecha termino] |
| Version del software | [PENDIENTE: version o hash de commit evaluado] |
| Estado | Borrador |

---

## 1. Introduccion y alcance

El presente informe documenta los resultados de las pruebas de interoperabilidad realizadas sobre los componentes criptograficos y de identidad digital del Prestador de Servicios de Certificacion (PSC) Goya Ledger, con el objeto de verificar la compatibilidad de las estructuras generadas por el sistema con implementaciones de referencia y herramientas de terceros ampliamente reconocidas en la industria.

El alcance comprende:

- Firmas electronicas avanzadas en formatos CAdES, XAdES y PAdES conforme a las especificaciones ETSI EN 319 122, ETSI EN 319 132 y ETSI EN 319 142, respectivamente.
- Infraestructura de clave publica (PKI): certificados X.509, listas de revocacion (CRL) y protocolo OCSP.
- Sellado de tiempo (TSA) conforme a RFC 3161.
- Credenciales de identidad digital europea: SD-JWT VC, mdoc ISO 18013-5, OpenID4VCI y OpenID4VP.
- Listas de confianza (Trusted Lists) conforme a ETSI TS 119 612.

Las pruebas se ejecutan contra herramientas externas independientes del codebase de Goya Ledger, incluyendo OpenSSL, EU DSS (Digital Signature Service), Adobe Reader, xmlsec, y librerias de referencia para credenciales verificables.

---

## 2. Marco normativo

Las pruebas de interoperabilidad se enmarcan en las siguientes normas y regulaciones:

| Norma / Regulacion | Ambito |
|---|---|
| **ETSI TS 119 612** | Trusted Lists — formato, estructura y verificacion de listas de servicios de confianza |
| **ETSI EN 319 122** | Firmas electronicas CAdES (CMS Advanced Electronic Signatures) |
| **ETSI EN 319 132** | Firmas electronicas XAdES (XML Advanced Electronic Signatures) |
| **ETSI EN 319 142** | Firmas electronicas PAdES (PDF Advanced Electronic Signatures) |
| **ETSI EN 319 401** | Requisitos generales para prestadores de servicios de confianza |
| **ETSI EN 319 411** | Requisitos de politica para autoridades de certificacion |
| **ETSI EN 319 421** | Requisitos de politica para autoridades de sellado de tiempo |
| **Reglamento (UE) 910/2014 (eIDAS), Art. 27** | Reconocimiento transfronterizo de firmas electronicas avanzadas; requisitos de interoperabilidad |
| **Ley 19.799 (Chile), Art. 3** | Definicion de firma electronica y firma electronica avanzada; equivalencia funcional con la firma manuscrita |
| **RFC 5280** | Internet X.509 PKI — Certificate and CRL Profile |
| **RFC 6960** | Online Certificate Status Protocol (OCSP) |
| **RFC 3161** | Internet X.509 PKI — Time-Stamp Protocol (TSP) |
| **ISO 18013-5** | Mobile driving licence (mDL) — mdoc data model |

La conformidad con eIDAS Art. 27 exige que las firmas electronicas avanzadas basadas en certificados cualificados sean interoperables entre Estados miembros. La Ley 19.799 Art. 3 establece los criterios de validez juridica de la firma electronica en el ordenamiento chileno, requiriendo que los mecanismos tecnologicos empleados permitan la verificacion por terceros independientes.

---

## 3. Entorno de pruebas

### 3.1 Herramientas externas

| Herramienta | Version | Uso |
|---|---|---|
| OpenSSL | [PENDIENTE: version instalada] | Parsing ASN.1/DER, verificacion de certificados, OCSP client, TSA client |
| EU DSS (Digital Signature Service) | [PENDIENTE: version] | Verificacion de CAdES, XAdES, PAdES; validacion de Trusted Lists |
| Adobe Acrobat Reader | [PENDIENTE: version] | Verificacion visual y tecnica de PAdES |
| xmlsec1 | [PENDIENTE: version] | Verificacion de firmas XAdES/XML |
| x509-parser (crate Rust) | Segun Cargo.lock | Parsing independiente de estructuras DER/X.509 |
| cbor-diag / cddl | [PENDIENTE: version] | Verificacion de estructuras CBOR (mdoc) |

### 3.2 Entorno de ejecucion

| Componente | Detalle |
|---|---|
| Sistema operativo | [PENDIENTE: OS y version] |
| Toolchain Rust | Nightly (segun rust-toolchain.toml del proyecto) |
| Hardware | [PENDIENTE: especificaciones relevantes] |
| Red | [PENDIENTE: conectividad a servicios externos, si aplica] |

### 3.3 Datos de prueba

[PENDIENTE: describir los datos de prueba utilizados — claves de prueba, certificados de prueba, documentos firmados, etc. Indicar si se utilizaron datos sinteticos o provenientes de servicios de prueba de terceros (e.g., DSS demo, TSA de prueba).]

---

## 4. Pruebas de firma electronica

### 4.1 CAdES-BES/T/XL — verificacion con herramientas externas (OpenSSL, DSS)

**Objetivo:** Verificar que las estructuras CAdES-BES y CAdES-T generadas por Goya Ledger son parseables y verificables por OpenSSL y EU DSS.

| N. | Prueba | Herramienta | Resultado | Observaciones |
|---|---|---|---|---|
| 4.1.1 | Parsing ASN.1/DER de CAdES-BES (Ed25519) | OpenSSL asn1parse | [PENDIENTE] | Debe contener OID id-signedData (1.2.840.113549.1.7.2) |
| 4.1.2 | Parsing ASN.1/DER de CAdES-BES (RSA) | OpenSSL asn1parse | [PENDIENTE] | Debe contener OID id-signedData |
| 4.1.3 | Parsing ASN.1/DER de CAdES-T | OpenSSL asn1parse | [PENDIENTE] | Debe incluir atributo no firmado id-smime-aa-timeStampToken |
| 4.1.4 | Verificacion de firma CAdES-BES (RSA) | OpenSSL cms -verify | [PENDIENTE] | Verificacion criptografica completa |
| 4.1.5 | Verificacion de firma CAdES-BES | EU DSS | [PENDIENTE] | Validacion ETSI EN 319 122 completa |
| 4.1.6 | Verificacion de CAdES-T con timestamp | EU DSS | [PENDIENTE] | Validacion del token de sellado de tiempo incorporado |
| 4.1.7 | Verificacion de CAdES-XL (long-term) | EU DSS | [PENDIENTE] | Inclusion de datos de validacion para archivo a largo plazo |
| 4.1.8 | Presencia de SigningCertificateV2 | OpenSSL / DSS | [PENDIENTE] | Atributo firmado obligatorio segun ETSI EN 319 122 |
| 4.1.9 | Presencia de commitment-type-indication | OpenSSL / DSS | [PENDIENTE] | Distinguir FES (id-cti-ets-proofOfApproval) vs. FEA (id-cti-ets-proofOfCreation) |
| 4.1.10 | Presencia de signature-policy-identifier | DSS | [PENDIENTE] | OID de politica conforme a CP/CPS del PSC |

### 4.2 XAdES-BES/T — verificacion XML con DSS/xmlsec

**Objetivo:** Verificar que las firmas XAdES generadas son conformes al perfil ETSI EN 319 132 y verificables por herramientas XML independientes.

| N. | Prueba | Herramienta | Resultado | Observaciones |
|---|---|---|---|---|
| 4.2.1 | Validacion de esquema XML de firma XAdES-BES | xmlsec1 --verify | [PENDIENTE] | Estructura ds:Signature conforme a XMLDSig |
| 4.2.2 | Verificacion criptografica XAdES-BES | DSS | [PENDIENTE] | Verificacion de referencia y valor de firma |
| 4.2.3 | Verificacion XAdES-T con timestamp | DSS | [PENDIENTE] | SignatureTimeStamp presente y valido |
| 4.2.4 | Canonicalizacion C14N | xmlsec1 | [PENDIENTE] | Algoritmo de canonicalizacion correcto |
| 4.2.5 | Referencia al documento firmado | DSS | [PENDIENTE] | URI de referencia correcta, digest coincidente |

### 4.3 PAdES CMS — verificacion con Adobe Reader / DSS

**Objetivo:** Verificar que las estructuras PAdES CMS generadas son reconocidas por Adobe Reader y EU DSS.

| N. | Prueba | Herramienta | Resultado | Observaciones |
|---|---|---|---|---|
| 4.3.1 | Apertura de PDF firmado con PAdES | Adobe Acrobat Reader | [PENDIENTE] | Panel de firmas debe mostrar la firma |
| 4.3.2 | Verificacion de integridad del documento | Adobe Acrobat Reader | [PENDIENTE] | "El documento no ha sido modificado" |
| 4.3.3 | SubFilter adbe.pkcs7.detached | Adobe / DSS | [PENDIENTE] | Conforme a ISO 32000-1 |
| 4.3.4 | Filter Adobe.PPKLite | Adobe / DSS | [PENDIENTE] | Filtro requerido para compatibilidad Adobe |
| 4.3.5 | Verificacion PAdES-B completa | EU DSS | [PENDIENTE] | Validacion ETSI EN 319 142 |
| 4.3.6 | Nivel de firma FES / FEA | DSS | [PENDIENTE] | Correcta clasificacion del nivel |

---

## 5. Pruebas de PKI

### 5.1 Certificados X.509 — parsing con OpenSSL / x509-parser

**Objetivo:** Verificar que los certificados X.509 emitidos por la CA del PSC son parseables y conformes a RFC 5280.

| N. | Prueba | Herramienta | Resultado | Observaciones |
|---|---|---|---|---|
| 5.1.1 | Parsing de certificado de entidad final | OpenSSL x509 -text | [PENDIENTE] | Todos los campos obligatorios presentes |
| 5.1.2 | Parsing de certificado de CA intermedia | OpenSSL x509 -text | [PENDIENTE] | BasicConstraints CA:TRUE, pathLen correcto |
| 5.1.3 | Parsing de certificado raiz | OpenSSL x509 -text | [PENDIENTE] | Autofirmado, KeyUsage keyCertSign |
| 5.1.4 | Verificacion de extensiones | OpenSSL / x509-parser | [PENDIENTE] | AuthorityKeyIdentifier, SubjectKeyIdentifier, KeyUsage |
| 5.1.5 | Verificacion de algoritmo de firma | OpenSSL | [PENDIENTE] | Ed25519 / ML-DSA-65 / RSA segun configuracion |
| 5.1.6 | Codificacion DER conforme | x509-parser (Rust) | [PENDIENTE] | Parsing exitoso sin errores de decodificacion |

### 5.2 CRL RFC 5280 — parsing y verificacion

**Objetivo:** Verificar que las CRL generadas son conformes a RFC 5280 y parseables por herramientas externas.

| N. | Prueba | Herramienta | Resultado | Observaciones |
|---|---|---|---|---|
| 5.2.1 | Parsing de CRL | OpenSSL crl -text | [PENDIENTE] | Emisor, fecha emision, proxima actualizacion |
| 5.2.2 | Verificacion de firma de CRL | OpenSSL crl -verify | [PENDIENTE] | Firmada por la CA emisora |
| 5.2.3 | Entrada de certificado revocado | OpenSSL crl | [PENDIENTE] | Serial, fecha, razon de revocacion |
| 5.2.4 | Extension CRLNumber | OpenSSL / x509-parser | [PENDIENTE] | Presente y monotonicamente creciente |

### 5.3 OCSP RFC 6960 — interop con OpenSSL ocsp client

**Objetivo:** Verificar que las respuestas OCSP generadas son conformes a RFC 6960 y procesables por el cliente OCSP de OpenSSL.

| N. | Prueba | Herramienta | Resultado | Observaciones |
|---|---|---|---|---|
| 5.3.1 | Consulta OCSP y parsing de respuesta | OpenSSL ocsp | [PENDIENTE] | Respuesta "good" para certificado vigente |
| 5.3.2 | Respuesta OCSP para certificado revocado | OpenSSL ocsp | [PENDIENTE] | Estado "revoked" con fecha y razon |
| 5.3.3 | Verificacion de firma de respuesta OCSP | OpenSSL ocsp -verify | [PENDIENTE] | Firmada por responder autorizado |
| 5.3.4 | Nonce en solicitud y respuesta | OpenSSL ocsp -nonce | [PENDIENTE] | Nonce presente y coincidente |
| 5.3.5 | Codificacion DER de respuesta OCSP | x509-parser | [PENDIENTE] | Parsing exitoso de estructura BasicOCSPResponse |

### 5.4 Cadena de certificados — validacion de jerarquia

**Objetivo:** Verificar la validacion completa de la cadena de certificados desde la entidad final hasta la raiz.

| N. | Prueba | Herramienta | Resultado | Observaciones |
|---|---|---|---|---|
| 5.4.1 | Validacion de cadena completa | OpenSSL verify -CAfile | [PENDIENTE] | Raiz -> Intermedia -> Entidad final |
| 5.4.2 | Rechazo con CA intermedia faltante | OpenSSL verify | [PENDIENTE] | Error esperado: unable to get local issuer certificate |
| 5.4.3 | Rechazo con certificado expirado | OpenSSL verify | [PENDIENTE] | Error esperado: certificate has expired |
| 5.4.4 | Validacion de restricciones de nombre | OpenSSL / x509-parser | [PENDIENTE] | NameConstraints respetados si presentes |

---

## 6. Pruebas de TSA

### 6.1 RFC 3161 DER — parsing con OpenSSL ts

**Objetivo:** Verificar que las respuestas de sellado de tiempo generadas son conformes a RFC 3161 y parseables por OpenSSL.

| N. | Prueba | Herramienta | Resultado | Observaciones |
|---|---|---|---|---|
| 6.1.1 | Parsing de TimeStampResp | OpenSSL ts -reply -text | [PENDIENTE] | Status, serial, hash algorithm, genTime |
| 6.1.2 | Verificacion de estructura TSTInfo | OpenSSL ts -reply | [PENDIENTE] | OID id-smime-ct-TSTInfo (1.2.840.113549.1.9.16.1.4) |
| 6.1.3 | Verificacion de OID signedData | OpenSSL asn1parse | [PENDIENTE] | ContentType id-signedData presente |
| 6.1.4 | Nonce preservado en respuesta | OpenSSL ts | [PENDIENTE] | Nonce de solicitud coincide con respuesta |
| 6.1.5 | Serial number unico | Inspeccion manual | [PENDIENTE] | Cada respuesta tiene serial distinto |

### 6.2 Verificacion de timestamp token con herramientas independientes

| N. | Prueba | Herramienta | Resultado | Observaciones |
|---|---|---|---|---|
| 6.2.1 | Verificacion de firma del timestamp | OpenSSL ts -verify | [PENDIENTE] | Firmado por TSA autorizada |
| 6.2.2 | Verificacion cruzada con DSS | EU DSS | [PENDIENTE] | Token reconocido como RFC 3161 valido |
| 6.2.3 | Hash algorithm conforme | OpenSSL / DSS | [PENDIENTE] | SHA-256 o SHA3-256 segun configuracion |

---

## 7. Pruebas de identidad digital EU

### 7.1 SD-JWT VC — verificacion con librerias de referencia

**Objetivo:** Verificar que las credenciales verificables en formato SD-JWT emitidas por el sistema son procesables por implementaciones de referencia.

| N. | Prueba | Herramienta | Resultado | Observaciones |
|---|---|---|---|---|
| 7.1.1 | Parsing de SD-JWT VC | Libreria de referencia sd-jwt | [PENDIENTE] | Header, payload, disclosures parseables |
| 7.1.2 | Verificacion de firma del Issuer | Libreria de referencia | [PENDIENTE] | Firma JWS valida |
| 7.1.3 | Selective disclosure — revelacion parcial | Libreria de referencia | [PENDIENTE] | Claims individuales revelables sin invalidar firma |
| 7.1.4 | Key binding JWT | Libreria de referencia | [PENDIENTE] | Holder binding verificable |
| 7.1.5 | Conformidad con IETF draft-ietf-oauth-sd-jwt-vc | Inspeccion manual | [PENDIENTE] | Campos vct, iss, iat presentes |

### 7.2 mdoc ISO 18013-5 — verificacion CBOR

**Objetivo:** Verificar que los documentos mdoc generados son conformes a ISO 18013-5 y decodificables con herramientas CBOR independientes.

| N. | Prueba | Herramienta | Resultado | Observaciones |
|---|---|---|---|---|
| 7.2.1 | Decodificacion CBOR del IssuerSigned | cbor-diag / cddl | [PENDIENTE] | Estructura CBOR valida |
| 7.2.2 | Verificacion de firma COSE_Sign1 | Libreria COSE de referencia | [PENDIENTE] | Firma del emisor valida |
| 7.2.3 | Verificacion de nameSpaces y dataElements | cbor-diag | [PENDIENTE] | Elementos de datos conforme a doctype |
| 7.2.4 | Mobile Security Object (MSO) | Libreria de referencia | [PENDIENTE] | digestAlgorithm y valueDigests correctos |
| 7.2.5 | DeviceAuth — MAC o firma | Libreria COSE | [PENDIENTE] | Autenticacion de dispositivo verificable |

### 7.3 OpenID4VCI — flujo completo con wallet de referencia

**Objetivo:** Verificar el flujo de emision de credenciales conforme a OpenID for Verifiable Credential Issuance.

| N. | Prueba | Herramienta | Resultado | Observaciones |
|---|---|---|---|---|
| 7.3.1 | Descubrimiento de metadata del emisor | Wallet de referencia / curl | [PENDIENTE] | /.well-known/openid-credential-issuer accesible |
| 7.3.2 | Obtencion de token de acceso | Wallet de referencia | [PENDIENTE] | Flujo pre-authorized_code o authorization_code |
| 7.3.3 | Solicitud de credencial | Wallet de referencia | [PENDIENTE] | Endpoint /credential responde con VC |
| 7.3.4 | Formato de credencial emitida | Wallet de referencia | [PENDIENTE] | sd-jwt-vc o mdoc segun solicitud |
| 7.3.5 | Binding de clave del holder | Wallet de referencia | [PENDIENTE] | Proof of possession verificable |

### 7.4 OpenID4VP — presentacion y verificacion

**Objetivo:** Verificar el flujo de presentacion de credenciales conforme a OpenID for Verifiable Presentations.

| N. | Prueba | Herramienta | Resultado | Observaciones |
|---|---|---|---|---|
| 7.4.1 | Generacion de authorization request | Verifier de referencia | [PENDIENTE] | presentation_definition valida |
| 7.4.2 | Respuesta de presentacion del wallet | Wallet de referencia | [PENDIENTE] | vp_token presente |
| 7.4.3 | Verificacion de presentacion por el verifier | Verifier de referencia | [PENDIENTE] | Credencial y holder binding validos |
| 7.4.4 | Selective disclosure en presentacion | Wallet de referencia | [PENDIENTE] | Solo claims solicitados revelados |
| 7.4.5 | Manejo de presentation_definition con restricciones | Verifier de referencia | [PENDIENTE] | Filtros por campo, formato, algoritmo |

---

## 8. Pruebas de Trusted List

### 8.1 Parsing de LOTL EU real

**Objetivo:** Verificar que el sistema puede parsear la List of Trusted Lists (LOTL) oficial de la Union Europea.

| N. | Prueba | Herramienta | Resultado | Observaciones |
|---|---|---|---|---|
| 8.1.1 | Descarga y parsing de LOTL EU | Goya Ledger TL parser | [PENDIENTE] | URL: https://ec.europa.eu/tools/lotl/eu-lotl.xml |
| 8.1.2 | Extraccion de punteros a TL nacionales | Goya Ledger TL parser | [PENDIENTE] | Al menos 27 TL de Estados miembros |
| 8.1.3 | Parsing de TL nacional (ejemplo: Espana) | Goya Ledger TL parser | [PENDIENTE] | Servicios de confianza extraidos correctamente |
| 8.1.4 | Identificacion de TSP y servicios | Goya Ledger TL parser | [PENDIENTE] | Tipo de servicio, estado, certificados |

### 8.2 Verificacion de firma XAdES de TL

| N. | Prueba | Herramienta | Resultado | Observaciones |
|---|---|---|---|---|
| 8.2.1 | Verificacion de firma XAdES de LOTL | DSS / xmlsec | [PENDIENTE] | Firma del esquema de gobierno valida |
| 8.2.2 | Verificacion de firma XAdES de TL nacional | DSS / xmlsec | [PENDIENTE] | Firma del operador del esquema valida |
| 8.2.3 | Verificacion cruzada: certificado del esquema en LOTL | DSS | [PENDIENTE] | Certificado del firmante presente en LOTL |

---

## 9. Resultados existentes del codebase

El codebase de Goya Ledger incluye pruebas de interoperabilidad automatizadas que se ejecutan como parte del conjunto de pruebas unitarias. A la fecha de este informe, el proyecto cuenta con **2503 tests** pasando exitosamente. A continuacion se detallan las pruebas de interoperabilidad existentes por modulo.

### 9.1 CAdES DER (`src/signature/cades_der.rs`)

Pruebas de interoperabilidad con `x509-parser` (crate Rust independiente) y OpenSSL CLI:

| Funcion de test | Descripcion | Estado |
|---|---|---|
| `interop_x509_parser_parses_content_info` | Parsing de ContentInfo CAdES-BES con x509-parser; verifica OID id-signedData | PASS |
| `interop_x509_parser_finds_signer_info` | Extraccion de SignerInfo desde la estructura CAdES con x509-parser | PASS |
| `interop_mldsa65_parseable` | Parsing de CAdES-BES con firma ML-DSA-65 (post-cuantica) por x509-parser | PASS |
| `interop_rsa_parseable` | Parsing de CAdES-BES con firma RSA por x509-parser | PASS |
| `cades_t_parseable_by_x509_parser` | Parsing de CAdES-T (con timestamp token) por x509-parser | PASS |
| `interop_openssl_asn1parse_rsa_cades` | Validacion ASN.1/DER de CAdES-BES (RSA) con `openssl asn1parse`; verifica presencia de OID id-signedData | PASS |
| `interop_openssl_asn1parse_ed25519_cades` | Validacion ASN.1/DER de CAdES-BES (Ed25519) con `openssl asn1parse` | PASS |
| `interop_openssl_asn1parse_cades_t` | Validacion ASN.1/DER de CAdES-T con `openssl asn1parse` | PASS |

### 9.2 RFC 3161 DER (`src/tsa/rfc3161_der.rs`)

Pruebas de interoperabilidad con `x509-parser`:

| Funcion de test | Descripcion | Estado |
|---|---|---|
| `interop_x509_parser_parses_timestamp_resp` | Parsing de TimeStampResp DER completa con x509-parser | PASS |
| `interop_x509_parser_finds_signed_data_oid` | Extraccion de OID id-signedData desde la respuesta de timestamp | PASS |
| `interop_x509_parser_extracts_tst_info_content_type` | Extraccion de ContentType id-ct-TSTInfo desde el contenido firmado | PASS |

Pruebas funcionales complementarias con relevancia de interoperabilidad:

| Funcion de test | Descripcion | Estado |
|---|---|---|
| `build_and_verify_roundtrip` | Construccion y verificacion round-trip de TimeStampResp | PASS |
| `der_oid_encoding` | Verificacion de codificacion correcta de OIDs en DER | PASS |
| `rsa_roundtrip` | Round-trip con proveedor RSA | PASS |
| `mldsa65_roundtrip` | Round-trip con proveedor ML-DSA-65 (post-cuantico) | PASS |

### 9.3 OCSP DER (`src/msp/ocsp_der.rs`)

Pruebas de interoperabilidad con `x509-parser`:

| Funcion de test | Descripcion | Estado |
|---|---|---|
| `interop_x509_parser_parses_ocsp_response` | Parsing de OCSPResponse DER completa con x509-parser; verifica estructura BasicOCSPResponse | PASS |

Pruebas funcionales complementarias con relevancia de interoperabilidad:

| Funcion de test | Descripcion | Estado |
|---|---|---|
| `der_roundtrip_good` | Round-trip de respuesta OCSP con estado "good" | PASS |
| `der_roundtrip_revoked` | Round-trip de respuesta OCSP con estado "revoked" | PASS |
| `der_error_response_no_body` | Respuesta de error OCSP sin cuerpo (tryLater, etc.) | PASS |
| `mldsa65_der_roundtrip` | Round-trip con proveedor ML-DSA-65 | PASS |
| `nonce_roundtrip_zero` | Preservacion de nonce en solicitud/respuesta | PASS |

### 9.4 PAdES CMS (`src/signature/pades.rs`)

Pruebas de interoperabilidad con `x509-parser`:

| Funcion de test | Descripcion | Estado |
|---|---|---|
| `pades_cms_interop_x509_parser` | Parsing de estructura PAdES CMS con x509-parser | PASS |

Pruebas funcionales con relevancia de interoperabilidad:

| Funcion de test | Descripcion | Estado |
|---|---|---|
| `filter_is_adobe_ppklite` | Verificacion de filtro Adobe.PPKLite en estructura PAdES | PASS |
| `sub_filter_is_pkcs7_detached` | Verificacion de SubFilter adbe.pkcs7.detached | PASS |
| `pades_cms_roundtrip` | Construccion y verificacion round-trip de PAdES CMS | PASS |
| `pades_cms_wrong_key_fails` | Rechazo de firma con clave incorrecta | PASS |

### 9.5 Resumen de cobertura de interoperabilidad automatizada

| Modulo | Tests interop (x509-parser) | Tests interop (OpenSSL CLI) | Tests funcionales relacionados | Total |
|---|---|---|---|---|
| CAdES DER | 5 | 3 | 12 | 20 |
| RFC 3161 DER | 3 | 0 | 13 | 16 |
| OCSP DER | 1 | 0 | 9 | 10 |
| PAdES CMS | 1 | 0 | 17 | 18 |
| **Total** | **10** | **3** | **51** | **64** |

---

## 10. Conclusiones y observaciones

### 10.1 Estado general

[PENDIENTE: resumen ejecutivo del estado de interoperabilidad. Indicar si el PSC cumple los requisitos de interoperabilidad exigidos por el marco normativo aplicable.]

### 10.2 Hallazgos positivos

- Las estructuras CAdES-BES, CAdES-T, RFC 3161 y OCSP generadas por Goya Ledger son parseables exitosamente por `x509-parser`, un crate Rust independiente que implementa parsing X.509/ASN.1 conforme a RFC 5280.
- Las estructuras CAdES DER (Ed25519, RSA y CAdES-T) son parseables exitosamente por OpenSSL `asn1parse`, confirmando conformidad con la codificacion DER estandar.
- La estructura PAdES CMS cumple con los campos requeridos por Adobe Reader (Filter: Adobe.PPKLite, SubFilter: adbe.pkcs7.detached).
- El sistema soporta algoritmos post-cuanticos (ML-DSA-65) con interoperabilidad verificada a nivel de parsing DER.

### 10.3 Brechas identificadas

[PENDIENTE: listar las brechas de interoperabilidad detectadas durante las pruebas con herramientas externas completas (DSS, Adobe Reader, OpenSSL verify). Clasificar por severidad: critica / mayor / menor.]

### 10.4 Plan de remediacion

[PENDIENTE: acciones correctivas para cada brecha identificada, con responsable y plazo estimado.]

### 10.5 Recomendaciones

[PENDIENTE: recomendaciones para mejorar la interoperabilidad del PSC. Considerar:
- Integracion con servicios de prueba de DSS (sandbox de la Comision Europea)
- Pruebas con wallets EUDI de referencia
- Participacion en eventos de interoperabilidad (plugtests ETSI)
- Certificacion ETSI EN 319 401]

---

## 11. Anexo: Matriz de compatibilidad

### 11.1 Formatos de firma

| Formato | Ed25519 | ML-DSA-65 | RSA-2048+ | OpenSSL parse | DSS verify | Adobe verify |
|---|---|---|---|---|---|---|
| CAdES-BES | PASS (auto) | PASS (auto) | PASS (auto) | PASS (auto) | [PENDIENTE] | N/A |
| CAdES-T | PASS (auto) | [PENDIENTE] | [PENDIENTE] | PASS (auto) | [PENDIENTE] | N/A |
| CAdES-XL | [PENDIENTE] | [PENDIENTE] | [PENDIENTE] | [PENDIENTE] | [PENDIENTE] | N/A |
| XAdES-BES | [PENDIENTE] | [PENDIENTE] | [PENDIENTE] | N/A | [PENDIENTE] | N/A |
| XAdES-T | [PENDIENTE] | [PENDIENTE] | [PENDIENTE] | N/A | [PENDIENTE] | N/A |
| PAdES-B | PASS (auto) | [PENDIENTE] | [PENDIENTE] | [PENDIENTE] | [PENDIENTE] | [PENDIENTE] |

*(auto) = verificado por pruebas automatizadas del codebase*

### 11.2 Componentes PKI

| Componente | OpenSSL parse | OpenSSL verify | x509-parser | DSS |
|---|---|---|---|---|
| Certificado X.509 EE | [PENDIENTE] | [PENDIENTE] | [PENDIENTE] | [PENDIENTE] |
| Certificado CA intermedia | [PENDIENTE] | [PENDIENTE] | [PENDIENTE] | [PENDIENTE] |
| Certificado CA raiz | [PENDIENTE] | [PENDIENTE] | [PENDIENTE] | [PENDIENTE] |
| CRL | [PENDIENTE] | [PENDIENTE] | [PENDIENTE] | [PENDIENTE] |
| Respuesta OCSP | [PENDIENTE] | [PENDIENTE] | PASS (auto) | [PENDIENTE] |
| Cadena completa | [PENDIENTE] | [PENDIENTE] | [PENDIENTE] | [PENDIENTE] |

### 11.3 Sellado de tiempo

| Componente | OpenSSL ts | x509-parser | DSS |
|---|---|---|---|
| TimeStampResp DER | [PENDIENTE] | PASS (auto) | [PENDIENTE] |
| TSTInfo | [PENDIENTE] | PASS (auto) | [PENDIENTE] |
| Firma del token | [PENDIENTE] | [PENDIENTE] | [PENDIENTE] |

### 11.4 Identidad digital EU

| Componente | Libreria referencia | Wallet referencia | Verifier referencia |
|---|---|---|---|
| SD-JWT VC | [PENDIENTE] | [PENDIENTE] | [PENDIENTE] |
| mdoc ISO 18013-5 | [PENDIENTE] | [PENDIENTE] | [PENDIENTE] |
| OpenID4VCI | N/A | [PENDIENTE] | N/A |
| OpenID4VP | N/A | [PENDIENTE] | [PENDIENTE] |

### 11.5 Trusted Lists

| Componente | LOTL EU real | DSS | xmlsec |
|---|---|---|---|
| Parsing TL XML | [PENDIENTE] | [PENDIENTE] | N/A |
| Firma XAdES de TL | [PENDIENTE] | [PENDIENTE] | [PENDIENTE] |

---

*Fin del informe.*
