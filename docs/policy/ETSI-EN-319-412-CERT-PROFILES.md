# ETSI EN 319 412 Certificate Profiles

| Campo | Valor |
|-------|-------|
| **ID** | GOYA-CERT-PROF-001 |
| **Version** | 1.0 |
| **Fecha** | 2026-09-03 |
| **Base normativa** | ETSI EN 319 412-1 (overview), 412-2 (natural persons), 412-3 (legal persons), 412-4 (QWAC), 412-5 (QCStatements) |
| **Referencia CP/CPS** | GOYA-PO01-001 / docs/policy/CPS.md |

## 1. Alcance

Este documento define los perfiles de certificado X.509 emitidos por la CA de Goya Ledger, conforme a ETSI EN 319 412 partes 1 a 5 y RFC 5280.

## 2. Extensiones comunes a todos los certificados

| Extension | OID | Criticidad | Valor |
|-----------|-----|------------|-------|
| Version | -- | -- | v3 (2) |
| Serial Number | -- | -- | 128-bit aleatorio criptografico |
| Authority Key Identifier | `2.5.29.35` | No critica | SHA-1 hash de la clave publica de la CA emisora |
| Subject Key Identifier | `2.5.29.14` | No critica | SHA-1 hash de la clave publica del sujeto |
| Key Usage | `2.5.29.15` | Critica | Per perfil |
| Basic Constraints | `2.5.29.19` | Critica | CA: FALSE (certificados de suscriptor) |
| Certificate Policies | `2.5.29.32` | No critica | CP OID `1.3.6.1.4.1.{PEN}.2.1` + CPS URI `https://goya.cl/pki/cp` |
| Authority Information Access | `1.3.6.1.5.5.7.1.1` | No critica | OCSP: `https://goya.cl/pki/ocsp`; CA Issuers: `https://goya.cl/pki/ca.crt` |
| CRL Distribution Points | `2.5.29.31` | No critica | `https://goya.cl/pki/crl.der` |

## 3. Perfil FES — Persona Natural (Firma Electronica Simple)

**Referencia:** ETSI EN 319 412-2 (natural persons)

| Campo | Valor |
|-------|-------|
| Algoritmo de firma | Ed25519 (RFC 8032) |
| Subject DN | `CN={nombre}, serialNumber=did:goya:{pubkey_hex[..16]}, C=CL` |
| Key Usage | `digitalSignature` |
| Extended Key Usage | No incluido |
| QCStatements | No incluido (no cualificado) |
| Validez | 365 dias |
| Nivel de aseguramiento | Bajo |

## 4. Perfil FEA — Persona Natural (Firma Electronica Avanzada)

**Referencia:** ETSI EN 319 412-2 (natural persons) + EN 319 412-5 (QCStatements)

| Campo | Valor |
|-------|-------|
| Algoritmo de firma CA | ML-DSA-65 (FIPS 204) |
| Subject DN | `CN={nombre}, serialNumber={RUT}, OI=NTRCL-{RUT}, C=CL` |
| Key Usage | `digitalSignature`, `nonRepudiation` |
| Extended Key Usage | No incluido |
| Subject Alternative Name | `email:{correo}` (cuando disponible) |
| QCStatements | `id-etsi-qcs-QcCompliance` (`0.4.0.1862.1.1`), `id-etsi-qcs-QcType` = `id-etsi-qct-esign` (`0.4.0.1862.1.6.1`) |
| Validez | 365 dias |
| Nivel de aseguramiento | Sustancial |
| Requisito biometrico | Minimo 1 BiometricEvidence (SHA-256 commitment) |

## 5. Perfil e-Seal — Persona Juridica (Sello Electronico)

**Referencia:** ETSI EN 319 412-3 (legal persons)

| Campo | Valor |
|-------|-------|
| Algoritmo de firma CA | ML-DSA-65 (FIPS 204) |
| Subject DN | `O={razon_social}, serialNumber={RUT}, OI=NTRCL-{RUT}, C=CL` |
| Key Usage | `digitalSignature`, `nonRepudiation` |
| Extended Key Usage | No incluido |
| QCStatements | `id-etsi-qcs-QcCompliance`, `id-etsi-qcs-QcType` = `id-etsi-qct-eseal` (`0.4.0.1862.1.6.2`) |
| Validez | 365 dias |
| Nivel de aseguramiento | Alto |

## 6. Perfil QWAC — Autenticacion Web (Website Authentication)

**Referencia:** ETSI EN 319 412-4

| Campo | Valor |
|-------|-------|
| Algoritmo de firma CA | ML-DSA-65 (FIPS 204) |
| Subject DN | `CN={fqdn}, O={razon_social}, OI=NTRCL-{RUT}, C=CL` |
| Key Usage | `digitalSignature`, `keyEncipherment` |
| Extended Key Usage | `id-kp-serverAuth` (`1.3.6.1.5.5.7.3.1`) |
| Subject Alternative Name | `dNSName:{fqdn}` (uno o mas FQDN del servicio web) |
| QCStatements | `id-etsi-qcs-QcCompliance`, `id-etsi-qcs-QcType` = `id-etsi-qct-web` (`0.4.0.1862.1.6.3`) |
| Validacion de dominio | Per CA/Browser Forum Baseline Requirements seccion 3.2.2 |
| Validez | 365 dias |
| Nivel de aseguramiento | Alto |

## 7. Perfil TSA — Certificado de Firma TSA

**Referencia:** ETSI EN 319 421 seccion 7.2

| Campo | Valor |
|-------|-------|
| Algoritmo de firma CA | ML-DSA-65 (FIPS 204) |
| Subject DN | `CN=Goya Ledger TSA, O=Goya Ledger SpA, C=CL` |
| Key Usage | `digitalSignature` |
| Extended Key Usage | `id-kp-timeStamping` (`1.3.6.1.5.5.7.3.8`) |
| QCStatements | No incluido (pendiente QTSP status) |
| Validez | 730 dias |

## 8. Perfil CA Raiz (Self-signed)

| Campo | Valor |
|-------|-------|
| Algoritmo de firma | ML-DSA-65 (FIPS 204) |
| Subject DN | `CN=Goya Ledger Root CA, O=Goya Ledger SpA, C=CL` |
| Key Usage | `keyCertSign`, `cRLSign` |
| Basic Constraints | `CA: TRUE` |
| Path Length Constraint | Sin limite |
| Validez | 10 anos |

## 9. Perfil CA Intermedia

| Campo | Valor |
|-------|-------|
| Algoritmo de firma CA raiz | ML-DSA-65 (FIPS 204) |
| Subject DN | `CN=Goya Ledger Intermediate CA, O=Goya Ledger SpA, C=CL` |
| Key Usage | `keyCertSign`, `cRLSign`, `digitalSignature` |
| Basic Constraints | `CA: TRUE, pathLen: 0` |
| Validez | 5 anos |

## 10. Formato de CRL

**Referencia:** RFC 5280 seccion 5

| Campo | Valor |
|-------|-------|
| Algoritmo de firma | ML-DSA-65 (FIPS 204) |
| Issuer | CA Intermedia DN |
| This Update | Momento de emision (UTC) |
| Next Update | This Update + 24 horas |
| CRL Number | Monotonicamente creciente |
| Revoked Certificates | Lista de serial + fecha de revocacion + razon (CRL reason code) |
| Punto de distribucion | `https://goya.cl/pki/crl.der` |

## 11. Respuesta OCSP

**Referencia:** RFC 6960

| Campo | Valor |
|-------|-------|
| Algoritmo de firma | ML-DSA-65 (FIPS 204) |
| Responder ID | By key hash (SHA-256 del public key del responder) |
| Produced At | Momento de generacion (UTC) |
| Certificate Status | good / revoked / unknown |
| This Update | Momento de consulta |
| Next Update | This Update + 1 hora |
| Endpoint | `https://goya.cl/pki/ocsp` |

## 12. Mapeo de OIDs

| OID | Descripcion | Referencia |
|-----|-------------|------------|
| `1.3.6.1.4.1.{PEN}.2.1` | Certificate Policy (CP) | docs/policy/CP.md |
| `1.3.6.1.4.1.{PEN}.2.2` | Certification Practice Statement (CPS) | docs/policy/CPS.md |
| `1.3.6.1.4.1.{PEN}.1.1` | TSA Policy | GOYA-TSA-POL-001 |
| `0.4.0.1862.1.1` | QcCompliance | ETSI EN 319 412-5 |
| `0.4.0.1862.1.6.1` | QcType: esign | ETSI EN 319 412-5 |
| `0.4.0.1862.1.6.2` | QcType: eseal | ETSI EN 319 412-5 |
| `0.4.0.1862.1.6.3` | QcType: web | ETSI EN 319 412-5 |

Nota: `{PEN}` sera reemplazado por el IANA Private Enterprise Number una vez asignado. Registro pendiente en https://pen.iana.org/pen/PenApplication.page.

## 13. Referencias

| Referencia | Titulo |
|-----------|--------|
| ETSI EN 319 412-1 | Certificate profiles -- Part 1: Overview |
| ETSI EN 319 412-2 | Certificate profiles -- Part 2: Natural persons |
| ETSI EN 319 412-3 | Certificate profiles -- Part 3: Legal persons |
| ETSI EN 319 412-4 | Certificate profiles -- Part 4: Web site certificates |
| ETSI EN 319 412-5 | Certificate profiles -- Part 5: QCStatements |
| RFC 5280 | Internet X.509 PKI Certificate and CRL Profile |
| RFC 6960 | X.509 Internet PKI OCSP |
| FIPS 204 | ML-DSA (Module-Lattice-Based Digital Signature Algorithm) |
| CA/BF BRs | CA/Browser Forum Baseline Requirements |
