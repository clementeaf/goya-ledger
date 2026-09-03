# ETSI EN 319 422 TSA Token Profile

| Campo | Valor |
|-------|-------|
| **ID** | GOYA-TSA-PROF-001 |
| **Version** | 1.0 |
| **Fecha** | 2026-09-03 |
| **Base normativa** | ETSI EN 319 422 V1.1.1, RFC 3161, RFC 5816 |
| **Referencia TSA Policy** | GOYA-TSA-POL-001 (`docs/policy/ETSI-EN-319-421-TSA-POLICY.md`) |

## 1. Alcance

Este documento define el perfil de tokens de sello de tiempo emitidos por la TSA de Goya Ledger, conforme a ETSI EN 319 422 y RFC 3161. La TSA emite tokens en dos formatos: JSON (nativo) y DER (RFC 3161 compatible).

## 2. Formato JSON (nativo)

### 2.1 Estructura TimeStampRequest

| Campo | Tipo | Obligatorio | Descripcion |
|-------|------|-------------|-------------|
| `message_imprint` | string (hex) | Si | SHA-256 o SHA3-256 hash del dato a sellar (64 chars hex) |
| `nonce` | u64 | No | Valor aleatorio del cliente para proteccion anti-replay |
| `require_ordering` | bool | No | Si el cliente requiere garantia de ordenamiento (default: false) |

### 2.2 Estructura TstInfo

| Campo | Tipo | Valor | RFC 3161 equiv |
|-------|------|-------|----------------|
| `version` | u32 | 1 | TSTInfo.version |
| `policy` | string | `1.3.6.1.4.1.{PEN}.1.1` | TSTInfo.policy |
| `hash_algorithm` | enum | `Sha256` o `Sha3_256` | MessageImprint.hashAlgorithm |
| `message_imprint` | string (hex) | Hash del dato sellado | MessageImprint.hashedMessage |
| `serial_number` | u64 | Monotonicamente creciente, nunca reciclado | TSTInfo.serialNumber |
| `gen_time` | u64 | UNIX timestamp UTC (segundos) | TSTInfo.genTime (GeneralizedTime) |
| `accuracy_secs` | u32 | 1 (default) | TSTInfo.accuracy |
| `ordering` | bool | Per request | TSTInfo.ordering |
| `nonce` | u64 (opcional) | Echo del nonce del cliente | TSTInfo.nonce |
| `tsa_name` | string | DID de la TSA (`did:goya:{pubkey_hex[..16]}`) | TSTInfo.tsa (GeneralName) |

### 2.3 Estructura TimeStampToken

| Campo | Tipo | Descripcion |
|-------|------|-------------|
| `id` | string | UUID v4 unico del token |
| `tst_info` | TstInfo | Contenido del sello de tiempo |
| `signature` | string (hex) | Firma sobre el payload canonico del TstInfo |
| `public_key` | string (hex) | Clave publica de la TSA |
| `signature_algorithm` | enum | `Ed25519`, `MlDsa65`, `EcdsaP256`, o `SlhDsa128s` |

### 2.4 Payload canonico de firma

La firma se calcula sobre la representacion canonica del TstInfo:

```
"{policy}|{hash_algorithm}|{message_imprint}|{serial_number}|{gen_time}|{accuracy_secs}|{ordering}|{nonce_or_empty}|{tsa_name}"
```

Campos separados por `|`. El nonce se omite (campo vacio) si no fue proporcionado por el cliente.

### 2.5 Verificacion de token JSON

1. Reconstruir el payload canonico a partir de los campos del TstInfo.
2. Verificar la firma contra el payload usando la clave publica y el algoritmo declarado.
3. Verificar que el hash_algorithm y message_imprint coinciden con el dato original.
4. Verificar que el nonce (si fue enviado) coincide con el solicitado.

Implementado en `src/tsa/mod.rs` funcion `verify_token()`.

## 3. Formato DER (RFC 3161)

### 3.1 Estructura ASN.1

El formato DER sigue la estructura ASN.1 definida en RFC 3161 seccion 2.4.2:

```asn1
TimeStampResp ::= SEQUENCE {
    status          PKIStatusInfo,
    timeStampToken  ContentInfo OPTIONAL
}

TSTInfo ::= SEQUENCE {
    version         INTEGER { v1(1) },
    policy          TSAPolicyId,
    messageImprint  MessageImprint,
    serialNumber    INTEGER,
    genTime         GeneralizedTime,
    accuracy        Accuracy OPTIONAL,
    ordering        BOOLEAN DEFAULT FALSE,
    nonce           INTEGER OPTIONAL,
    tsa             [0] GeneralName OPTIONAL
}
```

### 3.2 Codificacion DER

Implementado en `src/tsa/rfc3161_der.rs`:

| Campo ASN.1 | Tag | Codificacion |
|-------------|-----|-------------|
| version | INTEGER (0x02) | Valor fijo: 1 |
| policy | OID (0x06) | OID de la TSA policy |
| messageImprint | SEQUENCE | AlgorithmIdentifier + OCTET STRING |
| serialNumber | INTEGER (0x02) | Big-endian, sin leading zeros |
| genTime | GeneralizedTime (0x18) | `YYYYMMDDHHmmSSZ` (UTC) |
| accuracy | SEQUENCE (opcional) | seconds INTEGER |
| ordering | BOOLEAN (0x01) | Solo presente si TRUE |
| nonce | INTEGER (opcional) | Echo del cliente |
| tsa | [0] EXPLICIT GeneralName | uniformResourceIdentifier (DID) |

### 3.3 Algoritmos de firma en DER

| Algoritmo | AlgorithmIdentifier OID | Tamano firma |
|-----------|------------------------|-------------|
| Ed25519 | `1.3.101.112` | 64 B |
| ML-DSA-65 | `2.16.840.1.101.3.4.3.18` (FIPS 204) | 3,309 B |
| ECDSA P-256 | `1.2.840.10045.4.3.2` (SHA-256) | ~70 B (DER-encoded r,s) |
| SLH-DSA-128s | `2.16.840.1.101.3.4.3.21` (FIPS 205) | 7,856 B |

### 3.4 PKIStatusInfo

| Status | Valor | Descripcion |
|--------|-------|-------------|
| granted | 0 | Token emitido exitosamente |
| rejection | 2 | Solicitud rechazada (hash invalido, politica no soportada) |

Status 1 (grantedWithMods), 3 (waiting), 4 (revocationWarning), 5 (revocationNotification) no son emitidos por esta TSA.

## 4. Algoritmos soportados

### 4.1 Algoritmos de hash (message imprint)

| Algoritmo | OID | Tamano hash | Estado |
|-----------|-----|-------------|--------|
| SHA-256 | `2.16.840.1.101.3.4.2.1` | 32 B | Default |
| SHA3-256 | `2.16.840.1.101.3.4.2.8` | 32 B | Recomendado (BSI TR-02102-1) |

### 4.2 Algoritmos de firma TSA

| Algoritmo | Estandar | Estado BSI | Uso |
|-----------|----------|------------|-----|
| ML-DSA-65 | FIPS 204 | Recommended | Produccion (default) |
| Ed25519 | RFC 8032 | Transitional | Legacy / interoperabilidad |
| ECDSA P-256 | FIPS 186-5 | Transitional | OID4VCI interop |
| SLH-DSA-128s | FIPS 205 | Recommended | Backup (hash-based) |

## 5. Requisitos operacionales

### 5.1 Precision temporal

| Parametro | Valor |
|-----------|-------|
| Fuente de tiempo | NTP (configurable via `NtpTimeSource`) |
| Accuracy declarada | 1 segundo (default, configurable) |
| Drift maximo tolerado | Configurable; el token se rechaza si NTP no esta disponible |
| Formato de tiempo | UNIX timestamp (JSON), GeneralizedTime UTC (DER) |

### 5.2 Numero de serie

| Parametro | Valor |
|-----------|-------|
| Tipo | u64 (monotonicamente creciente) |
| Persistencia | Archivo en disco, actualizado en cada emision |
| Unicidad | Garantizada por incremento atomico; nunca reciclado |
| Capacidad | 1.8 x 10^19 valores |

### 5.3 Self-check pre-emision

Antes de cada emision, la TSA ejecuta `validate_signer()`:

1. Genera mensaje de prueba.
2. Firma con la clave TSA.
3. Verifica la firma.
4. Si falla, rechaza la solicitud (fail-closed).

## 6. Interoperabilidad

### 6.1 Verificacion externa

Los tokens JSON pueden verificarse con cualquier implementacion que soporte el algoritmo de firma declarado y reconstruya el payload canonico.

Los tokens DER son verificables con herramientas estandar:

```
openssl ts -verify -in token.tsr -data original_file -CAfile ca.pem
```

Nota: `openssl ts` no soporta ML-DSA-65 nativamente. Verificacion PQC requiere herramientas que soporten FIPS 204.

### 6.2 Compatibilidad con ETSI EN 319 422

| Requisito EN 319 422 | Cumplimiento |
|-----------------------|-------------|
| Token basado en RFC 3161 | Si (formato DER) |
| Policy OID en el token | Si |
| Accuracy declarada | Si (configurable) |
| Nonce echo | Si (cuando proporcionado) |
| Serial number unico | Si (monotonicamente creciente) |
| Ordenamiento opcional | Si (campo ordering) |
| Firma con algoritmo aprobado | Si (ML-DSA-65, Ed25519, ECDSA) |

## 7. Referencias

| Referencia | Titulo |
|-----------|--------|
| ETSI EN 319 422 V1.1.1 | Profiles for TSA and TSU |
| RFC 3161 | Internet X.509 PKI Time-Stamp Protocol |
| RFC 5816 | ESSCertIDv2 update to RFC 3161 |
| FIPS 204 | ML-DSA |
| FIPS 205 | SLH-DSA |
| BSI TR-02102-1 (2024) | Recomendaciones de algoritmos criptograficos |
| GOYA-TSA-POL-001 | TSA Policy (ETSI EN 319 421) |
