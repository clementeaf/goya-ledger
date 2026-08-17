# Goya Ledger: Primera DLT Post-Cuántica con Emisión de Credenciales hacia EUDI Wallet

**Fecha:** 17 de agosto de 2026
**Autor:** Proyecto Goya Ledger
**Estado:** Verificado — demostración en vivo

---

## Afirmación

> Hasta agosto de 2026, y según el estado público del arte verificable, Goya Ledger es la primera DLT con capacidad post-cuántica (FIPS 204 / ML-DSA-65) que ha demostrado públicamente la emisión exitosa de una credencial verificable (OID4VCI 1.0) directamente hacia la implementación de referencia iOS de la EU Digital Identity Wallet.

## Evidencia

| Artefacto | URL / Referencia |
|---|---|
| Metadata del emisor | `https://goya-node.fly.dev/.well-known/openid-credential-issuer` |
| Metadata OAuth AS | `https://goya-node.fly.dev/.well-known/oauth-authorization-server` |
| JWKS (clave pública del emisor) | `https://goya-node.fly.dev/.well-known/jwt-vc-issuer` |
| Formato de credencial | `dc+sd-jwt` (OID4VCI 1.0 Final) |
| Algoritmo de firma | ES256 (ECDSA P-256) para interop EUDI; ML-DSA-65 (FIPS 204) disponible |
| Aplicación wallet | `eu-digital-identity-wallet/eudi-app-ios-wallet-ui` (referencia oficial UE) |
| Biblioteca VCI | `eu-digital-identity-wallet/eudi-lib-ios-openid4vci-swift` v0.51.0 |
| Wallet Kit | `eu-digital-identity-wallet/eudi-lib-ios-wallet-kit` v0.37.6 |
| Tipo de credencial | `urn:eudi:pid:1` (PID — Datos de Identificación Personal) |
| Tipo de grant | `urn:ietf:params:oauth:grant-type:pre-authorized_code` |
| Tipo de prueba | `attestation` (atestación de clave vinculada al dispositivo) |

## Análisis del Panorama Competitivo

### 1. EBSI — Infraestructura Europea de Servicios Blockchain

- **Operador:** Comisión Europea
- **Criptografía:** ECDSA (secp256k1, P-256) — convencional
- **PQC:** Ninguna
- **Interop EUDI Wallet:** Sí (mismo ecosistema), pero no post-cuántica
- **Fuente:** https://ec.europa.eu/digital-building-blocks/sites/display/EBSI

### 2. QANplatform

- **Afirmación:** "Blockchain Layer 1 resistente a computación cuántica"
- **Criptografía:** Basada en retículos (referencia a CRYSTALS-Dilithium), no certificada NIST FIPS 204
- **OID4VCI:** No se encontró implementación
- **Interop EUDI Wallet:** Sin demostración pública
- **Fuente:** https://qanplatform.com

### 3. IOTA / Shimmer

- **Enfoque:** DLT basada en DAG, identidad (IOTA Identity)
- **Criptografía:** Ed25519 — convencional
- **PQC:** Solo investigación (IOTA 2.0 menciona PQC como objetivo futuro)
- **Interop EUDI Wallet:** Sin demostración pública de OID4VCI
- **Fuente:** https://wiki.iota.org

### 4. Hyperledger Aries / Indy / AnonCreds

- **Enfoque:** Ecosistema SSI/VC maduro
- **Criptografía:** Ed25519, BLS12-381 — convencional
- **PQC:** Ninguna en producción
- **OID4VCI 1.0:** Parcial (Aries RFC, no OID4VCI 1.0 Final)
- **Interop EUDI Wallet:** Sin demostración directa con wallet de referencia EUDI
- **Fuente:** https://www.hyperledger.org/projects/aries

### 5. Pilotos a Gran Escala de la UE (LSPs)

| Piloto | PQC | Notas |
|---|---|---|
| POTENTIAL | No | Solo ES256 / EdDSA |
| NOBID | No | Piloto nórdico/báltico, criptografía convencional |
| EWC (Consorcio EU Digital Identity Wallet) | No | PKI convencional |
| DC4EU | No | Servicios transfronterizos, sin PQC |

- **Fuente:** https://digital-strategy.ec.europa.eu/en/policies/eudi-wallet-toolbox

### 6. Otros Proyectos Post-Cuánticos

| Proyecto | DLT | OID4VCI | EUDI Wallet |
|---|---|---|---|
| QRL (Quantum Resistant Ledger) | Sí (XMSS) | No | No |
| Participantes NIST PQC | N/A (organismo de estándares) | N/A | N/A |
| Post-Quantum (empresa) | No (enfoque VPN/TLS) | No | No |
| IBM Quantum Safe | No (herramientas empresariales) | No | No |

### 7. Implementaciones de Referencia de Emisores EUDI

| Emisor | Operador | PQC | DLT |
|---|---|---|---|
| issuer.eudiw.dev | Comisión Europea | No (ES256) | No |
| issuer-backend.eudiw.dev | Comisión Europea | No (ES256) | No |
| Pilotos nacionales (DE, FR, ES, etc.) | Gobiernos | No | No |

## Implementación Técnica

### Flujo del Protocolo (Verificado Funcionando)

```
1. Escaneo QR
   openid-credential-offer://?credential_offer={...}
        ↓
2. Resolución de Metadata
   GET /.well-known/openid-credential-issuer → 200
   GET /.well-known/oauth-authorization-server → 200
        ↓
3. Intercambio de Token (código pre-autorizado)
   POST /token → 200 {access_token, expires_in}
        ↓
4. Adquisición de Nonce
   POST /nonce → 200 {c_nonce}
        ↓
5. Solicitud de Credencial (con prueba de atestación)
   POST /credential → 200 {credential: "<sd-jwt>"}
        ↓
6. Almacenamiento de Credencial
   EUDI Wallet valida:
   ✓ Clave de vinculación cnf coincide con clave del dispositivo
   ✓ iss coincide con credential_issuer
   ✓ kid se resuelve vía /.well-known/jwt-vc-issuer JWKS
   ✓ Firma ES256 verificada
   ✓ Credencial almacenada en wallet
```

### Estructura SD-JWT VC (Emitida por Goya)

```
Header:  {"alg":"ES256", "typ":"dc+sd-jwt", "kid":"<key-id>"}
Payload: {
  "iss": "https://goya-node.fly.dev",
  "sub": "holder",
  "iat": <timestamp>,
  "exp": <timestamp>,
  "vct": "urn:eudi:pid:1",
  "_sd_alg": "sha-256",
  "_sd": [...],
  "cnf": {"jwk": {"kty":"EC","crv":"P-256","x":"...","y":"..."}}
}
Firma: <ES256>
~<disclosure1>~<disclosure2>~...~
```

### Capacidad Post-Cuántica

Goya Ledger soporta ML-DSA-65 (FIPS 204) como su algoritmo de firma principal. Para la interoperabilidad con EUDI Wallet, se utiliza ES256 porque la implementación de referencia EUDI actual no soporta verificación de firmas ML-DSA-65.

La arquitectura de doble algoritmo permite:
- **ES256** para compatibilidad actual con EUDI Wallet
- **ML-DSA-65** para emisión de credenciales quantum-safe (soporte futuro de wallet)
- Selección en tiempo de ejecución vía variable de entorno `SIGNING_ALGORITHM`

```
SIGNING_ALGORITHM=ecdsa-p256  → ES256 (interop EUDI)
SIGNING_ALGORITHM=ml-dsa-65   → ML-DSA-65 (post-cuántico, por defecto)
```

## Cumplimiento de Estándares

| Estándar | Estado |
|---|---|
| OID4VCI 1.0 Final | ✓ Cumplido |
| SD-JWT VC (dc+sd-jwt) | ✓ Cumplido |
| RFC 9449 (DPoP) | ✓ Soportado |
| RFC 7638 (JWK Thumbprint) | ✓ Usado para kid |
| FIPS 204 (ML-DSA-65) | ✓ Implementado |
| eIDAS 2.0 (ARF) | ✓ Tipo de credencial PID |
| ETSI TS 119 612 (Listas de Confianza) | ◐ Parcial (no registrado) |

## Cobertura Jurisdiccional

| Jurisdicción | Marco Legal | Estado |
|---|---|---|
| Unión Europea | eIDAS 2.0 | Interop técnica demostrada |
| Chile | Ley 19.799 (Firma Electrónica) | Jurisdicción nativa |
| Emiratos Árabes Unidos | Decreto-Ley Federal No. 46/2021 | Marco regulatorio mapeado |

## Metodología

Este análisis fue conducido mediante:

1. Búsqueda en repositorios públicos de la organización `eu-digital-identity-wallet` en GitHub por referencias PQC
2. Revisión de documentación y comunicados de prensa de proyectos blockchain post-cuánticos conocidos
3. Examen de las especificaciones de pilotos LSP de la UE para soporte de algoritmos criptográficos
4. Verificación de la ausencia de ML-DSA-65 / CRYSTALS-Dilithium / FIPS 204 en cualquier emisor OID4VCI conocido
5. Prueba en vivo del flujo OID4VCI completo contra la aplicación EUDI wallet de referencia iOS

**Limitación:** Este análisis cubre información disponible públicamente hasta agosto de 2026. Implementaciones privadas o clasificadas de estados miembros de la UE no están incluidas.

## Conclusión

Ningún otro proyecto DLT ha demostrado públicamente la combinación de:

1. Capacidad criptográfica post-cuántica (NIST FIPS 204 / ML-DSA-65)
2. Cumplimiento OID4VCI 1.0
3. Emisión exitosa de credenciales hacia la implementación oficial de referencia de EU Digital Identity Wallet
4. Endpoint de emisor en vivo y accesible públicamente

Goya Ledger es, según el mejor conocimiento públicamente verificable, la primera en lograr este hito.
