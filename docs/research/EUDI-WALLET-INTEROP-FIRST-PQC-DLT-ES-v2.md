# Goya Ledger: Primera DLT Post-Cuántica con Emisión de Credenciales hacia EUDI Wallet

**Versión:** 2.0 — Prior Art Reviewed
**Fecha:** 17 de agosto de 2026
**Autor:** Proyecto Goya Ledger
**Estado:** Verificado — demostración en vivo

---

## Afirmación

> Con base en el prior art públicamente disponible identificado hasta el 17 de agosto de 2026, no hemos identificado una demostración pública anterior de una DLT con capacidad post-cuántica que haya emitido exitosamente una credencial verificable directamente hacia la implementación oficial de referencia de la EU Digital Identity Wallet (EUDI Reference Wallet iOS).

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

**Resultado verificado:** La EUDI Reference Wallet iOS resolvió Goya como emisor, verificó la credencial emitida (firma ES256, `cnf` binding key, `kid` vía JWKS) y la almacenó exitosamente en el dispositivo.

---

## Análisis del Panorama Competitivo (Prior Art Reviewed)

### 1. EBSI — Infraestructura Europea de Servicios Blockchain

- **Operador:** Comisión Europea
- **Criptografía:** ECDSA (secp256k1, P-256) — convencional
- **PQC:** Ninguna implementada
- **Interop EUDI Wallet:** Sí (mismo ecosistema), pero sin capacidad post-cuántica
- **Fuente:** https://ec.europa.eu/digital-building-blocks/sites/display/EBSI
- **Evaluación:** No cumple el criterio PQC.

### 2. IOTA Foundation

- **Enfoque:** DLT basada en DAG (Tangle), identidad descentralizada (IOTA Identity)
- **Criptografía base:** Ed25519 — convencional
- **PQC:** IOTA ha investigado y prototipado integración con CRYSTALS-Dilithium. Publicaciones del IOTA Research Department y repositorios experimentales documentan esta línea de trabajo.
- **EUDI / eIDAS:** IOTA ha participado en discusiones y pruebas de concepto relacionadas con eIDAS y credenciales verificables en el contexto europeo. El proyecto IOTA Identity soporta estándares W3C DID/VC.
- **EUDI Reference Wallet:** No se encontró evidencia pública de una emisión exitosa de credencial verificable (OID4VCI 1.0) directamente hacia la implementación oficial de referencia iOS de la EUDI Wallet (`eu-digital-identity-wallet/eudi-app-ios-wallet-ui`).
- **Fuentes:** https://wiki.iota.org, https://github.com/iotaledger
- **Evaluación:** Trabajo relevante en DLT + PQC + identidad, pero sin demostración pública documentada contra la EUDI Reference Wallet oficial.

### 3. Procivis AG

- **Enfoque:** Plataforma de identidad digital (Procivis One), SSI/VC
- **PQC:** Procivis ha documentado soporte para ML-DSA-65 (FIPS 204) en su stack de credenciales verificables.
- **EUDI / OID4VC:** Procivis participa activamente en el ecosistema EUDI y soporta protocolos OID4VC (OpenID for Verifiable Credentials).
- **DLT:** No se identificó una DLT propia operada por Procivis como parte integral del flujo de emisión de credenciales. Su arquitectura se basa en infraestructura centralizada o federada, no en un ledger distribuido propio.
- **EUDI Reference Wallet:** No se encontró evidencia pública de emisión directa hacia la EUDI Reference Wallet oficial con PQC + DLT combinados.
- **Fuentes:** https://www.procivis.ch, documentación pública Procivis One
- **Evaluación:** Soporte PQC + EUDI/OID4VC confirmado, pero sin DLT propia formando parte del flujo. El criterio evaluado requiere la combinación DLT + PQC + EUDI Reference Wallet.

### 4. Quantum-Blockchains (Polonia)

- **Enfoque:** Investigación en DLT con criptografía cuántica y post-cuántica, DID
- **PQC + DLT:** Repositorios públicos documentan trabajo en blockchain con capacidades PQC y módulos DID.
- **EUDI:** Se identificaron repositorios relacionados con el ecosistema EUDI en su organización de GitHub/GitLab.
- **EUDI Reference Wallet:** No se encontró evidencia pública de una demostración exitosa de emisión de credencial verificable contra la implementación oficial de referencia iOS de la EUDI Wallet.
- **Fuentes:** https://www.quantum-blockchains.io, repositorios públicos asociados
- **Evaluación:** Trabajo relevante en DLT + PQC + DID + EUDI, pero sin demostración pública documentada contra la EUDI Reference Wallet oficial.

### 5. QANplatform

- **Afirmación:** "Blockchain Layer 1 resistente a computación cuántica"
- **Criptografía:** Basada en retículos (referencia a CRYSTALS-Dilithium), no certificada NIST FIPS 204
- **OID4VCI:** No se encontró implementación
- **Interop EUDI Wallet:** Sin demostración pública
- **Fuente:** https://qanplatform.com
- **Evaluación:** No cumple criterios de interop EUDI ni OID4VCI.

### 6. Hyperledger Aries / Indy / AnonCreds

- **Enfoque:** Ecosistema SSI/VC maduro
- **Criptografía:** Ed25519, BLS12-381 — convencional
- **PQC:** Ninguna en producción
- **OID4VCI 1.0:** Parcial (Aries RFC, no OID4VCI 1.0 Final)
- **Interop EUDI Wallet:** Sin demostración directa con la EUDI Reference Wallet oficial
- **Fuente:** https://www.hyperledger.org/projects/aries
- **Evaluación:** No cumple criterio PQC.

### 7. Pilotos a Gran Escala de la UE (LSPs)

| Piloto | PQC | DLT propia | EUDI Reference Wallet |
|---|---|---|---|
| POTENTIAL | No | No | Sí (interop) |
| NOBID | No | No | Sí (interop) |
| EWC | No | No | Sí (interop) |
| DC4EU | No | No | Sí (interop) |

- **Fuente:** https://digital-strategy.ec.europa.eu/en/policies/eudi-wallet-toolbox
- **Evaluación:** Interop con EUDI confirmada, pero ninguno incorpora PQC ni opera DLT propia.

### 8. Otros Proyectos Post-Cuánticos

| Proyecto | DLT | PQC | OID4VCI | EUDI Reference Wallet |
|---|---|---|---|---|
| QRL (Quantum Resistant Ledger) | Sí (XMSS) | Sí | No | No |
| Post-Quantum (empresa) | No (VPN/TLS) | Sí | No | No |
| IBM Quantum Safe | No (herramientas) | Sí | No | No |

### 9. Implementaciones de Referencia de Emisores EUDI

| Emisor | Operador | PQC | DLT |
|---|---|---|---|
| issuer.eudiw.dev | Comisión Europea | No (ES256) | No |
| issuer-backend.eudiw.dev | Comisión Europea | No (ES256) | No |
| Pilotos nacionales (DE, FR, ES, etc.) | Gobiernos | No | No |

---

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

---

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

---

## Metodología y Prior Art Revisado

Este análisis fue conducido mediante búsqueda sistemática en las siguientes fuentes:

### Bases de datos académicas y de patentes
- **IEEE Xplore / ACM Digital Library:** búsqueda de publicaciones combinando "post-quantum" + "DLT/blockchain" + "EUDI/eIDAS" + "verifiable credential" + "OID4VCI"
- **Bases de patentes:** Google Patents, Espacenet — búsqueda de patentes combinando PQC + DLT + digital identity wallet + credential issuance

### Programas de financiamiento e investigación europeos
- **CORDIS / Horizon Europe:** proyectos financiados por la UE en las áreas de identidad digital, blockchain y criptografía post-cuántica
- **EBSI (European Blockchain Services Infrastructure):** documentación técnica y roadmap criptográfico

### Pilotos oficiales EUDI
- **Large Scale Pilots:** POTENTIAL, NOBID, EWC (EU Digital Identity Wallet Consortium), DC4EU — especificaciones técnicas y algoritmos criptográficos soportados

### Repositorios de código fuente
- **GitHub / GitLab:** organización `eu-digital-identity-wallet`, repositorios de IOTA Foundation, Procivis AG, Quantum-Blockchains, QANplatform, Hyperledger, QRL, y proyectos PQC europeos
- Búsqueda específica de implementaciones OID4VCI con soporte ML-DSA-65 / CRYSTALS-Dilithium / FIPS 204

### Proyectos evaluados individualmente
- **IOTA Foundation:** DLT + prototipo CRYSTALS-Dilithium + trabajo eIDAS. Sin evidencia de emisión contra EUDI Reference Wallet oficial.
- **Procivis AG:** ML-DSA-65 + EUDI/OID4VC. Sin DLT propia en el flujo.
- **Quantum-Blockchains:** DLT + PQC + DID + repositorios EUDI. Sin demostración pública contra EUDI Reference Wallet oficial.
- **QANplatform, QRL, IBM Quantum Safe, Post-Quantum Ltd:** evaluados y descartados por no cumplir la combinación completa de criterios.

### Limitaciones
- Este análisis cubre información públicamente disponible hasta agosto de 2026.
- Implementaciones privadas, clasificadas o en desarrollo por estados miembros de la UE no están incluidas.
- El análisis no puede afirmar la inexistencia absoluta de implementaciones no publicadas.

---

## Conclusión

Con base en el prior art públicamente disponible identificado hasta el 17 de agosto de 2026, no hemos identificado una demostración pública anterior de una DLT con capacidad post-cuántica que combine:

1. Capacidad criptográfica post-cuántica (NIST FIPS 204 / ML-DSA-65)
2. Operación de una DLT propia como parte del flujo de emisión
3. Cumplimiento OID4VCI 1.0
4. Emisión exitosa de credenciales verificables directamente hacia la implementación oficial de referencia iOS de la EU Digital Identity Wallet
5. Endpoint de emisor en vivo y accesible públicamente

Proyectos como IOTA, Procivis y Quantum-Blockchains presentan avances significativos en subconjuntos de estos criterios, pero ninguno ha demostrado públicamente la combinación completa verificada en este documento.

---

*Documento v2 — Prior Art Reviewed. La versión v1 (17 agosto 2026) se conserva sin modificaciones como registro histórico.*
