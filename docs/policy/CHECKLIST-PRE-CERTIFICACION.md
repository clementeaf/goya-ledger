# Checklist Pre-Certificación PSC

Estado de preparación para certificación como Prestador de Servicios de Certificación (PSC) bajo Ley 19.799 y conformidad eIDAS.

---

## Componente técnico (código)

| # | Item | Estado | Evidencia |
|---|------|--------|-----------|
| 1 | FES (Firma Electrónica Simple) — Ed25519 | LISTO | `src/signature/`, 2503 tests |
| 2 | FEA (Firma Electrónica Avanzada) — ML-DSA-65 + biométrico | LISTO | `src/signature/`, `BiometricEvidence` |
| 3 | Qualified Seal (eIDAS Art. 3(25)) | LISTO | `SignatureLevel::Seal` |
| 4 | CAdES-BES/T/XL DER (ETSI TS 101 733) | LISTO | `src/signature/cades_der.rs` |
| 5 | XAdES-BES/T con firma real sobre SignedInfo | LISTO | `src/signature/xades.rs` |
| 6 | PAdES CMS PKCS#7 (ETSI TS 102 778) | LISTO | `src/signature/pades.rs` |
| 7 | TSA RFC 3161 (JSON + DER) | LISTO | `src/tsa/` |
| 8 | TSA serial persistence en disco | LISTO | `TsaProvider::with_serial_path()` |
| 9 | OCSP RFC 6960 (JSON + DER) | LISTO | `src/msp/ocsp.rs`, `ocsp_der.rs` |
| 10 | PKI: CA hierarchy + cert chain validation | LISTO | `src/pki.rs`, `pki_chain.rs` |
| 11 | CRL RFC 5280 (DER + PEM + endpoints) | LISTO | `src/msp/crl_rfc5280.rs`, `/api/v1/crl` |
| 12 | Registration Authority (identity proofing) | LISTO | `src/identity/ra.rs` |
| 13 | PKCS#11 HSM integration | LISTO (code) | `src/identity/hsm.rs` (feature-gated) |
| 14 | QCStatements EN 319 412-5 | LISTO | `src/pki.rs:qc_statements_extension()` |
| 15 | SD-JWT VC + Key Binding JWT (RFC 9901) | LISTO | `src/identity/sd_jwt.rs` |
| 16 | mdoc ISO 18013-5 | LISTO | `src/identity/mdoc.rs` |
| 17 | OpenID4VCI (DPoP + WIA + c_nonce) | LISTO | `src/api/handlers/oid4vci.rs` |
| 18 | OpenID4VP (presentation_definition matching) | LISTO | `src/api/handlers/oid4vp.rs` |
| 19 | ETSI TS 119 612 Trusted Lists (parse + verify XAdES) | LISTO | `src/tsl_client.rs`, `src/tsl.rs` |
| 20 | Audit hash-chain + retention auto-purge | LISTO | `src/audit.rs`, `audit_retention.rs` |
| 21 | DID consolidado did:goya: | LISTO | `src/identity/did.rs` |
| 22 | CAVP NIST test vectors | LISTO | `crates/pqc_crypto_module/` |
| 23 | Crypto boundary enforcement | LISTO | `tests/crypto_boundary.rs` |
| 24 | OCSP stapling en TLS | LISTO | `src/tls.rs:OcspStaple` |
| 25 | Cifrado at-rest (AES-256-GCM) | LISTO | `src/storage/` |

**Resultado: 25/25 items técnicos listos.**

---

## Documentación de política

| # | Documento | Estado | Archivo |
|---|-----------|--------|---------|
| 1 | CPS (RFC 3647) | LISTO | `docs/policy/CPS.md` |
| 2 | CP (RFC 3647) | LISTO | `docs/policy/CP.md` |
| 3 | ETSI EN 319 401 — TSP Policy | LISTO | `docs/policy/ETSI-EN-319-401-TSP-POLICY.md` |
| 4 | ETSI EN 319 411 — CA Policy | LISTO | `docs/policy/ETSI-EN-319-411-CA-POLICY.md` |
| 5 | ETSI EN 319 421 — TSA Policy | LISTO | `docs/policy/ETSI-EN-319-421-TSA-POLICY.md` |
| 6 | Plan de Seguridad (DS 181) | LISTO | `docs/policy/PLAN-SEGURIDAD.md` |
| 7 | Plan de Contingencia (DS 181) | LISTO | `docs/policy/PLAN-CONTINGENCIA.md` |
| 8 | Procedimiento Ceremonia de Claves | LISTO | `docs/policy/PROCEDIMIENTO-CEREMONIA-CLAVES.md` |
| 9 | Politica de Privacidad + EIPD | LISTO | `docs/policy/POLITICA-PRIVACIDAD-EIPD.md` |
| 10 | Acuerdo de Suscriptor | LISTO | `docs/policy/ACUERDO-SUSCRIPTOR.md` |
| 11 | Acuerdo de Parte Confiante | LISTO | `docs/policy/ACUERDO-PARTE-CONFIANTE.md` |
| 12 | Informe de Interoperabilidad | TEMPLATE | `docs/policy/INFORME-INTEROPERABILIDAD.md` |
| 13 | OID Registry + instrucciones PEN | LISTO | `docs/policy/OID-REGISTRY.md` |

**Resultado: 12/13 listos, 1 template pendiente de resultados reales.**

---

## Requisitos operacionales (mundo real)

| # | Item | Estado | Accion requerida | Prioridad |
|---|------|--------|------------------|-----------|
| 1 | OID PEN real (IANA) | PENDIENTE | Solicitar en https://pen.iana.org — gratuito, ~1 semana. Ver `OID-REGISTRY.md` para instrucciones de reemplazo | ALTA |
| 2 | HSM fisico FIPS 140-3 Level 2+ | PENDIENTE | Adquirir HSM compatible PKCS#11 (ej: Thales Luna, Utimaco, YubiHSM 2). Probar con `cargo test --features hsm` | ALTA |
| 3 | Sincronizacion NTP verificable | PENDIENTE | Configurar NTP contra servidores stratum 1/2 (ej: `time.cloudflare.com`, `ntp.shoa.cl`). Documentar evidencia de drift < 1s | ALTA |
| 4 | Ceremonia de claves ejecutada | PENDIENTE | Ejecutar `PROCEDIMIENTO-CEREMONIA-CLAVES.md` con personas reales, notario, sala segura. Generar acta firmada | ALTA |
| 5 | Penetration test independiente | PENDIENTE | Contratar empresa de seguridad certificada (ej: NCC Group, Bishop Fox, empresa local acreditada). Requiere informe formal | ALTA |
| 6 | Infraestructura de produccion | PENDIENTE | Datacenter con controles fisicos (no VPS compartido). Opciones: colocation, cloud dedicado (AWS GovCloud, Azure Government), datacenter nacional | ALTA |
| 7 | Revision legal de acuerdos | PENDIENTE | Abogado chileno revise `ACUERDO-SUSCRIPTOR.md` y `ACUERDO-PARTE-CONFIANTE.md`. Adaptar a entidad legal real | MEDIA |
| 8 | Seguro de responsabilidad civil | PENDIENTE | Poliza de seguros per Ley 19.799 Art. 14. Contactar corredor de seguros con experiencia en PSC | MEDIA |
| 9 | Interop testing real | PENDIENTE | Ejecutar pruebas contra sistemas externos. Rellenar `INFORME-INTEROPERABILIDAD.md` con resultados | MEDIA |
| 10 | Registro ante Subsecretaria de Economia | PENDIENTE | Presentar solicitud formal con toda la documentacion ante la Entidad Acreditadora | FINAL |

**Resultado: 0/10 — todos requieren accion fuera del codigo.**

---

## Orden recomendado de ejecucion

```
Semana 1:    Solicitar PEN IANA (#1)
Semana 1-2:  Adquirir HSM (#2) + configurar NTP (#3)
Semana 2-3:  Preparar infraestructura (#6)
Semana 3:    Ejecutar ceremonia de claves (#4)
Semana 4:    Contratar pentest (#5)
Semana 4:    Revision legal (#7) + seguro (#8)
Semana 5-6:  Pentest en ejecucion
Semana 6-7:  Interop testing (#9)
Semana 8:    Compilar expediente + presentar ante Entidad Acreditadora (#10)
```

Tiempo estimado: **8 semanas** desde inicio hasta presentacion formal.

---

## Resumen ejecutivo

| Categoria | Completo | Pendiente |
|-----------|----------|-----------|
| Codigo (items tecnicos) | 25/25 (100%) | 0 |
| Documentacion de politica | 12/13 (92%) | 1 template |
| Requisitos operacionales | 0/10 (0%) | 10 |
| **Total** | **37/48 (77%)** | **11** |

El 77% del trabajo de certificacion esta completo. El 23% restante es exclusivamente operacional y no requiere desarrollo de software adicional.
