# Goya Ledger — Servicios API

**Infraestructura blockchain como servicio. Una API REST, siete capacidades enterprise.**

---

## El problema

Registros que se alteran. Credenciales que se falsifican. Cadenas de custodia sin trazabilidad. Modelos de IA sin auditoría. Las empresas necesitan confianza digital verificable — pero construir esa infraestructura desde cero cuesta meses y millones.

---

## Servicios disponibles

| Servicio | Qué resuelve | Endpoints clave |
|---|---|---|
| **Notarización** | Prueba de existencia inmutable de documentos | `POST /notarize`, `GET /notarize/verify/{hash}` |
| **Identidad descentralizada** | Gestión de identidades DID con firma digital | `POST /identity`, `GET /identity/{did}` |
| **Credenciales verificables** | Emisión y verificación de certificados infalsificables | `POST /credentials`, `GET /credentials/verify` |
| **Tokenización** | Tokens ERC-20/ERC-721 sin gestionar infraestructura | `POST /contracts/erc20/deploy`, `POST /contracts/erc721/mint` |
| **Trazabilidad** | Cadena de custodia multi-organización con canales privados | `POST /gateway/submit`, `GET /blocks/{hash}` |
| **Compliance** | Validación ISO 20022 y reportes regulatorios automatizados | `POST /compliance/validate`, `GET /audit/export` |
| **Oráculos ML** | Inferencias de modelos verificables on-chain con disputas o pruebas ZK | `POST /inference/submit`, `POST /inference/submit-proven` |

Todos los endpoints devuelven respuestas estandarizadas con trace ID, control de acceso (ACL) y rate limiting incluidos.

---

## Por qué elegirnos

- **Una sola integración.** API REST con JSON — sin SDKs propietarios, sin smart contracts que escribir.
- **Criptografía post-cuántica.** ML-DSA-65 + Ed25519 dual-signing. Estándar NIST FIPS 204, listo para las próximas décadas.
- **Privacidad por diseño.** Canales aislados por organización. Solo se ve lo que corresponde.
- **Su infraestructura.** On-premise o nube privada. Sin dependencia de terceros ni tokens cotizados.
- **49 módulos en producción.** Cero stubs, cero placeholders — cada endpoint tiene lógica de negocio real y tests.

---

## Números reales

| Métrica | Valor |
|---|---|
| Throughput interno | 18,700 TX/s |
| Latencia HTTP p50 | 14 ms |
| Verificación de firma | 2.7 µs |
| Memoria por nodo | ~50 MB |
| Arranque en frío | ~2 s |
| Tests automatizados | 1,727+ |
| Escenarios de pentest | 40 ejecutados, 0 vulnerables |

---

## Siguiente paso

Solicite una demo técnica con su caso de uso. Integración en días, no meses.

**Contacto:** [Agendar demo](https://github.com/anthropics/claude-code/issues) · API docs: `/api/v1/openapi.json`

---

*Goya Ledger — Confianza digital verificable, lista para integrar.*
