# Service Catalog — Frontend Data

Data structure for the frontend that offers Goya Ledger services. Each service includes description, endpoints, use cases, and tier availability.

---

## Services

### 1. Notarizacion Digital

**slug:** `notarization`
**tagline:** Prueba de existencia inmutable para cualquier documento
**description:** Registra el hash SHA-256 de un documento en la blockchain sin subir el archivo. Verifica la existencia en cualquier momento. Firma criptografica vincula el documento al emisor.

**capabilities:**
- Registro de hash con firma Ed25519 o ML-DSA-65 (post-cuantico)
- Verificacion instantanea por hash
- Timestamp inmutable en bloque
- Metadata asociada (nombre de archivo, tipo, descripcion)
- Deteccion de duplicados (409 si el hash ya existe)

**endpoints:**

| Method | Path | Description |
|--------|------|-------------|
| POST | `/api/v1/notarize` | Registrar hash de documento |
| GET | `/api/v1/notarize/verify/{hash}` | Verificar existencia por hash |
| GET | `/api/v1/notarize/{id}` | Obtener notarizacion por ID |
| GET | `/api/v1/notarize` | Listar notarizaciones (filtro por signer) |

**use_cases:**
- Propiedad intelectual y patentes
- Contratos y acuerdos legales
- Cadena de custodia forense
- Certificacion de titulos academicos
- Registros notariales digitales

**tiers:** Starter, Business, Enterprise

---

### 2. Identidad Descentralizada

**slug:** `identity`
**tagline:** Identidades W3C DID con credenciales verificables
**description:** Gestion completa de identidades descentralizadas siguiendo el estandar W3C DID. Emision, almacenamiento y verificacion de credenciales verificables con divulgacion selectiva via zero-knowledge proofs.

**capabilities:**
- Crear y resolver DIDs (did:goya:*)
- Emitir Verifiable Credentials (VC Data Model 2.0)
- Verificar credenciales con firma criptografica
- ZK proofs para divulgacion selectiva (commitment-based)
- Alias con compromiso zero-knowledge y revocacion de 15 dias
- Interoperabilidad W3C DID Resolution y JSON-LD export

**endpoints:**

| Method | Path | Description |
|--------|------|-------------|
| POST | `/api/v1/identity` | Crear nueva identidad DID |
| GET | `/api/v1/identity/{did}` | Resolver identidad por DID |
| GET | `/api/v1/identity` | Listar identidades |
| POST | `/api/v1/store/credential` | Almacenar credencial verificable |
| GET | `/api/v1/store/credential/{id}` | Obtener credencial por ID |
| GET | `/api/v1/store/credentials` | Listar credenciales (paginado) |
| GET | `/api/v1/credentials/issuer/{did}` | Credenciales por emisor |
| POST | `/api/v1/zkp/prove` | Generar ZK proof |
| POST | `/api/v1/zkp/verify` | Verificar ZK proof |
| POST | `/api/v1/alias` | Crear alias DID |
| GET | `/api/v1/alias/{alias}` | Resolver alias |

**use_cases:**
- Titulos universitarios verificables
- Certificaciones profesionales
- Licencias y permisos
- Onboarding KYC/AML
- Identidad digital soberana

**tiers:** Starter, Business, Enterprise

---

### 3. Gobernanza On-Chain

**slug:** `governance`
**tagline:** Votacion transparente y trazable en blockchain
**description:** Sistema completo de gobernanza con propuestas, votacion delegada, depositos y periodos de bloqueo. Soporte para asambleas, sesiones y actas. Voto ciego para privacidad del votante.

**capabilities:**
- Propuestas con deposito y timelock configurable
- Votacion con poder delegado (DPoS)
- Voto ciego (privacidad del votante via blind voter ID)
- Veto y cancelacion
- Tallying automatico con cierre por deadline
- Entidades de gobierno: scopes, asambleas, sesiones, actas
- Verificacion de firmas Ed25519

**endpoints:**

| Method | Path | Description |
|--------|------|-------------|
| POST | `/api/v1/governance/proposals` | Crear propuesta |
| GET | `/api/v1/governance/proposals` | Listar propuestas (paginado) |
| GET | `/api/v1/governance/proposals/{id}` | Obtener propuesta |
| POST | `/api/v1/governance/proposals/{id}/vote` | Votar |
| POST | `/api/v1/governance/proposals/{id}/delegate` | Delegar voto |
| POST | `/api/v1/governance/proposals/{id}/veto` | Vetar propuesta |
| POST | `/api/v1/governance/proposals/{id}/tally` | Contar votos |
| POST | `/api/v1/governance/proposals/{id}/close` | Cerrar propuesta |
| POST | `/api/v1/governance/scopes` | Crear scope de gobierno |
| POST | `/api/v1/governance/assemblies` | Crear asamblea |
| POST | `/api/v1/governance/sessions` | Crear sesion |
| POST | `/api/v1/governance/actas` | Registrar acta |

**use_cases:**
- Juntas directivas y asambleas de accionistas
- Votaciones corporativas
- Cooperativas y organizaciones autonomas
- Presupuestos participativos
- Elecciones de representantes

**tiers:** Business, Enterprise

---

### 4. Registro de Activos y Tokenizacion

**slug:** `assets`
**tagline:** Registro on-chain con trazabilidad completa
**description:** Registro de activos del mundo real (RWA) en blockchain con historial de eventos inmutable. Tokenizacion con ciclo de vida completo y compliance automatizado conforme a estandares internacionales.

**capabilities:**
- Registro de activos con metadata extensible
- Historial de eventos por activo
- Tokenizacion RWA (Real World Assets)
- Compliance automatizado: ISO 4217, ISO 20022, ISO 3166, ERC-3643
- Transferencia de propiedad trazable
- Motor de reglas de compliance configurable

**endpoints:**

| Method | Path | Description |
|--------|------|-------------|
| POST | `/api/v1/registry/assets` | Registrar activo |
| GET | `/api/v1/registry/assets` | Listar activos |
| GET | `/api/v1/registry/assets/{id}` | Obtener activo |
| GET | `/api/v1/registry/assets/{id}/events` | Historial de eventos |
| POST | `/api/v1/tokenization/mint` | Crear token |
| POST | `/api/v1/tokenization/transfer` | Transferir token |
| POST | `/api/v1/tokenization/burn` | Destruir token |
| GET | `/api/v1/tokenization/{id}` | Estado del token |
| POST | `/api/v1/compliance/check` | Verificar compliance |
| GET | `/api/v1/compliance/rules` | Listar reglas activas |

**use_cases:**
- Bienes raices tokenizados
- Arte y coleccionables
- Commodities y materias primas
- Instrumentos financieros
- Inventario y supply chain

**tiers:** Business, Enterprise

---

### 5. Smart Contracts

**slug:** `contracts`
**tagline:** Dos motores de ejecucion: Wasm y EVM
**description:** Desarrollo y despliegue de contratos inteligentes con dos motores: chaincode en Rust/WebAssembly con SDK dedicado, y compatibilidad EVM para contratos Solidity. Politicas de endoso multi-organizacion.

**capabilities:**
- Chaincode Rust compilado a WebAssembly
- SDK de desarrollo con operaciones de estado, eventos y cross-chaincode
- Compatibilidad EVM (deploy, call, static-call)
- Politicas de endoso configurables por contrato
- Ciclo de vida completo: install, instantiate, upgrade
- Query y invoke con ACL

**endpoints:**

| Method | Path | Description |
|--------|------|-------------|
| POST | `/api/v1/chaincode/install` | Instalar chaincode Wasm |
| POST | `/api/v1/chaincode/invoke` | Invocar funcion |
| POST | `/api/v1/chaincode/query` | Consultar estado |
| POST | `/api/v1/evm/deploy` | Desplegar contrato Solidity |
| POST | `/api/v1/evm/call` | Ejecutar funcion (mutante) |
| POST | `/api/v1/evm/static-call` | Consultar (solo lectura) |
| GET | `/api/v1/evm/contracts` | Listar contratos desplegados |
| POST | `/api/v1/contracts/erc20/deploy` | Desplegar ERC-20 |
| POST | `/api/v1/contracts/erc721/deploy` | Desplegar ERC-721 |

**use_cases:**
- Logistica y supply chain
- Acuerdos multilaterales automatizados
- Escrow y pagos condicionados
- Programas de lealtad tokenizados
- Automatizacion de procesos empresariales

**tiers:** Enterprise

---

### 6. Red Multi-Organizacion

**slug:** `network`
**tagline:** Infraestructura permisionada para consorcios
**description:** Red blockchain permisionada estilo Fabric con canales privados, datos confidenciales con diseminacion P2P, y control de acceso granular por organizacion y rol. Consensus BFT tolerante a fallas.

**capabilities:**
- Canales privados entre organizaciones
- Datos privados con diseminacion P2P selectiva
- ACL por rol (Admin, Client, Peer) y organizacion
- Raft ordering con tolerancia a fallas
- mTLS entre todos los nodos
- Auto-discovery de peers
- Gateway endorse-order-commit

**endpoints:**

| Method | Path | Description |
|--------|------|-------------|
| POST | `/api/v1/channels` | Crear canal |
| GET | `/api/v1/channels` | Listar canales |
| POST | `/api/v1/organizations` | Registrar organizacion |
| GET | `/api/v1/organizations` | Listar organizaciones |
| POST | `/api/v1/gateway/submit` | Enviar transaccion via gateway |
| POST | `/api/v1/private-data` | Escribir dato privado |
| GET | `/api/v1/network/peers` | Listar peers conectados |
| POST | `/api/v1/msp/enroll` | Enrolar identidad MSP |

**use_cases:**
- Consorcios empresariales
- Cadenas de suministro multi-empresa
- Redes inter-bancarias
- Sistemas de salud inter-institucionales
- Registros compartidos entre entidades publicas

**tiers:** Enterprise

---

### 7. Auditoria y Compliance

**slug:** `audit`
**tagline:** Trazabilidad completa para reguladores
**description:** Registro de auditoria persistente en RocksDB con exportacion CSV. Analisis forense con timeline de eventos, deteccion de anomalias y verificacion de integridad de cadena. Compliance automatizado con motor de reglas.

**capabilities:**
- Audit trail persistente (RocksDB)
- Exportacion CSV para reguladores
- Timeline forense y eventos de seguridad
- Verificacion de integridad de cadena
- Compliance automatizado con motor de reglas
- Deteccion de anomalias (z-score estadistico)
- Risk scoring con 11 reglas (AML + credenciales)
- Deteccion de patrones: velocity, structuring, round-trip, dormant, credential mill

**endpoints:**

| Method | Path | Description |
|--------|------|-------------|
| GET | `/api/v1/audit/requests` | Consultar audit log (paginado) |
| GET | `/api/v1/audit/export` | Exportar CSV |
| GET | `/api/v1/forensic/timeline` | Timeline forense |
| GET | `/api/v1/forensic/security-events` | Eventos de seguridad |
| GET | `/api/v1/chain/verify` | Verificar integridad |
| POST | `/api/v1/intelligence/risk` | Evaluar riesgo |
| POST | `/api/v1/intelligence/anomaly` | Detectar anomalias |
| POST | `/api/v1/intelligence/patterns` | Detectar patrones |

**use_cases:**
- Auditorias regulatorias
- Reportes FIPS compliance
- Deteccion de fraude en credenciales
- Monitoreo AML/KYC
- Due diligence automatizado

**tiers:** Starter, Business, Enterprise

---

### 8. Vault de Secretos

**slug:** `vault`
**tagline:** Almacenamiento seguro de wallets con recuperacion ciega
**description:** Almacenamiento de wallets encriptadas con recuperacion via blind indexing (HMAC-SHA3-256). El nodo nunca accede al contenido — la encriptacion es del lado del cliente. Rate limiting contra brute-force y audit logging de cada operacion.

**capabilities:**
- Almacenamiento opaco de wallets encriptadas
- Recuperacion via blind index (HMAC-SHA3-256, NIST SP 800-185)
- Rate limiting: 5 intentos de recuperacion por IP cada 5 minutos
- Audit logging de cada operacion vault
- Fingerprint del secret para verificacion de rotacion

**endpoints:**

| Method | Path | Description |
|--------|------|-------------|
| POST | `/api/v1/vault/store` | Almacenar wallet encriptada |
| GET | `/api/v1/vault/{did}` | Recuperar por DID |
| POST | `/api/v1/vault/recover` | Recuperar via recovery key |

**use_cases:**
- Backup de wallets de estudiantes
- Custodia de claves de credenciales
- Recuperacion de acceso sin intermediarios
- Almacenamiento seguro de metadata sensible

**tiers:** Business, Enterprise

---

### 9. Bridge Cross-Chain

**slug:** `bridge`
**tagline:** Transferencias cross-chain con verificacion Merkle
**description:** Protocolo de bridge para transferencias de tokens entre Goya Ledger y cadenas externas. Escrow con ciclo lock-mint-burn-release. Verificacion de inclusion via Merkle proofs SHA-256. Proteccion contra replay.

**capabilities:**
- Transferencias outbound: lock tokens → relay → mint en cadena destino
- Transferencias inbound: verify proof → mint wrapped tokens
- Escrow vault con lock/release/refund
- Verificacion Merkle SHA-256
- Proteccion contra replay (message ID tracking)
- Registro de cadenas externas con confirmaciones minimas
- Balances de wrapped tokens por cuenta

**endpoints:**

| Method | Path | Description |
|--------|------|-------------|
| POST | `/api/v1/bridge/transfer` | Iniciar transferencia outbound |
| POST | `/api/v1/bridge/inbound` | Procesar mensaje inbound |
| GET | `/api/v1/bridge/transfer/{id}` | Estado de transferencia |
| GET | `/api/v1/bridge/chains` | Listar cadenas registradas |
| GET | `/api/v1/bridge/balances/{account}` | Balances wrapped tokens |

**use_cases:**
- Credenciales inter-institucionales
- Transferencia de activos entre redes
- Interoperabilidad con Ethereum/Cosmos
- Wrapped tokens para liquidez cross-chain

**tiers:** Enterprise

---

## Tiers

### Starter

**precio_sugerido:** Consultar
**sla:** 99.5% disponibilidad
**soporte:** 24 horas respuesta
**servicios:** Notarizacion, Identidad, Auditoria
**limites:**
- 100 requests/minuto
- 20 requests/segundo
- Storage en memoria (desarrollo) o RocksDB (produccion)

### Business

**precio_sugerido:** Consultar
**sla:** 99.5% disponibilidad
**soporte:** 4 horas respuesta (critico)
**servicios:** Starter + Gobernanza, Activos, Compliance, Vault
**limites:**
- 500 requests/minuto
- 50 requests/segundo
- RocksDB con backups diarios

### Enterprise

**precio_sugerido:** Consultar
**sla:** 99.9% disponibilidad (consortium 3+ nodos)
**soporte:** 2 horas respuesta
**servicios:** Todos los servicios
**limites:**
- Configurables por contrato
- Multi-nodo Raft
- mTLS obligatorio
- Canales privados
- Smart contracts custom

---

## Datos tecnicos para el frontend

### Response envelope

Todas las respuestas siguen el mismo formato:

```json
{
  "status": "Success",
  "status_code": 200,
  "message": "OK",
  "data": {},
  "timestamp": "2026-06-21T12:00:00Z",
  "trace_id": "uuid-v4"
}
```

### Paginacion

Endpoints de lista soportan `?page=1&limit=20` (max 100):

```json
{
  "data": {
    "data": [],
    "pagination": {
      "total": 150,
      "page": 1,
      "limit": 20,
      "total_pages": 8,
      "has_next": true
    }
  }
}
```

### Codigos de error

| HTTP | Code | Descripcion |
|------|------|-------------|
| 400 | VALIDATION_ERROR | Request invalido |
| 401 | UNAUTHORIZED | Sin identidad mTLS |
| 403 | FORBIDDEN | Permisos insuficientes |
| 404 | NOT_FOUND | Recurso no existe |
| 409 | CONFLICT | Recurso duplicado |
| 429 | RATE_LIMITED | Limite excedido |
| 500 | INTERNAL_ERROR | Error del servidor |

### Rate limits

| Tipo de endpoint | Por segundo | Por minuto | Por hora |
|-----------------|-------------|------------|----------|
| Lectura (GET) | 20 | 100 | 3000 |
| Escritura (POST/PUT/DELETE) | 10 | 50 | 1500 |
| Vault recovery | 5 intentos / 5 min por IP | — | — |
| Health check | Sin limite | — | — |

### Health check

```
GET /api/v1/health
```

Retorna estado de componentes: storage, peers, ordering.

### OpenAPI

```
GET /api/v1/openapi.json
GET /swagger
```

### Metricas (Prometheus)

```
GET /metrics
```
