# Politica de Uso Aceptable

| Campo | Valor |
|-------|-------|
| **ID** | GOYA-AUP-001 |
| **Version** | 1.0 |
| **Fecha** | 2026-09-03 |
| **Responsable** | Oficial de Seguridad |
| **Clasificacion** | Interna |
| **Base normativa** | ETSI EN 319 401 clausula 7.4.2, ISO/IEC 27002:2022 Control 5.10 |

## 1. Alcance

Esta politica aplica a todo el personal con acceso a los sistemas del Prestador de Servicios de Confianza (PSC), incluyendo empleados, contratistas, consultores y personal temporal. Cubre el uso de infraestructura de produccion, sistemas de desarrollo, claves criptograficas y datos de suscriptores.

## 2. Uso Permitido

| Recurso | Uso autorizado |
|---------|----------------|
| Sistemas de produccion (nodos BFT, CA, TSA, OCSP) | Operacion y mantenimiento conforme a procedimientos documentados |
| Claves criptograficas | Exclusivamente para las operaciones definidas en PS06 (Gestion de Claves) |
| Datos de suscriptores | Procesamiento necesario para emision, renovacion o revocacion de certificados |
| Entorno de desarrollo | Desarrollo, testing y staging con datos sinteticos |
| Repositorio de codigo | Commits firmados, revisados por pares, conformes al flujo git documentado |
| Acceso remoto | Via VPN o TLS mutuo, desde dispositivos autorizados |

## 3. Uso Prohibido

- Acceso a claves privadas de CA, TSA u OCSP fuera de ceremonias documentadas o procesos automatizados autorizados.
- Copia, exportacion o transmision de claves privadas por cualquier medio no autorizado en PS06.
- Almacenamiento de datos de suscriptores (nombres, RUT, datos biometricos) en dispositivos personales, correo electronico no cifrado o servicios cloud no autorizados.
- Uso de credenciales de produccion en entornos de desarrollo o staging.
- Instalacion de software no autorizado en servidores de produccion.
- Desactivacion de controles de seguridad (ACL, TLS, logging, rate limiting) sin autorizacion escrita del Oficial de Seguridad.
- Acceso a sistemas fuera del ambito del rol asignado.
- Uso de los sistemas del PSC para fines personales, comerciales ajenos o actividades ilegales.

## 4. Gestion de Credenciales

- Las credenciales de acceso son personales e intransferibles.
- Las contrasenas deben cumplir con la politica de complejidad definida en PS02 (Politica de Seguridad).
- La autenticacion multifactor es obligatoria para acceso a sistemas de produccion.
- Las credenciales comprometidas deben reportarse inmediatamente al Oficial de Seguridad.

## 5. Monitoreo y Auditoria

- Todo acceso a sistemas de produccion se registra en el log de auditoria (RocksDB append-only cuando `STORAGE_BACKEND=rocksdb`).
- Los logs de acceso se retienen por 7 anos conforme a PO01 (Politica de Certificados).
- El Oficial de Seguridad revisa los logs de acceso trimestralmente.
- El personal reconoce que su actividad en los sistemas del PSC esta sujeta a monitoreo.

## 6. Dispositivos y Medios

- Los dispositivos utilizados para acceso a sistemas de produccion deben tener cifrado de disco habilitado.
- Los medios removibles que contengan claves o fragmentos M-of-N siguen los procedimientos de PS06 seccion 6.2.
- La destruccion de medios sigue los procedimientos de sanitizacion de PS06 conforme a NIST SP 800-88.

## 7. Incumplimiento

- El incumplimiento de esta politica se gestiona conforme al proceso disciplinario definido en PE01 (Evaluacion de Personal).
- Las infracciones graves (acceso no autorizado a claves, filtracion de datos de suscriptores) se reportan como incidente de seguridad conforme a PS07 (Gestion de Incidentes) y pueden resultar en terminacion inmediata del contrato.
- Los incidentes con impacto en suscriptores se notifican conforme a los plazos de eIDAS Art. 19(2) y NIS2 Art. 23.

## 8. Aceptacion

Todo el personal debe firmar una copia de esta politica antes de recibir acceso a los sistemas del PSC. La aceptacion se renueva anualmente o cuando la politica se actualiza.

## 9. Referencias

| Referencia | Descripcion |
|-----------|-------------|
| GOYA-PS02-001 | Politica de Seguridad |
| GOYA-PS06-001 | Plan de Gestion de Claves Criptograficas |
| GOYA-PS07-001 | Plan de Gestion de Incidentes |
| GOYA-PE01-001 | Evaluacion de Personal |
| ISO/IEC 27002:2022 Control 5.10 | Uso aceptable de informacion y activos |
| ETSI EN 319 401 clausula 7.4.2 | Controles de personal |
