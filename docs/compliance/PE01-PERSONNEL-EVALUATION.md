# PE01 -- Evaluacion del Personal en Roles de Confianza

**ID Documento:** GOYA-PE01-001
**Version:** 1.0
**Fecha:** 2026-09-01
**Estado:** Borrador
**Autor:** Oficial de Seguridad
**Aprobado por:** Pendiente -- Gerencia General
**Clasificacion:** Confidencial
**Proximo revision:** 2027-09-01

| Version | Fecha | Autor | Cambios |
|---------|-------|-------|---------|
| 1.0 | 2026-09-01 | Oficial de Seguridad | Documento inicial |

---

## 1. Control del Documento

### 1.1 Responsabilidad del documento

| Funcion | Nombre | Cargo |
|---------|--------|-------|
| Elaboracion | Oficial de Seguridad | Oficial de Seguridad de la Informacion |
| Revision tecnica | Arquitecto de Sistema | Arquitecto Criptografico / Sistema |
| Aprobacion | Pendiente | Gerente General |

### 1.2 Distribucion

Este documento se clasifica como **Confidencial** y se distribuye al Oficial de Seguridad, Gerencia General, Jefe de Recursos Humanos y Auditoria Interna. Cada receptor debe registrar acuse de recibo segun seccion 9.

### 1.3 Relacion con EA-103 v2.1

Este documento cumple con el sub-proceso PE01 de la Guia de Acreditacion EA-103 v2.1 de la Entidad Acreditadora (Subsecretaria de Economia), seccion 4.23. Sus dependencias directas son PS02 (Politica de Seguridad, GOYA-PS02-001) y PS04 (Plan SGSI, GOYA-PS04-001).

| Criterio EA-103 4.23 | Referencia en este documento |
|----------------------|------------------------------|
| Credenciales profesionales y de experiencia del personal | Secciones 3, 4 |
| Capacitacion en seguridad segun rol asignado | Seccion 6 |
| Verificacion de antecedentes comerciales | Seccion 5.1 |
| Verificacion de antecedentes penales | Seccion 5.2 |
| Procedimiento de contratacion | Seccion 5 |
| Verificacion post-contratacion | Seccion 7 |
| Definicion de perfiles "Altamente Confiable" | Secciones 3, 4 |

### 1.4 Documentos relacionados

| ID Documento | Titulo |
|-------------|--------|
| GOYA-PS01-001 | Analisis de Riesgos |
| GOYA-PS02-001 | Politica de Seguridad de la Informacion |
| GOYA-PS04-001 | Plan SGSI |
| GOYA-PS07-001 | Politica de Seguridad del Personal |
| GOYA-PO01-001 | Procedimientos Operacionales de AC |
| GOYA-PO04-001 | Control de Acceso Fisico y Logico |
| GOYA-PE02-001 | Evaluacion del Oficial de Seguridad |

---

## 2. Objetivo y Alcance

### 2.1 Objetivo

Definir los perfiles de cargo, requisitos de formacion, procedimientos de verificacion de antecedentes y programas de capacitacion para todo el personal que desempena roles de confianza dentro del Prestador de Servicios de Certificacion (PSC) Goya Ledger SpA, conforme a los requerimientos de acreditacion EA-103 v2.1 seccion 4.23.

### 2.2 Alcance

Este documento aplica a:

- Personal interno de Goya Ledger SpA que desempena roles de confianza en la operacion del PSC.
- Contratistas y consultores externos con acceso a sistemas criticos de la infraestructura PKI.
- Personal temporal que desempene funciones dentro del alcance de los roles definidos en la seccion 3.

### 2.3 Definicion de "Altamente Confiable"

Un rol se clasifica como **Altamente Confiable** cuando el personal que lo desempena tiene acceso directo o indirecto a:

- Material criptografico (llaves privadas de AC raiz, AC subordinadas o sellos de tiempo).
- Sistemas de emision, revocacion o suspension de certificados digitales.
- Infraestructura critica del PSC (HSM, servidores de AC/AR, repositorios de certificados).
- Registros de auditoria y evidencia forense del PSC.
- Datos personales de suscriptores protegidos por la Ley 19.628.

Todos los roles definidos en la seccion 3 se consideran Altamente Confiables.

---

## 3. Definicion de Roles de Confianza

### 3.1 Administrador de AC (Autoridad Certificadora)

**Codigo de rol:** ROL-AC-ADM

**Descripcion:** Responsable de la operacion, configuracion y mantenimiento de los sistemas de la Autoridad Certificadora. Ejecuta ceremonias de generacion de llaves, firma de certificados de AC subordinadas y administracion del ciclo de vida de certificados.

**Funciones principales:**

- Operar el software y hardware de la AC (incluyendo HSM).
- Ejecutar ceremonias de llaves conforme a PO01.
- Gestionar el ciclo de vida de certificados: emision, renovacion, revocacion y suspension.
- Publicar CRL y respuestas OCSP.
- Mantener la integridad de los repositorios de certificados.
- Custodiar los respaldos de configuracion de la AC.

**Separacion de funciones:** El Administrador de AC no puede desempenar simultaneamente el rol de Auditor Interno ni de Custodio de Llaves de recuperacion.

### 3.2 Administrador de AR (Autoridad de Registro)

**Codigo de rol:** ROL-AR-ADM

**Descripcion:** Responsable de los procesos de verificacion de identidad de solicitantes, aprobacion de solicitudes de certificados y gestion de las comunicaciones con suscriptores.

**Funciones principales:**

- Verificar la identidad de solicitantes conforme al procedimiento PO02.
- Aprobar o rechazar solicitudes de certificados.
- Gestionar solicitudes de revocacion y suspension.
- Mantener registros de verificacion de identidad.
- Custodiar documentacion de suscriptores conforme a Ley 19.628.
- Coordinar la validacion presencial o remota de identidad.

**Separacion de funciones:** El Administrador de AR no puede aprobar sus propias solicitudes de certificado ni desempenar el rol de Administrador de AC.

### 3.3 Operador de Sistemas

**Codigo de rol:** ROL-SYS-OPS

**Descripcion:** Responsable de la administracion de la infraestructura tecnologica que soporta los servicios del PSC, incluyendo servidores, redes, almacenamiento y sistemas de respaldo.

**Funciones principales:**

- Administrar servidores de produccion, staging y desarrollo.
- Gestionar la infraestructura de red y firewalls del PSC.
- Ejecutar y verificar procedimientos de respaldo y recuperacion.
- Monitorear la disponibilidad y rendimiento de los servicios.
- Aplicar parches de seguridad y actualizaciones de sistema operativo.
- Mantener la documentacion de configuracion de infraestructura.

**Separacion de funciones:** El Operador de Sistemas no tiene acceso al material criptografico de la AC. El acceso a sistemas de produccion requiere autorizacion del Oficial de Seguridad.

### 3.4 Auditor Interno

**Codigo de rol:** ROL-AUD-INT

**Descripcion:** Responsable de la revision independiente de los controles, procedimientos y registros del PSC para verificar el cumplimiento de la CPS, politicas de seguridad y requisitos regulatorios.

**Funciones principales:**

- Ejecutar el plan de auditoria interna conforme a PS06.
- Revisar registros de auditoria de la AC y AR.
- Verificar el cumplimiento de la CPS y politicas del PSC.
- Emitir informes de auditoria con hallazgos y recomendaciones.
- Dar seguimiento a la remediacion de no conformidades.
- Reportar directamente a Gerencia General.

**Separacion de funciones:** El Auditor Interno no puede desempenar ningun otro rol operativo dentro del PSC. Su independencia funcional esta garantizada por reporte directo a Gerencia General.

### 3.5 Custodio de Llaves

**Codigo de rol:** ROL-KEY-CUS

**Descripcion:** Responsable de la custodia fisica de componentes de activacion del HSM (tarjetas inteligentes, PINs, shares de recuperacion) utilizados en ceremonias de llaves y procedimientos de recuperacion de desastres.

**Funciones principales:**

- Custodiar de forma segura los componentes de activacion asignados.
- Participar en ceremonias de generacion y destruccion de llaves.
- Participar en procedimientos de recuperacion de desastres que requieran reconstruccion de llaves.
- Reportar inmediatamente cualquier compromiso o sospecha de compromiso de los componentes bajo su custodia.
- Mantener el secreto de los componentes asignados conforme al esquema M-de-N.

**Separacion de funciones:** Se requieren al menos 3 Custodios de Llaves para operar bajo esquema M-de-N (minimo 2-de-3). Ningun Custodio puede ser simultaneamente Administrador de AC.

---

## 4. Perfiles de Cargo

### 4.1 Administrador de AC

| Aspecto | Requisito |
|---------|-----------|
| Formacion | Ingeniero Civil Informatico, Ingeniero en Computacion o carrera afin. Titulo profesional reconocido en Chile |
| Experiencia | Minimo 3 anos en administracion de infraestructura PKI, gestion de certificados digitales o criptografia aplicada |
| Conocimientos | Estandares X.509v3, RFC 5280, PKCS#11, operacion de HSM, protocolos OCSP/CRL, criptografia post-cuantica (ML-DSA, ML-KEM) |
| Certificaciones deseables | CompTIA Security+, Certified PKI Professional (CPKIP), certificacion de fabricante de HSM |
| Idiomas | Espanol nativo. Ingles tecnico lectura (manuales, RFC, estandares) |
| Habilitacion de seguridad | Antecedentes penales y comerciales limpios. NDA firmado |

### 4.2 Administrador de AR

| Aspecto | Requisito |
|---------|-----------|
| Formacion | Ingeniero Civil Informatico, Ingeniero Comercial con especializacion en TI, o carrera afin. Titulo profesional reconocido en Chile |
| Experiencia | Minimo 2 anos en procesos de verificacion de identidad, atencion de requerimientos de certificacion digital o administracion de sistemas de registro |
| Conocimientos | Procedimientos de verificacion de identidad (presencial y remota), normativa Ley 19.799, Ley 19.628 (proteccion de datos personales), estandares ETSI EN 319 411-1 |
| Certificaciones deseables | ISO 27001 Foundation, certificacion en proteccion de datos personales |
| Idiomas | Espanol nativo. Ingles tecnico lectura |
| Habilitacion de seguridad | Antecedentes penales y comerciales limpios. NDA firmado |

### 4.3 Operador de Sistemas

| Aspecto | Requisito |
|---------|-----------|
| Formacion | Ingeniero Civil Informatico, Ingeniero en Redes, Tecnico en Administracion de Redes o carrera afin |
| Experiencia | Minimo 3 anos en administracion de servidores Linux, gestion de redes, implementacion de firewalls y sistemas de monitoreo en ambientes de produccion |
| Conocimientos | Administracion Linux (Ubuntu/Debian), Docker, redes TCP/IP, TLS 1.3, firewalls (iptables/nftables), monitoreo (Prometheus/Grafana), procedimientos de respaldo y recuperacion |
| Certificaciones deseables | LPIC-2, CompTIA Linux+, AWS Solutions Architect Associate, Red Hat Certified Engineer (RHCE) |
| Idiomas | Espanol nativo. Ingles tecnico lectura |
| Habilitacion de seguridad | Antecedentes penales y comerciales limpios. NDA firmado |

### 4.4 Auditor Interno

| Aspecto | Requisito |
|---------|-----------|
| Formacion | Ingeniero Civil Informatico, Ingeniero Civil Industrial, Contador Auditor o carrera afin. Titulo profesional reconocido en Chile |
| Experiencia | Minimo 3 anos en auditoria de sistemas de informacion, auditoria de seguridad informatica o auditoria de cumplimiento normativo |
| Conocimientos | ISO 27001/27002, ISO 19011 (directrices de auditoria), ETSI TS 102 042, ETSI EN 319 411-1/2, Ley 19.799, estandares WebTrust for CAs |
| Certificaciones deseables | CISA (Certified Information Systems Auditor), ISO 27001 Lead Auditor, CRISC |
| Idiomas | Espanol nativo. Ingles tecnico lectura |
| Habilitacion de seguridad | Antecedentes penales y comerciales limpios. NDA firmado. Sin conflicto de interes con operaciones del PSC |

### 4.5 Custodio de Llaves

| Aspecto | Requisito |
|---------|-----------|
| Formacion | Profesional o tecnico en area de tecnologia, ingenieria o ciencias. Titulo reconocido en Chile |
| Experiencia | Minimo 1 ano en entornos de alta seguridad o manejo de material sensible |
| Conocimientos | Principios basicos de criptografia, procedimientos de ceremonias de llaves, esquemas de secreto compartido (Shamir), manejo seguro de HSM |
| Certificaciones deseables | Certificacion de fabricante de HSM, CompTIA Security+ |
| Idiomas | Espanol nativo |
| Habilitacion de seguridad | Antecedentes penales y comerciales limpios. NDA firmado. Evaluacion de confiabilidad personal |

---

## 5. Procedimiento de Contratacion Segura

Todo personal que desempene un rol de confianza debe completar el procedimiento de contratacion segura antes de obtener acceso a sistemas, instalaciones o informacion del PSC.

### 5.1 Verificacion de antecedentes comerciales

| Paso | Descripcion | Responsable | Evidencia |
|------|-------------|-------------|-----------|
| 1 | Solicitar certificado de antecedentes comerciales al candidato, emitido por la Camara de Comercio de Santiago o entidad equivalente | Recursos Humanos | Certificado original con fecha no superior a 30 dias |
| 2 | Verificar que el candidato no presenta protestos de documentos, morosidades en el sistema financiero ni quiebras vigentes | Recursos Humanos | Informe de verificacion firmado |
| 3 | Consultar registros de Dicom/Equifax para verificar situacion comercial | Recursos Humanos | Reporte impreso y fechado |
| 4 | Documentar resultado en expediente del candidato | Recursos Humanos | Expediente actualizado |

**Criterio de rechazo:** Se rechazara al candidato que presente protestos vigentes no aclarados, quiebras en curso o deudas impagas superiores a 90 dias con entidades financieras, salvo justificacion documentada aprobada por Gerencia General.

### 5.2 Verificacion de antecedentes penales

| Paso | Descripcion | Responsable | Evidencia |
|------|-------------|-------------|-----------|
| 1 | Solicitar certificado de antecedentes penales emitido por el Servicio de Registro Civil e Identificacion de Chile | Recursos Humanos | Certificado original con fecha no superior a 30 dias |
| 2 | Verificar que el candidato no presenta condenas por delitos contra la fe publica, delitos informaticos (Ley 21.459), fraude, estafa, falsificacion o delitos contra la propiedad intelectual | Recursos Humanos | Informe de verificacion firmado |
| 3 | Para personal extranjero, solicitar certificado de antecedentes penales del pais de origen apostillado o legalizado | Recursos Humanos | Certificado apostillado/legalizado |
| 4 | Documentar resultado en expediente del candidato | Recursos Humanos | Expediente actualizado |

**Criterio de rechazo:** Se rechazara al candidato que presente condenas vigentes por delitos contra la fe publica, delitos informaticos, fraude, falsificacion de instrumentos o cualquier delito que comprometa la confianza requerida para el rol. Antecedentes eliminados conforme al Decreto Ley 409 no constituyen impedimento.

### 5.3 Verificacion de referencias profesionales

| Paso | Descripcion | Responsable | Evidencia |
|------|-------------|-------------|-----------|
| 1 | Solicitar al candidato al menos 2 referencias profesionales de empleadores anteriores en los ultimos 5 anos | Recursos Humanos | Datos de contacto de referentes |
| 2 | Contactar a cada referente y verificar: periodo de empleo, cargo desempenado, motivo de desvinculacion, desempeno general | Recursos Humanos | Formulario de verificacion completado por cada referente |
| 3 | Verificar la autenticidad de titulos profesionales y certificaciones declaradas mediante consulta directa a la institucion emisora | Recursos Humanos | Constancia de verificacion |
| 4 | Documentar resultado en expediente del candidato | Recursos Humanos | Expediente actualizado |

### 5.4 Firma de NDA y compromiso de confidencialidad

| Paso | Descripcion | Responsable | Evidencia |
|------|-------------|-------------|-----------|
| 1 | Entregar al candidato el Acuerdo de Confidencialidad (NDA) del PSC para revision previa a la firma | Recursos Humanos | Acuse de recibo del NDA |
| 2 | El NDA debe incluir como minimo: definicion de informacion confidencial, obligaciones del receptor, plazo de vigencia (minimo 5 anos post-termino), sanciones por incumplimiento, jurisdiccion aplicable (tribunales de Santiago) | Asesoria Legal | NDA revisado por area legal |
| 3 | Firmar el NDA ante ministro de fe o con firma electronica avanzada | Candidato + Gerencia General | NDA firmado y fechado |
| 4 | Registrar el NDA en el sistema de gestion documental del PSC | Recursos Humanos | Registro en sistema documental |

El NDA debe cubrir expresamente:

- Material criptografico y procedimientos de ceremonias de llaves.
- Datos personales de suscriptores.
- Arquitectura de seguridad y configuracion de sistemas del PSC.
- Vulnerabilidades conocidas y planes de remediacion.
- Registros de auditoria e incidentes de seguridad.
- Informacion comercial y estrategica de Goya Ledger SpA.

---

## 6. Capacitacion en Seguridad

### 6.1 Programa inicial (induccion)

Todo personal en rol de confianza debe completar el programa de induccion en seguridad dentro de los primeros 15 dias habiles desde su incorporacion y antes de obtener acceso a sistemas de produccion del PSC.

| Modulo | Contenido | Duracion | Evaluacion |
|--------|-----------|----------|------------|
| M01 - Marco regulatorio | Ley 19.799, Reglamento DS 181, EA-103 v2.1, ETSI EN 319 411-1/2, eIDAS (referencia) | 4 horas | Examen escrito (70% minimo) |
| M02 - Politica de seguridad | PS02 Politica de Seguridad, PS04 Plan SGSI, CPS del PSC | 3 horas | Examen escrito (70% minimo) |
| M03 - Seguridad de la informacion | ISO 27001/27002 fundamentos, clasificacion de informacion, gestion de incidentes | 4 horas | Examen escrito (70% minimo) |
| M04 - Seguridad operacional | Procedimientos de acceso fisico (PO04), gestion de llaves (PO01), respaldo y recuperacion (PO03) | 3 horas | Evaluacion practica |
| M05 - Proteccion de datos personales | Ley 19.628, tratamiento de datos de suscriptores, derechos ARCO | 2 horas | Examen escrito (70% minimo) |
| M06 - Ingenieria social y amenazas | Phishing, pretexting, tailgating, reporte de incidentes sospechosos | 2 horas | Simulacro practico |

**Criterio de aprobacion:** El personal debe aprobar todos los modulos con nota minima de 70%. En caso de reprobacion, se permite un reintento dentro de los 5 dias habiles siguientes. Dos reprobaciones consecutivas requieren evaluacion por el Oficial de Seguridad.

### 6.2 Capacitacion continua (anual)

Todo personal en rol de confianza debe completar un minimo de 16 horas anuales de capacitacion en seguridad de la informacion, distribuidas en:

| Actividad | Frecuencia | Duracion | Registro |
|-----------|------------|----------|----------|
| Actualizacion normativa y regulatoria | Anual | 4 horas | Certificado de asistencia |
| Simulacro de incidentes de seguridad | Semestral | 2 horas por simulacro | Informe de simulacro |
| Taller de amenazas emergentes (phishing, ransomware, ataques a PKI) | Anual | 4 horas | Certificado de asistencia |
| Evaluacion de conocimientos de seguridad | Anual | 2 horas | Resultado de evaluacion (70% minimo) |
| Revision de politicas y procedimientos actualizados | Ante cada actualizacion | Variable | Acuse de recibo firmado |

### 6.3 Capacitacion especifica por rol

Adicionalmente a la capacitacion comun, cada rol requiere formacion especializada:

**Administrador de AC:**

- Operacion de HSM y PKCS#11 (8 horas anuales).
- Ceremonias de generacion de llaves y firma de AC subordinadas (4 horas anuales).
- Criptografia post-cuantica: ML-DSA-65, ML-KEM, estrategias de migracion hibrida (4 horas anuales).
- Estandares de perfil de certificados X.509v3 y RFC 5280 (4 horas anuales).

**Administrador de AR:**

- Procedimientos de verificacion de identidad presencial y remota (4 horas anuales).
- Normativa de proteccion de datos personales aplicada a AR (4 horas anuales).
- Deteccion de documentos fraudulentos y suplantacion de identidad (4 horas anuales).

**Operador de Sistemas:**

- Hardening de servidores Linux y contenedores (4 horas anuales).
- Seguridad de redes y deteccion de intrusiones (4 horas anuales).
- Procedimientos de respaldo, recuperacion y continuidad operacional (4 horas anuales).
- Gestion de vulnerabilidades y aplicacion de parches (4 horas anuales).

**Auditor Interno:**

- Metodologia de auditoria ISO 19011 (8 horas anuales).
- Actualizacion en estandares ETSI y WebTrust para PSC (4 horas anuales).
- Herramientas de analisis de registros de auditoria (4 horas anuales).

**Custodio de Llaves:**

- Procedimientos de ceremonias de llaves y recuperacion de desastres (4 horas anuales).
- Manejo seguro de componentes de activacion de HSM (2 horas anuales).

---

## 7. Verificacion Post-Contratacion

La verificacion de antecedentes y aptitud del personal en roles de confianza no se limita al momento de la contratacion. Se ejecutan las siguientes verificaciones periodicas:

| Verificacion | Frecuencia | Responsable | Accion ante hallazgo |
|-------------|------------|-------------|---------------------|
| Antecedentes penales | Anual | Recursos Humanos | Evaluacion por Oficial de Seguridad y Gerencia General |
| Antecedentes comerciales | Anual | Recursos Humanos | Evaluacion por Oficial de Seguridad |
| Evaluacion de desempeno en seguridad | Semestral | Oficial de Seguridad | Plan de mejora o reasignacion |
| Renovacion de compromiso de confidencialidad | Cada 2 anos | Recursos Humanos | Firma de renovacion o desvinculacion |
| Verificacion de certificaciones profesionales vigentes | Anual | Recursos Humanos | Plan de renovacion o capacitacion compensatoria |
| Evaluacion de conflicto de interes | Anual | Oficial de Seguridad | Declaracion jurada actualizada |

**Procedimiento ante hallazgo adverso:**

1. El hallazgo se reporta al Oficial de Seguridad dentro de las 24 horas siguientes a su deteccion.
2. El Oficial de Seguridad evalua el impacto del hallazgo en la confiabilidad del personal para el rol asignado.
3. Si el hallazgo compromete la confiabilidad, se suspenden temporalmente los accesos del personal afectado.
4. Gerencia General, con asesoria del Oficial de Seguridad y Asesoria Legal, determina la accion definitiva: reasignacion, capacitacion correctiva o desvinculacion.
5. Se documenta la decision y las acciones tomadas en el expediente del personal.

---

## 8. Procedimiento de Desvinculacion

### 8.1 Revocacion de accesos

| Paso | Accion | Plazo | Responsable |
|------|--------|-------|-------------|
| 1 | Notificar al Oficial de Seguridad sobre la desvinculacion | Inmediato al comunicar la desvinculacion | Recursos Humanos |
| 2 | Revocar acceso logico: cuentas de usuario, VPN, correo electronico, acceso a repositorios | Dentro de las 2 horas siguientes a la notificacion | Operador de Sistemas |
| 3 | Revocar acceso fisico: desactivar tarjetas de acceso, biometria, llaves fisicas | Dentro de las 2 horas siguientes a la notificacion | Oficial de Seguridad |
| 4 | Revocar certificados digitales personales emitidos al personal | Dentro de las 4 horas siguientes a la notificacion | Administrador de AC |
| 5 | Revocar tokens de autenticacion, API keys y credenciales de servicio asociadas | Dentro de las 2 horas siguientes a la notificacion | Operador de Sistemas |
| 6 | Verificar la completitud de la revocacion de todos los accesos | Dentro de las 24 horas | Oficial de Seguridad |

### 8.2 Devolucion de activos

| Activo | Procedimiento | Responsable |
|--------|---------------|-------------|
| Equipos de computo (laptops, monitores, perifericos) | Devolucion con inventario verificado. Borrado seguro del disco conforme a NIST SP 800-88 | Operador de Sistemas |
| Dispositivos de autenticacion (tokens, tarjetas inteligentes) | Devolucion y destruccion certificada | Oficial de Seguridad |
| Componentes de activacion de HSM (para Custodios de Llaves) | Devolucion inmediata. Ceremonia de reemplazo de componente si aplica | Administrador de AC |
| Documentacion fisica clasificada | Devolucion y verificacion contra inventario | Oficial de Seguridad |
| Copias digitales de documentacion del PSC | Certificacion de borrado. Declaracion jurada de no retencion | Operador de Sistemas + Personal desvinculado |

### 8.3 Vigencia de NDA post-termino

- El NDA firmado al ingreso mantiene su vigencia por un periodo minimo de **5 anos** contados desde la fecha efectiva de desvinculacion.
- El personal desvinculado debe firmar un recordatorio de vigencia del NDA al momento de la desvinculacion.
- Las clausulas de confidencialidad relativas a material criptografico, vulnerabilidades de seguridad y datos personales de suscriptores tienen vigencia **indefinida**.
- El incumplimiento del NDA post-termino faculta a Goya Ledger SpA para ejercer las acciones legales civiles y penales correspondientes conforme a la legislacion chilena.

---

## 9. Registros y Evidencia

Los siguientes registros deben mantenerse como evidencia de cumplimiento y estar disponibles para auditoria interna y externa:

| Registro | Formato | Retencion | Responsable |
|----------|---------|-----------|-------------|
| Expediente de contratacion (antecedentes, referencias, verificaciones) | Fisico y digital | 10 anos desde la desvinculacion | Recursos Humanos |
| NDA firmados (originales y renovaciones) | Fisico y digital | Indefinido | Asesoria Legal |
| Certificados de capacitacion y evaluaciones | Digital | 10 anos desde la desvinculacion | Recursos Humanos |
| Resultados de verificaciones periodicas | Digital | 5 anos | Oficial de Seguridad |
| Actas de desvinculacion y revocacion de accesos | Fisico y digital | 10 anos | Recursos Humanos |
| Declaraciones juradas de conflicto de interes | Fisico y digital | 5 anos desde la desvinculacion | Oficial de Seguridad |
| Registros de asistencia a capacitaciones | Digital | 5 anos | Recursos Humanos |

Todos los registros digitales deben almacenarse en el sistema de gestion documental del PSC con control de acceso restringido al Oficial de Seguridad, Recursos Humanos y Gerencia General.

Los registros fisicos deben almacenarse en area de acceso controlado conforme a PO04.

---

## 10. Referencias

| Referencia | Descripcion |
|-----------|-------------|
| Ley 19.799 | Sobre documentos electronicos, firma electronica y servicios de certificacion |
| DS 181/2002 | Reglamento de la Ley 19.799 |
| EA-103 v2.1 | Guia de Acreditacion de Prestadores de Servicios de Certificacion, seccion 4.23 |
| ISO/IEC 27001:2022 | Sistemas de gestion de seguridad de la informacion |
| ISO/IEC 27002:2022 | Controles de seguridad de la informacion (secciones 6.1 a 6.6: controles de personas) |
| ETSI TS 102 042 | Policy requirements for certification authorities issuing public key certificates |
| ETSI EN 319 411-1 | Electronic Signatures and Infrastructures -- Policy and security requirements for TSP issuing certificates -- Part 1 |
| Ley 19.628 | Sobre proteccion de la vida privada (datos personales) |
| Ley 21.459 | Sobre delitos informaticos |
| NIST SP 800-88 Rev.1 | Guidelines for Media Sanitization |
| ISO 19011:2018 | Directrices para la auditoria de sistemas de gestion |
