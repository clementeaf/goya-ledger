# Acuerdo de Suscriptor

**Prestador de Servicios de Certificacion Goya Ledger**

| Campo | Valor |
|---|---|
| **Version** | 1.0.0 |
| **Estado** | Borrador |
| **Fecha de vigencia** | 2024-01-01 |
| **OID de la CP** | `1.3.6.1.4.1.99999.2.1` |
| **OID de la CPS** | `1.3.6.1.4.1.99999.2.2` |
| **Jurisdiccion** | Republica de Chile |
| **CP publicada en** | `GET /api/v1/cp/document` |
| **CPS publicada en** | `GET /api/v1/cps/document` |

---

## Indice

1. [Partes](#1-partes)
2. [Definiciones](#2-definiciones)
3. [Objeto del acuerdo](#3-objeto-del-acuerdo)
4. [Obligaciones del PSC](#4-obligaciones-del-psc)
5. [Obligaciones del suscriptor](#5-obligaciones-del-suscriptor)
6. [Proceso de solicitud de certificado](#6-proceso-de-solicitud-de-certificado)
7. [Niveles de firma y requisitos](#7-niveles-de-firma-y-requisitos)
8. [Revocacion y suspension](#8-revocacion-y-suspension)
9. [Limitacion de responsabilidad](#9-limitacion-de-responsabilidad)
10. [Proteccion de datos personales y consentimiento](#10-proteccion-de-datos-personales-y-consentimiento)
11. [Propiedad intelectual](#11-propiedad-intelectual)
12. [Duracion, renovacion y terminacion](#12-duracion-renovacion-y-terminacion)
13. [Resolucion de controversias](#13-resolucion-de-controversias)
14. [Ley aplicable](#14-ley-aplicable)
15. [Disposiciones generales](#15-disposiciones-generales)

---

## 1. Partes

Comparecen en el presente acuerdo:

**A. El Prestador de Servicios de Certificacion (en adelante, "el PSC"):**

Goya Ledger, en su calidad de Prestador de Servicios de Certificacion de firma electronica, con domicilio en Santiago, Republica de Chile, que opera la Autoridad de Certificacion (CA) y la Autoridad de Registro (RA) conforme a la Politica de Certificados (CP, OID `1.3.6.1.4.1.99999.2.1`) y la Declaracion de Practicas de Certificacion (CPS, OID `1.3.6.1.4.1.99999.2.2`) publicadas en `GET /api/v1/cp/document` y `GET /api/v1/cps/document`, respectivamente.

**B. El Suscriptor (en adelante, "el Suscriptor"):**

La persona natural o juridica individualizada en la solicitud de certificado, identificada mediante su Identificador Descentralizado (DID) en formato `did:goya:{clave_publica_hex[..16]}`, derivado canonicamente mediante la funcion `identity::did::did_from_pubkey_hex()`.

Ambas partes, en adelante denominadas conjuntamente "las Partes", declaran su voluntad libre y espontanea de celebrar el presente acuerdo, sujeto a los terminos y condiciones que se expresan a continuacion.

---

## 2. Definiciones

Para los efectos del presente acuerdo, se entendera por:

**Autoridad de Certificacion (CA):** Entidad de confianza que emite, administra, revoca y renueva certificados digitales dentro de la infraestructura de clave publica (PKI) de Goya Ledger. La CA opera una jerarquia de dos niveles: CA Raiz (offline) y CA Intermedia (operacional).

**Autoridad de Registro (RA):** Entidad responsable de la verificacion de identidad del Suscriptor previo a la emision de certificados, conforme al articulo 15 de la Ley 19.799. Implementada en el modulo `src/identity/ra.rs`.

**Certificado digital:** Documento electronico firmado digitalmente por la CA que vincula una clave publica con la identidad de su titular, conforme al estandar X.509 v3.

**Clave privada:** Clave criptografica secreta del Suscriptor, utilizada para generar firmas electronicas. Nunca es transferida al PSC cuando es generada por el Suscriptor.

**Clave publica:** Clave criptografica contenida en el certificado digital, utilizada por terceros para verificar las firmas electronicas del Suscriptor.

**CP (Certificate Policy):** Politica de certificados del PSC, publicada bajo OID `1.3.6.1.4.1.99999.2.1`.

**CPS (Certification Practice Statement):** Declaracion de practicas de certificacion del PSC, publicada bajo OID `1.3.6.1.4.1.99999.2.2`.

**CRL (Certificate Revocation List):** Lista de certificados revocados publicada por la CA, conforme a RFC 5280. Disponible en `GET /api/v1/crl` (formato DER) y `GET /api/v1/crl/pem` (formato PEM).

**DID (Decentralized Identifier):** Identificador descentralizado del Suscriptor en formato `did:goya:{clave_publica_hex[..16]}`.

**Evidencia biometrica:** Compromiso criptografico (hash SHA-256) de datos biometricos del Suscriptor, requerido para certificados de Firma Electronica Avanzada (FEA). Los datos biometricos en bruto nunca son almacenados por el PSC.

**FEA (Firma Electronica Avanzada):** Firma electronica avanzada conforme al articulo 2, letra g) de la Ley 19.799, que utiliza el algoritmo ML-DSA-65 (FIPS 204) con vinculacion biometrica, proporcionando no repudio y equivalencia legal a la firma manuscrita.

**FES (Firma Electronica Simple):** Firma electronica simple conforme al articulo 2, letra f) de la Ley 19.799, que utiliza el algoritmo Ed25519 (FIPS 186-5), proporcionando autenticacion e integridad.

**HSM (Hardware Security Module):** Modulo de seguridad de hardware utilizado para la proteccion de claves criptograficas de la CA, conforme a FIPS 140-2/3.

**OCSP (Online Certificate Status Protocol):** Protocolo de consulta de estado de certificados en tiempo real, conforme a RFC 6960. Disponible en `GET /api/v1/ocsp/query` (formato JSON) y `GET /api/v1/ocsp/query/der` (formato DER).

**PSC (Prestador de Servicios de Certificacion):** Goya Ledger, en su calidad de entidad que presta servicios de certificacion de firma electronica conforme a la Ley 19.799.

**RUT (Rol Unico Tributario):** Numero de identificacion tributaria chileno, validado mediante el algoritmo modulo 11.

**Sello electronico:** Firma de persona juridica para la integridad de documentos institucionales, conforme al perfil LegalPerson de la CP.

**TSA (Time-Stamping Authority):** Autoridad de sellado de tiempo conforme a RFC 3161, disponible en `GET /api/v1/tsa/timestamp`.

---

## 3. Objeto del acuerdo

El presente acuerdo tiene por objeto establecer los terminos y condiciones bajo los cuales el PSC emitira, administrara y revocara certificados digitales de firma electronica a favor del Suscriptor, dentro del marco de la infraestructura de clave publica (PKI) de Goya Ledger.

El acuerdo regula:

a) La emision de certificados digitales X.509 v3 para firma electronica simple (FES), firma electronica avanzada (FEA) o sello electronico, segun el perfil solicitado por el Suscriptor y aprobado por la RA.

b) Las obligaciones reciprocas de las Partes en relacion con la generacion, custodia y uso de las claves criptograficas.

c) Los procedimientos de verificacion de identidad, emision, revocacion y suspension de certificados.

d) Las condiciones de uso, limitaciones de responsabilidad y proteccion de datos personales.

El presente acuerdo se complementa con la CP y la CPS vigentes al momento de la emision del certificado, las cuales se entienden incorporadas por referencia al presente instrumento. En caso de conflicto entre el presente acuerdo y la CP o la CPS, prevalecera el orden siguiente: (i) la CP, (ii) la CPS, (iii) el presente acuerdo.

---

## 4. Obligaciones del PSC

El PSC se obliga a cumplir las siguientes obligaciones:

### 4.1 Emision de certificados

a) Emitir certificados digitales exclusivamente conforme a los procedimientos, perfiles y requisitos establecidos en la CP (OID `1.3.6.1.4.1.99999.2.1`) y la CPS (OID `1.3.6.1.4.1.99999.2.2`).

b) Emitir certificados unicamente despues de la verificacion exitosa de identidad por parte de la RA, conforme al articulo 15 de la Ley 19.799.

c) Incluir en cada certificado el OID de la CP (`1.3.6.1.4.1.99999.2.1`) en la extension `certificatePolicies` (OID 2.5.29.32), con un calificador CPS Pointer.

d) Verificar que el perfil del certificado corresponda a los usos declarados por el Suscriptor conforme a la seccion 7 del presente acuerdo.

### 4.2 Mantenimiento de servicios de estado

a) Mantener disponible el servicio de consulta de CRL en los endpoints `GET /api/v1/crl` (formato DER) y `GET /api/v1/crl/pem` (formato PEM).

b) Mantener disponible el servicio OCSP en los endpoints `GET /api/v1/ocsp/query` (formato JSON) y `GET /api/v1/ocsp/query/der` (formato DER), conforme a RFC 6960.

c) Publicar una nueva CRL dentro de una (1) hora desde cualquier evento de revocacion.

d) Mantener disponible el servicio de sellado de tiempo (TSA) en el endpoint `GET /api/v1/tsa/timestamp`, conforme a RFC 3161.

e) Proporcionar acceso gratuito a los servicios de verificacion de estado (CRL y OCSP) a las partes confiantes.

### 4.3 Proteccion de datos personales

a) Tratar los datos personales del Suscriptor conforme a la Ley 19.628 sobre Proteccion de la Vida Privada y, cuando resulte aplicable, el Reglamento General de Proteccion de Datos de la Union Europea (RGPD/GDPR).

b) Implementar medidas tecnicas y organizativas para proteger la informacion personal contra acceso no autorizado, divulgacion, modificacion o destruccion.

c) No almacenar datos biometricos en bruto del Suscriptor. Unicamente se almacena el compromiso criptografico (hash SHA-256) de la evidencia biometrica.

d) No transferir datos personales del Suscriptor a terceros, salvo requerimiento judicial o administrativo conforme a la legislacion vigente.

e) Conservar los registros de verificacion de identidad por un periodo de siete (7) anos, conforme a la CP.

### 4.4 Notificacion de compromiso de claves

a) Notificar al Suscriptor dentro de veinticuatro (24) horas en caso de compromiso conocido o sospechado de las claves de la CA que afecten la validez de su certificado.

b) Proceder a la revocacion inmediata de los certificados afectados y publicar la CRL actualizada conforme a los procedimientos del Plan de Contingencia.

c) Publicar avisos de compromiso a traves de los mecanismos de notificacion del PSC, incluyendo la API, correo electronico registrado y el sistema de notificaciones de Goya Ledger.

### 4.5 Publicacion de documentos normativos

a) Mantener publicada la version vigente de la CP en `GET /api/v1/cp/document`.

b) Mantener publicada la version vigente de la CPS en `GET /api/v1/cps/document`.

c) Notificar las modificaciones sustanciales a la CP o la CPS con al menos treinta (30) dias de anticipacion a su entrada en vigencia.

### 4.6 Registro de auditoria

a) Mantener registros de auditoria encadenados por hash de todas las operaciones de la CA, la RA y los servicios de estado.

b) Conservar los registros de auditoria por un periodo minimo de siete (7) anos.

---

## 5. Obligaciones del suscriptor

El Suscriptor se obliga a cumplir las siguientes obligaciones:

### 5.1 Veracidad de la informacion

a) Proporcionar informacion veraz, completa y actualizada durante el proceso de verificacion de identidad (identity proofing) ante la RA.

b) Presentar documentacion de identidad valida, incluyendo cedula de identidad vigente y RUT, para su validacion mediante el algoritmo modulo 11.

c) En caso de persona juridica, acreditar la existencia legal de la entidad, la representacion legal del solicitante y la vigencia del mandato conferido.

### 5.2 Proteccion de la clave privada

a) Generar, almacenar y utilizar su clave privada en condiciones que aseguren su confidencialidad e integridad.

b) No compartir, transferir, copiar ni revelar su clave privada a terceros bajo ninguna circunstancia.

c) Emplear dispositivos seguros para el almacenamiento de la clave privada. Para certificados de FEA, se recomienda el uso de dispositivos criptograficos certificados (HSM, token criptografico o tarjeta inteligente).

d) Implementar controles de acceso adecuados (contrasenas, biometria u otros factores de autenticacion) para proteger el acceso a la clave privada.

### 5.3 Notificacion de compromiso

a) Notificar al PSC dentro de veinticuatro (24) horas desde el momento en que tome conocimiento o sospeche razonablemente del compromiso, perdida, robo, divulgacion no autorizada o uso indebido de su clave privada.

b) La notificacion debera realizarse a traves de los canales establecidos por el PSC, incluyendo la solicitud de revocacion mediante la API o el contacto directo con la RA.

c) El Suscriptor sera responsable de todas las firmas electronicas generadas con su clave privada hasta el momento en que el PSC procese efectivamente la solicitud de revocacion.

### 5.4 Uso conforme del certificado

a) Utilizar el certificado exclusivamente para los fines declarados en la solicitud y autorizados por el perfil del certificado, conforme a las extensiones Key Usage y Extended Key Usage.

b) No utilizar el certificado para actividades ilicitas, fraudulentas o que contravengan la legislacion vigente.

c) No utilizar el certificado para fines prohibidos por la CP, incluyendo pero no limitado a: emision de certificados propios, firma de codigo malicioso, cifrado de comunicaciones para ocultar actividades delictivas o actividades que infrinjan la ley aplicable.

d) Respetar las limitaciones de monto o transaccion asociadas al nivel de firma del certificado.

### 5.5 Revocacion por cambio de datos

a) Solicitar la revocacion de su certificado antes de su fecha de expiracion si alguno de los datos contenidos en el certificado deja de ser exacto o vigente, incluyendo cambio de nombre, razon social, RUT, domicilio legal u otros atributos certificados.

b) Solicitar un nuevo certificado con la informacion actualizada, cumpliendo nuevamente el proceso de verificacion de identidad.

### 5.6 Aceptacion de la CP y la CPS

a) El Suscriptor declara haber leido, comprendido y aceptado la CP y la CPS vigentes al momento de la emision del certificado.

b) El Suscriptor se obliga a mantenerse informado de las modificaciones a la CP y la CPS publicadas por el PSC.

---

## 6. Proceso de solicitud de certificado

El proceso de solicitud, verificacion y emision de certificados se rige por el flujo de trabajo de la RA implementado en `src/identity/ra.rs`, y comprende las siguientes etapas:

### 6.1 Presentacion de la solicitud

a) El Suscriptor presenta una solicitud de certificado ante la RA, proporcionando la siguiente informacion minima:

   - Nombre legal completo (persona natural) o razon social (persona juridica).
   - RUT (Rol Unico Tributario).
   - Clave publica generada por el Suscriptor.
   - Perfil de certificado solicitado (NaturalPerson/esign, LegalPerson/eseal o WebAuthentication).
   - Nivel de firma requerido (FES, FEA o Sello).
   - Para FEA: evidencia biometrica conforme a la seccion 7.2.

b) La solicitud adquiere el estado `Pending` en el sistema de la RA.

### 6.2 Verificacion de identidad

a) Un oficial de la RA, identificado por su DID, realiza la verificacion de identidad conforme al articulo 15 de la Ley 19.799 y los procedimientos de la CPS seccion 3.2.

b) La verificacion incluye:

   - Validacion del RUT mediante el algoritmo modulo 11 (`validate_rut()`).
   - Verificacion del nombre legal contra documentos oficiales.
   - Para FEA: verificacion presencial o equivalente con validacion biometrica.
   - Para persona juridica: verificacion de existencia legal, vigencia y representacion.

c) El oficial de la RA registra su decision con su DID, marca temporal y disposicion.

### 6.3 Aprobacion o rechazo

a) Si la verificacion es exitosa, la solicitud transita al estado `Verified` y se procede a la emision del certificado mediante la funcion `approve_and_issue_cert()`.

b) Si la verificacion falla, la solicitud transita al estado `Rejected`, registrandose los motivos del rechazo. El Suscriptor sera notificado y podra presentar una nueva solicitud subsanando las observaciones.

### 6.4 Emision del certificado

a) El certificado es emitido por la CA Intermedia, firmado con su clave privada.

b) El certificado incluye las extensiones correspondientes al perfil solicitado, incluyendo:

   - `certificatePolicies` con el OID de la CP.
   - `keyUsage` conforme al perfil (digitalSignature, nonRepudiation, keyEncipherment segun corresponda).
   - `extendedKeyUsage` segun el tipo de certificado.
   - `subjectKeyIdentifier` y `authorityKeyIdentifier`.
   - `crlDistributionPoints` apuntando a `GET /api/v1/crl`.
   - `authorityInfoAccess` con la URL del servicio OCSP.

c) El Suscriptor recibe su DID en formato `did:goya:{clave_publica_hex[..16]}`.

### 6.5 Entrega del certificado

a) El certificado emitido es entregado al Suscriptor a traves de la API del PSC.

b) El Suscriptor debera verificar que el contenido del certificado es correcto y notificar cualquier error dentro de las cuarenta y ocho (48) horas siguientes a la emision.

---

## 7. Niveles de firma y requisitos

El PSC emite certificados para tres niveles de firma, cada uno correspondiente a un perfil de certificado (`CertProfileType`) definido en la CP:

### 7.1 Firma Electronica Simple (FES)

| Atributo | Valor |
|---|---|
| **Perfil** | NaturalPerson (esign) |
| **Algoritmo** | Ed25519 (FIPS 186-5) |
| **Tamano de firma** | 64 bytes |
| **QCType OID** | `0.4.0.1862.1.6.1` |
| **Key Usage** | digitalSignature, nonRepudiation |
| **Base legal** | Art. 2 letra f), Art. 3 Ley 19.799 |
| **Nivel de verificacion** | Verificacion de identidad basica por la RA |
| **Evidencia biometrica** | No requerida |
| **Efecto juridico** | Admisible en juicio, no goza de presuncion de autenticidad salvo acuerdo de partes |

**Requisitos del Suscriptor:**

a) Presentar RUT valido y documentacion de identidad.

b) Completar el proceso de verificacion de identidad ante la RA.

c) Generar su par de claves Ed25519.

### 7.2 Firma Electronica Avanzada (FEA)

| Atributo | Valor |
|---|---|
| **Perfil** | NaturalPerson (esign) con nivel FEA |
| **Algoritmo** | ML-DSA-65 (FIPS 204) |
| **Tamano de firma** | 3309 bytes |
| **QCType OID** | `0.4.0.1862.1.6.1` |
| **Key Usage** | digitalSignature, nonRepudiation |
| **Base legal** | Art. 2 letra g), Art. 5 Ley 19.799; Decreto 24/2019 |
| **Nivel de verificacion** | Verificacion presencial o equivalente con validacion biometrica |
| **Evidencia biometrica** | Requerida (compromiso SHA-256) |
| **Efecto juridico** | Equivalente a firma manuscrita, goza de presuncion de autenticidad (Art. 5 Ley 19.799) |

**Requisitos del Suscriptor:**

a) Cumplir todos los requisitos de FES.

b) Someterse a verificacion presencial o equivalente con validacion biometrica conforme al Decreto 24/2019.

c) Proporcionar evidencia biometrica. El PSC almacenara unicamente el hash SHA-256 de la evidencia; los datos biometricos en bruto no son retenidos.

d) Generar su par de claves ML-DSA-65.

e) Se recomienda el uso de un dispositivo criptografico certificado para el almacenamiento de la clave privada.

### 7.3 Sello Electronico (Seal)

| Atributo | Valor |
|---|---|
| **Perfil** | LegalPerson (eseal) |
| **Algoritmo** | Ed25519 o ML-DSA-65, segun configuracion |
| **QCType OID** | `0.4.0.1862.1.6.2` |
| **Key Usage** | digitalSignature, nonRepudiation |
| **Base legal** | Ley 19.799; Reglamento (UE) 910/2014 Art. 3 numeral 25 (cuando aplique) |
| **Nivel de verificacion** | Verificacion de existencia legal y representacion |
| **Evidencia biometrica** | No aplicable (persona juridica) |
| **Efecto juridico** | Garantiza origen e integridad de documentos institucionales |

**Requisitos del Suscriptor (persona juridica):**

a) Acreditar la existencia legal de la entidad (escritura de constitucion, inscripcion en el Registro de Comercio).

b) Acreditar la representacion legal del solicitante (poder notarial vigente o acuerdo de directorio).

c) Presentar RUT de la entidad.

d) Designar un custodio autorizado de la clave privada del sello.

---

## 8. Revocacion y suspension

### 8.1 Circunstancias para la revocacion

El PSC procedera a revocar el certificado del Suscriptor en cualquiera de los siguientes casos:

a) Solicitud del Suscriptor.

b) Compromiso conocido o sospechado de la clave privada del Suscriptor.

c) Inexactitud o falsedad en la informacion proporcionada durante la verificacion de identidad.

d) Incumplimiento de las obligaciones del presente acuerdo o de la CP/CPS.

e) Orden judicial o administrativa competente.

f) Cese de actividades del PSC.

g) Compromiso de las claves de la CA que afecte la validez del certificado.

h) Cambio en los datos contenidos en el certificado que lo hagan inexacto.

### 8.2 Legitimacion para solicitar la revocacion

Podran solicitar la revocacion:

a) El Suscriptor titular del certificado.

b) Un representante legalmente autorizado del Suscriptor.

c) El PSC, de oficio, en los casos contemplados en las letras b), c), d), f) y g) de la seccion 8.1.

d) La autoridad judicial o administrativa competente.

### 8.3 Procedimiento de revocacion

a) La solicitud de revocacion podra presentarse a traves de la API del PSC o directamente ante la RA.

b) El PSC verificara la identidad del solicitante antes de procesar la revocacion.

c) Una vez procesada, el certificado sera incluido en la siguiente CRL publicada en `GET /api/v1/crl` y `GET /api/v1/crl/pem`.

d) El estado del certificado sera actualizado en el servicio OCSP disponible en `GET /api/v1/ocsp/query` y `GET /api/v1/ocsp/query/der`.

e) La revocacion es irrevocable y tiene efecto desde el momento de su procesamiento por el PSC.

### 8.4 Suspension

a) El PSC podra suspender temporalmente un certificado cuando existan indicios razonables de compromiso de clave u otra circunstancia que justifique la suspension mientras se completa la investigacion.

b) El periodo maximo de suspension sera de setenta y dos (72) horas, transcurrido el cual el PSC debera revocar definitivamente el certificado o restituir su vigencia.

c) Durante la suspension, el certificado aparecera como revocado en las consultas CRL y OCSP.

d) El Suscriptor sera notificado de la suspension y de su resolucion.

### 8.5 Efectos de la revocacion

a) Un certificado revocado no podra ser utilizado para generar nuevas firmas electronicas.

b) Las firmas electronicas generadas con anterioridad a la revocacion mantienen su validez, siempre que puedan ser verificadas con un sello de tiempo emitido con anterioridad a la fecha de revocacion, obtenible a traves de `GET /api/v1/tsa/timestamp`.

c) El Suscriptor debera cesar inmediatamente el uso de la clave privada asociada al certificado revocado.

---

## 9. Limitacion de responsabilidad

### 9.1 Responsabilidad del PSC

a) La responsabilidad del PSC se limita al cumplimiento de las obligaciones expresamente establecidas en el presente acuerdo, la CP y la CPS.

b) El PSC sera responsable de los danos directos causados al Suscriptor derivados exclusivamente del incumplimiento de sus obligaciones, hasta el monto maximo establecido en las condiciones comerciales aplicables.

c) El PSC no sera responsable por:

   i. La perdida, compromiso o uso indebido de la clave privada del Suscriptor.

   ii. El uso del certificado para fines no autorizados o contrarios a la CP/CPS.

   iii. La confianza depositada por terceros en un certificado que ha sido debidamente revocado o cuya verificacion de estado no fue realizada.

   iv. Danos indirectos, lucro cesante, perdida de datos o danos consecuenciales.

   v. Eventos de fuerza mayor o caso fortuito conforme a la legislacion vigente.

   vi. Fallas en la infraestructura de telecomunicaciones, energia electrica u otros servicios de terceros que afecten la disponibilidad de los servicios del PSC.

### 9.2 Responsabilidad del Suscriptor

a) El Suscriptor sera responsable de todos los actos realizados con su certificado y clave privada, salvo que demuestre que solicito oportunamente la revocacion conforme a la seccion 8 del presente acuerdo.

b) El Suscriptor indemnizara al PSC por las reclamaciones de terceros derivadas del incumplimiento de las obligaciones establecidas en la seccion 5 del presente acuerdo, conforme a la seccion 9.9 de la CPS.

### 9.3 Exclusion de garantias

EN LA MAXIMA MEDIDA PERMITIDA POR LA LEGISLACION APLICABLE, EL PSC NO OTORGA GARANTIAS DISTINTAS A LAS EXPRESAMENTE ESTABLECIDAS EN EL PRESENTE ACUERDO, LA CP Y LA CPS, INCLUYENDO, SIN LIMITACION, GARANTIAS IMPLICITAS DE COMERCIABILIDAD O IDONEIDAD PARA UN PROPOSITO PARTICULAR.

---

## 10. Proteccion de datos personales y consentimiento

### 10.1 Responsable del tratamiento

El PSC actua como responsable del tratamiento de los datos personales del Suscriptor recopilados durante el proceso de verificacion de identidad y emision de certificados.

### 10.2 Datos recopilados

Los datos personales tratados incluyen:

a) Nombre legal completo.

b) RUT (Rol Unico Tributario).

c) Numero de cedula de identidad.

d) Informacion de contacto (correo electronico, telefono, domicilio).

e) Clave publica y DID derivado.

f) Compromiso criptografico (hash SHA-256) de evidencia biometrica, cuando corresponda.

g) Registros de la verificacion de identidad por la RA.

### 10.3 Finalidades del tratamiento

Los datos personales seran tratados exclusivamente para las siguientes finalidades:

a) Verificacion de identidad conforme a la Ley 19.799 y el Decreto 24/2019.

b) Emision, administracion, renovacion y revocacion de certificados digitales.

c) Inclusion de datos identificativos en los certificados emitidos (nombre, clave publica).

d) Mantenimiento de registros de auditoria conforme a los requisitos legales y regulatorios.

e) Cumplimiento de obligaciones legales y requerimientos de la autoridad competente.

### 10.4 Consentimiento

a) Mediante la firma del presente acuerdo, el Suscriptor otorga su consentimiento libre, expreso e informado para el tratamiento de sus datos personales conforme a las finalidades descritas en la seccion 10.3.

b) El Suscriptor consiente que su nombre y clave publica sean incluidos en certificados digitales de caracter publico.

c) El Suscriptor consiente que el estado de su certificado (vigente, revocado, suspendido) sea publicado a traves de los servicios CRL y OCSP.

### 10.5 Derechos del titular

a) El Suscriptor podra ejercer los derechos de acceso, rectificacion, cancelacion y oposicion (derechos ARCO) respecto de sus datos personales, conforme a la Ley 19.628.

b) El ejercicio del derecho de cancelacion de datos contenidos en un certificado vigente implicara la revocacion del certificado.

c) Las solicitudes de ejercicio de derechos deberan dirigirse al PSC a traves de los canales establecidos.

### 10.6 Conservacion y eliminacion

a) Los datos personales y registros de verificacion de identidad seran conservados por un periodo minimo de siete (7) anos conforme a la CP y los requisitos regulatorios aplicables.

b) Transcurrido el periodo de conservacion, los datos seran eliminados de forma segura conforme a los procedimientos del Plan de Seguridad del PSC.

### 10.7 Divulgacion a terceros

a) Los datos personales del Suscriptor no seran transferidos a terceros, salvo:

   i. Requerimiento mediante orden judicial o proceso administrativo valido conforme a la legislacion chilena.

   ii. Datos incluidos en los certificados publicados (nombre, clave publica), que son de caracter publico.

   iii. Informacion de estado del certificado publicada en CRL y OCSP.

---

## 11. Propiedad intelectual

### 11.1 Propiedad del software

El software de la PKI de Goya Ledger, incluyendo los modulos de la CA, la RA, los servicios de estado y la API, es propiedad intelectual del proyecto Goya Ledger.

### 11.2 Propiedad de los certificados

a) Los certificados digitales emitidos por el PSC son propiedad del PSC.

b) El Suscriptor tiene derecho a utilizar su certificado conforme a los terminos del presente acuerdo durante su periodo de vigencia.

### 11.3 Propiedad de las claves

a) La clave privada del Suscriptor es de su exclusiva propiedad y responsabilidad.

b) Las claves de la CA son propiedad exclusiva del PSC.

### 11.4 Espacio de OID

El espacio de nombres OID bajo el arco `1.3.6.1.4.1.99999` es asignado al proyecto Goya Ledger (PEN provisional, sujeto a registro formal ante IANA).

---

## 12. Duracion, renovacion y terminacion

### 12.1 Duracion del acuerdo

El presente acuerdo entra en vigencia a partir de la emision del primer certificado al Suscriptor y permanece vigente mientras exista al menos un certificado activo emitido a su favor.

### 12.2 Vigencia de los certificados

a) La vigencia maxima de los certificados de suscriptor es determinada por la CP y la CPS, conforme al perfil del certificado.

b) La vigencia del certificado no podra exceder la vigencia de la CA Intermedia que lo emitio.

### 12.3 Renovacion

a) El Suscriptor podra solicitar la renovacion de su certificado antes de su expiracion, cumpliendo nuevamente los requisitos de verificacion de identidad vigentes al momento de la renovacion.

b) El PSC se reserva el derecho de requerir verificacion de identidad completa para cada renovacion, o aplicar procedimientos simplificados segun lo permita la CP/CPS.

c) La renovacion no constituye prorroga automatica del certificado anterior; se emitira un nuevo certificado con nuevo numero de serie.

### 12.4 Terminacion del acuerdo

El presente acuerdo podra terminar por:

a) Revocacion o expiracion de todos los certificados emitidos al Suscriptor, sin que existan solicitudes de renovacion pendientes.

b) Mutuo acuerdo de las Partes.

c) Incumplimiento grave de las obligaciones del Suscriptor, previa notificacion con quince (15) dias de plazo para subsanar.

d) Cese de actividades del PSC, con noventa (90) dias de preaviso.

e) Decision unilateral del Suscriptor, lo que implicara la revocacion de todos sus certificados vigentes.

### 12.5 Efectos de la terminacion

a) Las obligaciones de confidencialidad (seccion 10), limitacion de responsabilidad (seccion 9) e indemnizacion (seccion 9.2) sobreviven a la terminacion del acuerdo.

b) Los registros de auditoria y verificacion de identidad seran conservados conforme a la seccion 10.6, con independencia de la terminacion.

c) Las firmas electronicas generadas durante la vigencia del certificado mantienen su validez legal conforme a la ley aplicable.

---

## 13. Resolucion de controversias

### 13.1 Negociacion directa

Toda controversia derivada de la interpretacion, cumplimiento o terminacion del presente acuerdo sera sometida, en primer lugar, a negociacion directa entre las Partes por un plazo de treinta (30) dias habiles contados desde la notificacion escrita de la controversia.

### 13.2 Mediacion

Si la negociacion directa no prospera, las Partes someteran la controversia a mediacion ante el Centro de Arbitraje y Mediacion de Santiago (CAM Santiago), conforme a su reglamento de mediacion vigente.

### 13.3 Jurisdiccion

Si la mediacion no resuelve la controversia, esta sera sometida al conocimiento de los tribunales ordinarios de justicia de la ciudad de Santiago, Republica de Chile, a cuya jurisdiccion las Partes se someten expresamente, renunciando a cualquier otro fuero o domicilio que pudiere corresponderles.

---

## 14. Ley aplicable

El presente acuerdo se rige por las leyes de la Republica de Chile, en particular:

a) **Ley 19.799** -- Sobre Documentos Electronicos, Firma Electronica y Servicios de Certificacion de dicha Firma (publicada el 12 de abril de 2002).

b) **Decreto Supremo 181/2002** -- Reglamento de la Ley 19.799 sobre Documentos Electronicos, Firma Electronica y la Certificacion de dicha Firma.

c) **Decreto Supremo 24/2019** -- Norma Tecnica para los Prestadores de Servicios de Certificacion de Firma Electronica Avanzada (del Ministerio de Economia, Fomento y Turismo).

d) **Ley 19.628** -- Sobre Proteccion de la Vida Privada (proteccion de datos personales).

e) **Codigo Civil** de la Republica de Chile, en lo no regulado por las leyes especiales anteriores.

Para Suscriptores domiciliados en la Union Europea, se aplica complementariamente:

f) **Reglamento (UE) 910/2014** (eIDAS) -- Relativo a la identificacion electronica y los servicios de confianza para las transacciones electronicas en el mercado interior.

El cumplimiento tecnico se rige adicionalmente por:

- ETSI EN 319 411-1 (Requisitos de politica y seguridad para PSC que emiten certificados -- Requisitos generales).
- ETSI EN 319 411-2 (Requisitos de politica y seguridad para PSC que emiten certificados cualificados).
- ETSI EN 319 412-5 (QCStatements).
- RFC 3647 (Marco CP/CPS).
- RFC 5280 (PKI X.509).
- RFC 6960 (OCSP).
- RFC 3161 (TSP).
- FIPS 186-5 (Firmas digitales).
- FIPS 204 (ML-DSA).

---

## 15. Disposiciones generales

### 15.1 Notificaciones

a) Las notificaciones entre las Partes se realizaran por escrito, a traves de los siguientes medios:

   i. Correo electronico a la direccion registrada durante el proceso de verificacion de identidad.

   ii. Notificacion a traves de la API o el sistema de notificaciones de Goya Ledger.

   iii. Correo certificado al domicilio registrado, cuando la naturaleza de la comunicacion lo requiera.

b) Las notificaciones surtiran efecto desde su recepcion por el destinatario, o en el caso de correo certificado, al tercer dia habil siguiente a su envio.

### 15.2 Cesion

a) El Suscriptor no podra ceder ni transferir los derechos u obligaciones derivados del presente acuerdo sin el consentimiento previo y por escrito del PSC.

b) El PSC podra ceder el presente acuerdo a un sucesor que asuma las mismas obligaciones, previa notificacion al Suscriptor con noventa (90) dias de anticipacion.

### 15.3 Divisibilidad

Si alguna clausula o disposicion del presente acuerdo fuere declarada nula, invalida o inaplicable por un tribunal competente, las demas clausulas y disposiciones continuaran en plena vigencia y efecto.

### 15.4 Acuerdo completo

El presente acuerdo, junto con la CP y la CPS incorporadas por referencia, constituye el acuerdo completo entre las Partes en relacion con su objeto, y reemplaza cualquier acuerdo, entendimiento o negociacion previa, verbal o escrita, entre las Partes respecto de la misma materia.

### 15.5 Modificaciones

El presente acuerdo podra ser modificado por el PSC, notificando al Suscriptor con al menos treinta (30) dias de anticipacion a la entrada en vigencia de las modificaciones. El uso continuado del certificado despues de la fecha de vigencia de las modificaciones constituira aceptacion de las mismas.

### 15.6 Renuncia

La omision o demora de cualquiera de las Partes en ejercer un derecho conferido por el presente acuerdo no constituira renuncia a dicho derecho ni impedira su ejercicio futuro.

### 15.7 Idioma

El presente acuerdo se otorga en idioma espanol. En caso de discrepancia con cualquier traduccion, prevalecera la version en espanol.

### 15.8 Ejemplares

El presente acuerdo podra suscribirse mediante firma electronica conforme a la Ley 19.799, lo que tendra la misma validez que su suscripcion en soporte de papel.

---

## Firma de las partes

En senal de conformidad, las Partes suscriben el presente acuerdo:

**Por el PSC Goya Ledger:**

| Campo | Valor |
|---|---|
| Nombre | _________________________ |
| Cargo | _________________________ |
| DID | `did:goya:________________` |
| Fecha | _________________________ |
| Firma | _________________________ |

**Por el Suscriptor:**

| Campo | Valor |
|---|---|
| Nombre / Razon social | _________________________ |
| RUT | _________________________ |
| DID | `did:goya:________________` |
| Fecha | _________________________ |
| Firma | _________________________ |

---

*Documento sujeto a la Politica de Certificados (CP) OID `1.3.6.1.4.1.99999.2.1` y la Declaracion de Practicas de Certificacion (CPS) OID `1.3.6.1.4.1.99999.2.2`, publicadas en `GET /api/v1/cp/document` y `GET /api/v1/cps/document`.*
