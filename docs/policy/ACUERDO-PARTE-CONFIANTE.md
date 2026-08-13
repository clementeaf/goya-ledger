# Acuerdo de Parte Confiante

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
4. [Obligaciones de la Parte Confiante](#4-obligaciones-de-la-parte-confiante)
5. [Obligaciones del PSC](#5-obligaciones-del-psc)
6. [Niveles de confianza por tipo de certificado](#6-niveles-de-confianza-por-tipo-de-certificado)
7. [Limitacion de responsabilidad](#7-limitacion-de-responsabilidad)
8. [Exclusiones de garantia](#8-exclusiones-de-garantia)
9. [Verificacion de firma electronica](#9-verificacion-de-firma-electronica)
10. [Ley aplicable y jurisdiccion](#10-ley-aplicable-y-jurisdiccion)
11. [Disposiciones generales](#11-disposiciones-generales)

---

## 1. Partes

Comparecen en el presente acuerdo:

**A. El Prestador de Servicios de Certificacion (en adelante, "el PSC"):**

Goya Ledger, en su calidad de Prestador de Servicios de Certificacion de firma electronica, con domicilio en Santiago, Republica de Chile, que opera la Autoridad de Certificacion (CA) conforme a la Politica de Certificados (CP, OID `1.3.6.1.4.1.99999.2.1`) y la Declaracion de Practicas de Certificacion (CPS, OID `1.3.6.1.4.1.99999.2.2`) publicadas en `GET /api/v1/cp/document` y `GET /api/v1/cps/document`, respectivamente.

**B. La Parte Confiante (en adelante, "la Parte Confiante"):**

La persona natural o juridica que confie en los certificados digitales emitidos por el PSC para la verificacion de firmas electronicas, sellos electronicos o la autenticacion de entidades, segun los terminos del presente acuerdo.

Ambas partes, en adelante denominadas conjuntamente "las Partes", celebran el presente acuerdo conforme a los terminos y condiciones que se expresan a continuacion.

**Aceptacion del acuerdo.** La Parte Confiante acepta los terminos del presente acuerdo al momento de verificar un certificado emitido por el PSC, consultar los servicios de estado de certificados (CRL u OCSP) o utilizar de cualquier forma un certificado del PSC como base para tomar una decision de confianza.

---

## 2. Definiciones

Para los efectos del presente acuerdo, se entendera por:

**Autoridad de Certificacion (CA):** Entidad de confianza que emite, administra, revoca y renueva certificados digitales dentro de la infraestructura de clave publica (PKI) de Goya Ledger. La CA opera una jerarquia de dos niveles: CA Raiz (Common Name: "Rust-BC Internal CA", vigencia 10 anos) y CA Intermedia (Common Name: "Goya Ledger Intermediate CA", vigencia 5 anos, pathLenConstraint:0).

**Cadena de confianza:** Secuencia ordenada de certificados digitales que vincula un certificado de entidad final con la CA Raiz de confianza, pasando por la CA Intermedia. La validacion de la cadena completa es requisito previo para confiar en un certificado.

**Certificado digital:** Documento electronico firmado digitalmente por la CA que vincula una clave publica con la identidad de su titular, conforme al estandar X.509 v3.

**CP (Certificate Policy):** Politica de certificados del PSC, publicada bajo OID `1.3.6.1.4.1.99999.2.1` y accesible en `GET /api/v1/cp/document`.

**CPS (Certification Practice Statement):** Declaracion de practicas de certificacion del PSC, publicada bajo OID `1.3.6.1.4.1.99999.2.2` y accesible en `GET /api/v1/cps/document`.

**CRL (Certificate Revocation List):** Lista de certificados revocados publicada por la CA conforme a RFC 5280. Disponible en `GET /api/v1/crl` (formato DER) y `GET /api/v1/crl/pem` (formato PEM).

**Decision de confianza:** Acto mediante el cual la Parte Confiante decide aceptar o rechazar una firma electronica, sello electronico o conexion autenticada con base en la verificacion de un certificado emitido por el PSC.

**DID (Decentralized Identifier):** Identificador descentralizado del suscriptor del certificado, en formato `did:goya:{clave_publica_hex[..16]}`.

**FEA (Firma Electronica Avanzada):** Firma electronica avanzada conforme al articulo 2, letra g) de la Ley 19.799, que utiliza el algoritmo ML-DSA-65 (FIPS 204) con vinculacion biometrica, proporcionando no repudio y equivalencia legal a la firma manuscrita (articulo 5 Ley 19.799).

**FES (Firma Electronica Simple):** Firma electronica simple conforme al articulo 2, letra f) de la Ley 19.799, que utiliza el algoritmo Ed25519 (FIPS 186-5), proporcionando autenticacion e integridad.

**OCSP (Online Certificate Status Protocol):** Protocolo de consulta de estado de certificados en tiempo real, conforme a RFC 6960. Disponible en `GET /api/v1/ocsp/query` (formato JSON) y `GET /api/v1/ocsp/query/der` (formato DER).

**Parte Confiante (Relying Party):** Persona natural o juridica que confie en un certificado digital emitido por el PSC para verificar firmas electronicas, sellos electronicos o autenticacion, y que toma una decision de confianza con base en dicha verificacion.

**PSC (Prestador de Servicios de Certificacion):** Goya Ledger, en su calidad de entidad que presta servicios de certificacion de firma electronica conforme a la Ley 19.799.

**Sello de tiempo (Timestamp):** Declaracion firmada por la TSA que atestigua que un dato existia en un momento determinado, conforme a RFC 3161.

**Sello electronico:** Firma de persona juridica para la integridad de documentos institucionales.

**TSA (Time-Stamping Authority):** Autoridad de sellado de tiempo conforme a RFC 3161, disponible en `GET /api/v1/tsa/timestamp`, bajo la politica OID `1.3.6.1.4.1.99999.1.1`.

---

## 3. Objeto del acuerdo

El presente acuerdo tiene por objeto establecer los terminos y condiciones bajo los cuales la Parte Confiante podra confiar en los certificados digitales emitidos por el PSC para la verificacion de firmas electronicas, sellos electronicos y autenticacion de entidades.

El acuerdo regula:

a) Las obligaciones de la Parte Confiante al verificar certificados y firmas electronicas.

b) Las obligaciones del PSC en cuanto a la disponibilidad y confiabilidad de los servicios de verificacion.

c) Los niveles de confianza asociados a cada tipo de certificado y su efecto juridico.

d) Las limitaciones de responsabilidad del PSC y las exclusiones de garantia aplicables.

e) Los procedimientos de verificacion de firma electronica simple (FES) y firma electronica avanzada (FEA).

El presente acuerdo se complementa con la CP y la CPS vigentes, las cuales se entienden incorporadas por referencia. En caso de conflicto entre el presente acuerdo y la CP o la CPS, prevalecera el orden siguiente: (i) la CP, (ii) la CPS, (iii) el presente acuerdo.

---

## 4. Obligaciones de la Parte Confiante

La Parte Confiante se obliga a cumplir las siguientes obligaciones previo a depositar confianza en un certificado emitido por el PSC:

### 4.1 Verificacion del estado del certificado

a) Verificar el estado de revocacion del certificado antes de cada decision de confianza, consultando al menos uno de los siguientes servicios:

   i. **CRL:** Obtener la lista de certificados revocados vigente desde `GET /api/v1/crl` (formato DER) o `GET /api/v1/crl/pem` (formato PEM), y verificar que el numero de serie del certificado no figura en ella.

   ii. **OCSP:** Consultar el estado del certificado en tiempo real mediante `GET /api/v1/ocsp/query` (formato JSON) o `GET /api/v1/ocsp/query/der` (formato DER), conforme a RFC 6960.

b) No confiar en un certificado cuyo estado no haya podido ser verificado exitosamente. Si los servicios CRL y OCSP no estan disponibles, la Parte Confiante debera abstenerse de tomar una decision de confianza o asumir el riesgo de hacerlo.

c) Verificar que la CRL consultada se encuentre dentro de su periodo de vigencia (campo `nextUpdate`).

### 4.2 Verificacion de la cadena de confianza

a) Validar la cadena de certificados completa desde el certificado de entidad final hasta la CA Raiz de confianza ("Rust-BC Internal CA"), pasando por la CA Intermedia ("Goya Ledger Intermediate CA"), conforme a RFC 5280 seccion 6.

b) Verificar las firmas digitales de cada certificado en la cadena.

c) Verificar que cada certificado de la cadena se encuentre dentro de su periodo de vigencia (campos `notBefore` y `notAfter`).

d) Verificar las restricciones basicas (Basic Constraints) de los certificados de la CA, incluyendo el `pathLenConstraint`.

e) Verificar las extensiones criticas de cada certificado, incluyendo Key Usage y certificatePolicies.

### 4.3 Restricciones de uso del certificado

a) Respetar las restricciones de uso indicadas en las extensiones del certificado:

   i. **Key Usage** (OID 2.5.29.15): Verificar que el uso criptografico sea compatible con el proposito de la decision de confianza (digitalSignature, nonRepudiation, keyEncipherment, segun corresponda).

   ii. **Extended Key Usage** (OID 2.5.29.37): Verificar que la finalidad del uso este autorizada por esta extension.

   iii. **certificatePolicies** (OID 2.5.29.32): Verificar que el certificado incluya el OID de la CP `1.3.6.1.4.1.99999.2.1`.

b) Distinguir entre los perfiles de certificado (NaturalPerson/esign, LegalPerson/eseal, WebAuthentication) y confiar en cada certificado unicamente para los propositos correspondientes a su perfil.

c) No confiar en un certificado para un proposito que exceda las restricciones de uso establecidas en sus extensiones.

### 4.4 Prohibicion de confianza en certificados revocados o expirados

a) No confiar en certificados cuyo estado sea "revocado" segun la CRL u OCSP.

b) No confiar en certificados cuyo periodo de vigencia haya expirado.

c) No confiar en certificados cuya CA emisora haya sido revocada o cuya clave este comprometida, segun las notificaciones publicadas por el PSC.

### 4.5 Razonabilidad de la confianza

a) Evaluar la razonabilidad de la confianza depositada en un certificado en funcion de las circunstancias, incluyendo:

   i. El nivel de firma del certificado (FES, FEA o Sello) y su efecto juridico conforme a la seccion 6.

   ii. El valor o importancia de la transaccion o documento verificado.

   iii. La politica de certificados bajo la cual fue emitido el certificado.

b) Para transacciones de alto valor o importancia juridica, la Parte Confiante debera verificar que el certificado corresponda a un nivel de firma apropiado (preferentemente FEA para equivalencia a firma manuscrita).

---

## 5. Obligaciones del PSC

El PSC se obliga a cumplir las siguientes obligaciones frente a la Parte Confiante:

### 5.1 Disponibilidad de servicios de verificacion

a) Mantener los servicios de verificacion de estado de certificados operativos y accesibles a traves de los siguientes endpoints:

   | Servicio | Endpoint | Formato | Protocolo |
   |---|---|---|---|
   | CRL | `GET /api/v1/crl` | DER (application/pkix-crl) | RFC 5280 |
   | CRL | `GET /api/v1/crl/pem` | PEM | RFC 5280 |
   | OCSP | `GET /api/v1/ocsp/query` | JSON | RFC 6960 |
   | OCSP | `GET /api/v1/ocsp/query/der` | DER (application/ocsp-response) | RFC 6960 |
   | TSA | `GET /api/v1/tsa/timestamp` | RFC 3161 | RFC 3161 |

b) Publicar una nueva CRL dentro de una (1) hora desde cualquier evento de revocacion.

c) Los servicios CRL y OCSP se proporcionan sin costo para la Parte Confiante, conforme a la seccion 9.1.3 de la CPS.

### 5.2 Publicacion de CRL y OCSP

a) Publicar CRL conforme a RFC 5280, incluyendo los campos `thisUpdate` y `nextUpdate` para que la Parte Confiante pueda verificar la vigencia de la lista.

b) Las respuestas OCSP seran firmadas por la CA conforme a RFC 6960, y la Parte Confiante podra verificar su autenticidad mediante la cadena de confianza.

c) La CRL incluira todos los certificados revocados que no hayan expirado, con indicacion de la fecha y motivo de revocacion.

### 5.3 Publicacion de CP y CPS

a) Mantener publicada la version vigente de la CP en `GET /api/v1/cp/document`.

b) Mantener publicada la version vigente de la CPS en `GET /api/v1/cps/document`.

c) Notificar las modificaciones sustanciales a la CP o la CPS con al menos treinta (30) dias de anticipacion a su entrada en vigencia, conforme a la seccion 9.12 de la CPS.

d) Permitir a la Parte Confiante consultar la CP y la CPS para determinar el nivel de aseguramiento bajo el cual fue emitido un certificado.

### 5.4 Integridad de la cadena de confianza

a) Mantener la integridad de la jerarquia de dos niveles de la CA (CA Raiz y CA Intermedia).

b) Notificar a las Partes Confiantes en caso de compromiso de las claves de la CA, conforme al Plan de Contingencia del PSC.

c) Publicar los certificados de la CA Raiz y la CA Intermedia para que la Parte Confiante pueda construir y validar la cadena de confianza.

### 5.5 Sellado de tiempo

a) Mantener disponible el servicio de sellado de tiempo (TSA) en `GET /api/v1/tsa/timestamp` bajo la politica OID `1.3.6.1.4.1.99999.1.1`, conforme a RFC 3161.

b) Los sellos de tiempo permiten a la Parte Confiante determinar que una firma electronica existia en un momento determinado, lo cual es relevante para la verificacion de firmas en certificados revocados o expirados (Long-Term Validation).

---

## 6. Niveles de confianza por tipo de certificado

La Parte Confiante debera considerar los siguientes niveles de confianza al verificar certificados emitidos por el PSC:

### 6.1 Certificado de Firma Electronica Simple (FES)

| Atributo | Valor |
|---|---|
| **Perfil** | NaturalPerson (esign) |
| **Algoritmo de firma** | Ed25519 (FIPS 186-5) |
| **Tamano de firma** | 64 bytes |
| **QCType OID** | `0.4.0.1862.1.6.1` |
| **Key Usage** | digitalSignature, nonRepudiation |
| **Nivel de verificacion de identidad** | Verificacion basica por la RA |
| **Evidencia biometrica** | No |

**Efecto juridico (Art. 3 Ley 19.799):** La firma electronica simple es admisible como prueba en juicio y no puede ser excluida como evidencia por el solo hecho de ser electronica. Sin embargo, no goza de la presuncion de autenticidad del articulo 5; su valor probatorio queda sujeto a la apreciacion del tribunal conforme a las reglas generales.

**Nivel de confianza recomendado:** Adecuado para transacciones de valor moderado, comunicaciones comerciales, acuerdos informales y autenticacion de documentos internos. No recomendado como unico medio de verificacion para instrumentos publicos o documentos de alto valor juridico.

### 6.2 Certificado de Firma Electronica Avanzada (FEA)

| Atributo | Valor |
|---|---|
| **Perfil** | NaturalPerson (esign) con nivel FEA |
| **Algoritmo de firma** | ML-DSA-65 (FIPS 204) |
| **Tamano de firma** | 3309 bytes |
| **QCType OID** | `0.4.0.1862.1.6.1` |
| **Key Usage** | digitalSignature, nonRepudiation |
| **Nivel de verificacion de identidad** | Verificacion presencial o equivalente con validacion biometrica |
| **Evidencia biometrica** | Si (compromiso SHA-256) |

**Efecto juridico (Art. 5 Ley 19.799):** La firma electronica avanzada, producida por un certificado emitido por un PSC acreditado, tiene el mismo valor juridico que la firma manuscrita. Los documentos firmados con FEA gozan de una presuncion legal de autenticidad: se presume que provienen del titular del certificado y que no han sido alterados desde su firma, salvo prueba en contrario.

**Nivel de confianza recomendado:** Adecuado para transacciones de alto valor, contratos, instrumentos publicos electronicos, declaraciones juradas, y cualquier documento que requiera equivalencia a firma manuscrita o presuncion de autenticidad.

### 6.3 Certificado de Sello Electronico (Seal)

| Atributo | Valor |
|---|---|
| **Perfil** | LegalPerson (eseal) |
| **Algoritmo de firma** | Ed25519 o ML-DSA-65 |
| **QCType OID** | `0.4.0.1862.1.6.2` |
| **Key Usage** | digitalSignature, nonRepudiation |
| **Nivel de verificacion de identidad** | Verificacion de existencia legal y representacion de la persona juridica |
| **Evidencia biometrica** | No aplicable |

**Efecto juridico:** El sello electronico garantiza el origen e integridad de documentos emitidos por una persona juridica. Bajo el Reglamento (UE) 910/2014 (cuando aplique), el sello electronico cualificado goza de presuncion de integridad de los datos y correccion del origen.

**Nivel de confianza recomendado:** Adecuado para verificar la autenticidad e integridad de documentos institucionales, facturas electronicas, certificados automatizados y comunicaciones oficiales de personas juridicas.

### 6.4 Certificado de Autenticacion Web (WebAuthentication)

| Atributo | Valor |
|---|---|
| **Perfil** | WebAuthentication (QWAC) |
| **QCType OID** | `0.4.0.1862.1.6.3` |
| **Key Usage** | digitalSignature, keyEncipherment |
| **Uso** | Autenticacion TLS de nodos |

**Nivel de confianza recomendado:** Destinado a la autenticacion TLS entre nodos de la red Goya Ledger. La Parte Confiante (en este contexto, otro nodo de la red) debera verificar la cadena de confianza y las extensiones Subject Alternative Name para confirmar la identidad del par.

---

## 7. Limitacion de responsabilidad

### 7.1 Alcance de la responsabilidad del PSC

a) La responsabilidad del PSC frente a la Parte Confiante se limita al cumplimiento de las obligaciones expresamente establecidas en el presente acuerdo, la CP y la CPS.

b) El PSC sera responsable unicamente en caso de que la Parte Confiante demuestre:

   i. Que verifico el estado del certificado conforme a la seccion 4.1 del presente acuerdo.

   ii. Que verifico la cadena de confianza completa conforme a la seccion 4.2.

   iii. Que respeto las restricciones de uso del certificado conforme a la seccion 4.3.

   iv. Que el dano fue consecuencia directa de un incumplimiento imputable al PSC.

### 7.2 Supuestos de exclusion de responsabilidad

El PSC no sera responsable frente a la Parte Confiante por danos derivados de:

a) La omision de la Parte Confiante de verificar el estado del certificado antes de confiar en el.

b) La omision de la Parte Confiante de verificar la cadena de confianza completa.

c) La confianza depositada en un certificado revocado, suspendido o expirado.

d) La confianza depositada en un certificado para un proposito que exceda las restricciones de uso establecidas en sus extensiones.

e) La confianza desproporcionada o irrazonable en un certificado en atencion a las circunstancias de la transaccion y al nivel de firma del certificado.

f) El incumplimiento del suscriptor de sus obligaciones de proteccion de clave privada o veracidad de informacion.

g) La indisponibilidad transitoria de los servicios de verificacion por causas de fuerza mayor, caso fortuito o fallas en la infraestructura de terceros (telecomunicaciones, energia electrica).

h) Danos indirectos, lucro cesante, perdida de datos, perdida de oportunidad de negocio o danos consecuenciales.

### 7.3 Limite cuantitativo

a) En todo caso, la responsabilidad acumulada del PSC frente a la Parte Confiante no podra exceder el monto maximo establecido en las condiciones comerciales del PSC o, en su defecto, el monto que resulte de la aplicacion de la Ley 19.799 y sus reglamentos.

b) Las limitaciones de responsabilidad establecidas en el presente acuerdo no aplican en caso de dolo o negligencia grave del PSC.

---

## 8. Exclusiones de garantia

### 8.1 Exclusion general

EN LA MAXIMA MEDIDA PERMITIDA POR LA LEGISLACION APLICABLE, EL PSC NO OTORGA GARANTIAS DISTINTAS A LAS EXPRESAMENTE ESTABLECIDAS EN EL PRESENTE ACUERDO, LA CP Y LA CPS. SE EXCLUYEN EXPRESAMENTE, SIN LIMITACION, LAS GARANTIAS IMPLICITAS DE COMERCIABILIDAD, IDONEIDAD PARA UN PROPOSITO PARTICULAR, EXACTITUD O INTEGRIDAD DE LA INFORMACION CONTENIDA EN LOS CERTIFICADOS.

### 8.2 Exclusiones especificas

El PSC no garantiza:

a) Que la informacion contenida en un certificado sea exacta en todo momento posterior a su emision. La informacion es verificada por la RA al momento de la emision conforme a los procedimientos de la CPS.

b) La solvencia, probidad, capacidad contractual o cumplimiento de obligaciones del suscriptor del certificado.

c) La autenticidad, validez juridica o exigibilidad del contenido de un documento firmado electronicamente, mas alla de la verificacion criptografica de la firma.

d) Que los servicios de verificacion (CRL, OCSP, TSA) estaran disponibles de forma ininterrumpida. El PSC empleara esfuerzos comercialmente razonables para mantener la disponibilidad, pero no garantiza un nivel de servicio especifico salvo que se acuerde por separado.

e) La compatibilidad de los algoritmos criptograficos del PSC (Ed25519, ML-DSA-65) con todos los sistemas de la Parte Confiante.

### 8.3 Responsabilidad por verificacion

La Parte Confiante es la unica responsable de evaluar la razonabilidad de depositar confianza en un certificado y de las consecuencias de su decision de confianza. El PSC proporciona los medios tecnicos para la verificacion, pero la decision de confiar recae exclusivamente en la Parte Confiante.

---

## 9. Verificacion de firma electronica

La Parte Confiante debera observar los siguientes procedimientos al verificar firmas electronicas generadas con certificados emitidos por el PSC:

### 9.1 Verificacion de Firma Electronica Simple (FES) -- Art. 3 Ley 19.799

Para verificar una firma electronica simple (FES), la Parte Confiante debera:

a) **Obtener el certificado** del firmante y extraer la clave publica Ed25519.

b) **Verificar la cadena de confianza** del certificado conforme a la seccion 4.2 del presente acuerdo.

c) **Verificar el estado del certificado** consultando CRL (`GET /api/v1/crl` o `GET /api/v1/crl/pem`) u OCSP (`GET /api/v1/ocsp/query` o `GET /api/v1/ocsp/query/der`).

d) **Verificar la firma criptografica** Ed25519 sobre el documento o datos firmados, utilizando la clave publica contenida en el certificado.

e) **Verificar las restricciones de uso** del certificado (Key Usage: digitalSignature).

f) **Evaluar el efecto juridico** conforme al articulo 3 de la Ley 19.799: la firma electronica simple no es equivalente a la firma manuscrita, pero es admisible como prueba. Su valor probatorio queda sujeto a las reglas generales de apreciacion de la prueba.

g) **Opcionalmente, verificar el sello de tiempo** asociado mediante `GET /api/v1/tsa/timestamp` para establecer la existencia de la firma en un momento determinado.

### 9.2 Verificacion de Firma Electronica Avanzada (FEA) -- Art. 5 Ley 19.799

Para verificar una firma electronica avanzada (FEA), la Parte Confiante debera:

a) **Cumplir todos los pasos de verificacion de FES** descritos en la seccion 9.1, letras a) a e).

b) **Verificar la firma criptografica** ML-DSA-65 (FIPS 204) sobre el documento o datos firmados. La firma ML-DSA-65 tiene un tamano de 3309 bytes.

c) **Verificar que el certificado es de nivel FEA**, confirmando:

   i. Que el certificado fue emitido bajo un proceso de verificacion de identidad conforme al Decreto 24/2019.

   ii. Que el certificado incluye evidencia de vinculacion biometrica (compromiso SHA-256).

   iii. Que el PSC se encuentra acreditado conforme a la Ley 19.799, cuando corresponda.

d) **Evaluar el efecto juridico** conforme al articulo 5 de la Ley 19.799: la firma electronica avanzada producida por un PSC acreditado tiene el mismo valor que la firma manuscrita. Se presume que:

   i. La firma proviene del titular del certificado.

   ii. El documento no ha sido alterado desde su firma.

   Estas presunciones son legales y admiten prueba en contrario.

e) **Obtener un sello de tiempo** del servicio TSA (`GET /api/v1/tsa/timestamp`) para Long-Term Validation (LTV), especialmente cuando se requiera verificar la firma despues de la expiracion o revocacion del certificado.

### 9.3 Verificacion de Sello Electronico

Para verificar un sello electronico, la Parte Confiante debera:

a) Cumplir los pasos de verificacion descritos en la seccion 9.1, letras a) a e), adaptados al perfil LegalPerson (eseal).

b) Verificar que el certificado corresponde al perfil LegalPerson (QCType OID `0.4.0.1862.1.6.2`).

c) Verificar que el Key Usage incluye digitalSignature y nonRepudiation.

d) El sello electronico acredita el origen e integridad del documento respecto de la persona juridica titular del certificado.

### 9.4 Validacion a largo plazo (Long-Term Validation)

a) Para mantener la verificabilidad de una firma electronica mas alla de la vigencia del certificado, la Parte Confiante debera:

   i. Obtener un sello de tiempo RFC 3161 a traves de `GET /api/v1/tsa/timestamp` que cubra la firma y el certificado.

   ii. Conservar la CRL u OCSP response vigente al momento de la firma.

   iii. Conservar la cadena de certificados completa.

b) Con estos elementos, la Parte Confiante podra verificar que la firma era valida al momento de su creacion, aun cuando el certificado haya expirado o sido revocado con posterioridad.

---

## 10. Ley aplicable y jurisdiccion

### 10.1 Ley aplicable

El presente acuerdo se rige por las leyes de la Republica de Chile, en particular:

a) **Ley 19.799** -- Sobre Documentos Electronicos, Firma Electronica y Servicios de Certificacion de dicha Firma (publicada el 12 de abril de 2002).

b) **Decreto Supremo 181/2002** -- Reglamento de la Ley 19.799 sobre Documentos Electronicos, Firma Electronica y la Certificacion de dicha Firma.

c) **Decreto Supremo 24/2019** -- Norma Tecnica para los Prestadores de Servicios de Certificacion de Firma Electronica Avanzada (del Ministerio de Economia, Fomento y Turismo).

d) **Ley 19.628** -- Sobre Proteccion de la Vida Privada (proteccion de datos personales).

e) **Codigo Civil** de la Republica de Chile, en lo no regulado por las leyes especiales anteriores.

Para Partes Confiantes domiciliadas en la Union Europea, se aplica complementariamente:

f) **Reglamento (UE) 910/2014** (eIDAS) -- Relativo a la identificacion electronica y los servicios de confianza para las transacciones electronicas en el mercado interior.

El cumplimiento tecnico se rige adicionalmente por:

- ETSI EN 319 411-1 (Requisitos de politica y seguridad para PSC que emiten certificados -- Requisitos generales).
- ETSI EN 319 411-2 (Requisitos de politica y seguridad para PSC que emiten certificados cualificados).
- RFC 3647 (Marco CP/CPS).
- RFC 5280 (PKI X.509).
- RFC 6960 (OCSP).
- RFC 3161 (TSP).

### 10.2 Resolucion de controversias

#### 10.2.1 Negociacion directa

Toda controversia derivada de la interpretacion, cumplimiento o terminacion del presente acuerdo sera sometida, en primer lugar, a negociacion directa entre las Partes por un plazo de treinta (30) dias habiles contados desde la notificacion escrita de la controversia.

#### 10.2.2 Mediacion

Si la negociacion directa no prospera, las Partes someteran la controversia a mediacion ante el Centro de Arbitraje y Mediacion de Santiago (CAM Santiago), conforme a su reglamento de mediacion vigente.

#### 10.2.3 Jurisdiccion

Si la mediacion no resuelve la controversia, esta sera sometida al conocimiento de los tribunales ordinarios de justicia de la ciudad de Santiago, Republica de Chile, a cuya jurisdiccion las Partes se someten expresamente, renunciando a cualquier otro fuero o domicilio que pudiere corresponderles.

---

## 11. Disposiciones generales

### 11.1 Aceptacion

El presente acuerdo se entiende aceptado por la Parte Confiante al momento de:

a) Verificar un certificado emitido por el PSC.

b) Consultar los servicios CRL u OCSP del PSC.

c) Utilizar de cualquier forma un certificado del PSC como base para una decision de confianza.

No se requiere firma expresa de la Parte Confiante. La aceptacion por uso constituye consentimiento pleno a los terminos del presente acuerdo.

### 11.2 Relacion con la CP y la CPS

a) El presente acuerdo debe interpretarse de conformidad con la CP (OID `1.3.6.1.4.1.99999.2.1`) y la CPS (OID `1.3.6.1.4.1.99999.2.2`), disponibles en `GET /api/v1/cp/document` y `GET /api/v1/cps/document`.

b) La Parte Confiante se obliga a consultar la CP y la CPS para comprender el alcance de las garantias y las practicas del PSC aplicables a cada certificado.

c) En caso de conflicto entre el presente acuerdo y la CP o la CPS, prevalecera el orden establecido en la seccion 3.

### 11.3 Modificaciones

a) El PSC podra modificar el presente acuerdo publicando la version actualizada. Las modificaciones sustanciales se notificaran con al menos treinta (30) dias de anticipacion a su entrada en vigencia.

b) El uso continuado de los servicios de verificacion del PSC despues de la fecha de vigencia de las modificaciones constituira aceptacion de las mismas.

### 11.4 Cesion

a) La Parte Confiante no podra ceder ni transferir los derechos u obligaciones derivados del presente acuerdo sin el consentimiento previo y por escrito del PSC.

b) El PSC podra ceder el presente acuerdo a un sucesor que asuma las mismas obligaciones, previa publicacion con noventa (90) dias de anticipacion.

### 11.5 Divisibilidad

Si alguna clausula o disposicion del presente acuerdo fuere declarada nula, invalida o inaplicable por un tribunal competente, las demas clausulas y disposiciones continuaran en plena vigencia y efecto.

### 11.6 Acuerdo completo

El presente acuerdo, junto con la CP y la CPS incorporadas por referencia, constituye el acuerdo completo entre las Partes en relacion con los terminos de confianza en los certificados emitidos por el PSC.

### 11.7 Renuncia

La omision o demora de cualquiera de las Partes en ejercer un derecho conferido por el presente acuerdo no constituira renuncia a dicho derecho ni impedira su ejercicio futuro.

### 11.8 Idioma

El presente acuerdo se otorga en idioma espanol. En caso de discrepancia con cualquier traduccion, prevalecera la version en espanol.

### 11.9 Supervivencia

Las secciones 7 (Limitacion de responsabilidad), 8 (Exclusiones de garantia) y 10 (Ley aplicable y jurisdiccion) sobreviven a la terminacion del presente acuerdo.

---

*Documento sujeto a la Politica de Certificados (CP) OID `1.3.6.1.4.1.99999.2.1` y la Declaracion de Practicas de Certificacion (CPS) OID `1.3.6.1.4.1.99999.2.2`, publicadas en `GET /api/v1/cp/document` y `GET /api/v1/cps/document`.*
