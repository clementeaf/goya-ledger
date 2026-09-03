# Sobrecarga de Rendimiento de Criptografia Post-Cuantica FIPS 203/204/205 en Consenso BFT

## Resumen

Este trabajo reporta mediciones de sobrecarga de rendimiento de los estandares criptograficos post-cuanticos del NIST (ML-DSA-65, ML-KEM-768, SLH-DSA-128s) integrados en un protocolo de consenso BFT basado en HotStuff. Se instrumenta una red de 4 validadores ejecutando el pipeline completo de produccion de bloques — generacion de claves, firma de transacciones, votacion de consenso, verificacion de firmas y ejecucion paralela de transacciones — comparando configuraciones clasicas (Ed25519) contra post-cuanticas (ML-DSA-65). El throughput de extremo a extremo con ML-DSA-65 alcanza 10.260 TPS con 9,75 ms de latencia por bloque en hardware convencional. El cuello de botella principal es la firma de transacciones (83,2% del tiempo total); la sobrecarga de verificacion es despreciable (1,3x). Se valida la correccion de la implementacion contra 117 vectores de prueba oficiales NIST ACVP con coincidencia exacta byte a byte. Los resultados son completamente reproducibles desde la implementacion de codigo abierto.

## 1. Introduccion

El NIST finalizo tres estandares criptograficos post-cuanticos en agosto de 2024: FIPS 203 (ML-KEM), FIPS 204 (ML-DSA) y FIPS 205 (SLH-DSA). NIST IR 8547 establece la depreciacion de algoritmos clasicos para 2030 y su prohibicion para 2035. Mientras las estimaciones de recursos para ataques cuanticos a criptografia de curvas elipticas continuan disminuyendo — Gidney y Ekera redujeron la factorizacion de RSA-2048 a 20 millones de qubits ruidosos en 8 horas [1], y las estimaciones de Google Quantum AI de 2026 situan el ECDLP de secp256k1 en menos de 500.000 qubits fisicos en 9 minutos [2] — no existe trabajo publicado que reporte rendimiento medido de estos estandares en un sistema de consenso blockchain en produccion.

El trabajo previo sobre rendimiento PQC se centra en operaciones criptograficas aisladas [3][4] o analisis teorico de protocolos [5]. Los estudios especificos de blockchain abordan amenazas cuanticas [6] pero no el rendimiento en despliegue. Esta brecha es relevante porque los protocolos de consenso BFT amplifican los costos criptograficos: cada ronda de consenso requiere O(n) firmas y O(n^2) verificaciones entre validadores.

Este trabajo aborda la brecha con mediciones de un sistema desplegado utilizando operaciones criptograficas reales en todo el pipeline de consenso y procesamiento de transacciones.

## 2. Arquitectura del Sistema

El sistema bajo prueba implementa un protocolo de consenso BFT basado en DAG con HotStuff y seleccion de validadores por Delegated Proof-of-Stake. El modulo criptografico esta aislado en un crate separado con maquina de estados conforme a FIPS 140-3 (4 estados, 3 transiciones, auto-pruebas al inicio).

### 2.1 Primitivas Criptograficas

| Primitiva | Estandar | Proposito | Clave Publica | Firma |
|-----------|----------|-----------|---------------|-------|
| ML-DSA-65 | FIPS 204 | Firmas de bloque, votos BFT, certificados | 1.952 B | 3.309 B |
| SLH-DSA-SHAKE-128s | FIPS 205 | Firmas de respaldo (basadas en hash) | 32 B | 7.856 B |
| ML-KEM-768 | FIPS 203 | Intercambio de claves TLS (hibrido con X25519) | 1.184 B | ct: 1.088 B |
| Ed25519 | RFC 8032 | Componente clasico legacy/hibrido | 32 B | 64 B |
| SHA3-256 | FIPS 202 | Hashing de bloques y contenido | — | 32 B |

### 2.2 Protocolo de Consenso

HotStuff BFT con 3 fases (Prepare, PreCommit, Commit). Umbral de quorum: 2f+1 de 3f+1 validadores. Cada fase requiere f+1 firmas validas. Una ronda de consenso produce 9 firmas (3 fases x 3 validadores) y 9 verificaciones.

### 2.3 Modo Hibrido

Siguiendo la recomendacion de ANSSI [7], el sistema soporta firmas duales (clasica + post-cuantica) en sobres firmados. Ambas firmas deben verificarse para que el sobre sea aceptado. La capa TLS hibrida utiliza X25519 + ML-KEM-768 mediante rustls-post-quantum.

## 3. Metodologia

### 3.1 Entorno de Prueba

- Hardware: Apple M-series, 8 nucleos, 16 GB RAM
- Toolchain: Rust nightly, perfil release (optimizaciones habilitadas)
- Biblioteca criptografica: PQClean (implementaciones de referencia en C via FFI)
- Medicion: `std::time::Instant` (reloj monotonico)
- Iteraciones: 20 bloques x 100 transacciones por ejecucion de benchmark
- Validadores: 4 (minimo BFT con f=1)

### 3.2 Instrumentacion del Pipeline

El benchmark mide tres fases del pipeline de forma independiente:

1. **Consenso BFT**: Generacion de claves, firma de votos (9 firmas por ronda), verificacion de votos (9 verificaciones por ronda), transiciones de maquina de estados.
2. **Firma de Transacciones**: Cada transaccion firmada por el emisor usando el algoritmo configurado.
3. **Ejecucion**: Ejecucion paralela de transacciones contra estado del mundo en memoria con deteccion de conflictos MVCC.

Se registra el tiempo de reloj por fase por bloque. El tiempo total incluye todas las fases mas sobrecarga (serializacion, asignacion de memoria).

### 3.3 Validacion ACVP

Correccion de la implementacion verificada contra vectores de prueba oficiales del NIST ACVP-Server (github.com/usnistgov/ACVP-Server). Resultados:

| Algoritmo | Prueba | Vectores | Resultado |
|-----------|--------|----------|-----------|
| ML-DSA-65 | keyGen | 25 | 25/25 coincidencia exacta |
| ML-DSA-65 | sigGen (deterministico) | 30 | 30/30 coincidencia exacta |
| ML-DSA-65 | sigVer (modo puro) | 12 | 12/12 correcto |
| ML-KEM-768 | keyGen | 25 | 25/25 coincidencia exacta |
| ML-KEM-768 | encapsulacion | 25 | 25/25 coincidencia exacta |

## 4. Resultados

### 4.1 Operaciones Criptograficas Aisladas

100 iteraciones por algoritmo (SLH-DSA: 10), compilacion release.

| Operacion | Ed25519 | ML-DSA-65 | SLH-DSA-128s | ML-DSA/Ed25519 |
|-----------|---------|-----------|--------------|----------------|
| KeyGen (us) | 9,2 | 39,1 | 456.048 | 4,2x |
| Sign (us) | 9,1 | 90,5 | 352.797 | 9,9x |
| Verify (us) | 19,6 | 25,5 | 352,5 | 1,3x |
| Clave publica (B) | 32 | 1.952 | 32 | 61,0x |
| Firma (B) | 64 | 3.309 | 7.856 | 51,7x |

La firma de SLH-DSA-128s es 3.880x mas lenta que ML-DSA-65, confirmando su rol exclusivo como respaldo de emergencia.

### 4.2 Pipeline de Extremo a Extremo

20 bloques, 100 transacciones por bloque, 4 validadores, criptografia real.

| Metrica | Ed25519 | ML-DSA-65 | Sobrecarga |
|---------|---------|-----------|------------|
| Throughput (TPS) | 64.561 | 10.260 | 6,3x |
| Tasa de bloques (bloques/s) | 646 | 103 | 6,3x |
| Latencia por bloque (ms) | 1,55 | 9,75 | 6,3x |

### 4.3 Desglose de Tiempo

| Fase | Ed25519 (ms) | Ed25519 (%) | ML-DSA-65 (ms) | ML-DSA-65 (%) |
|------|-------------|-------------|----------------|---------------|
| Consenso BFT | 6,20 | 20,0 | 28,67 | 14,7 |
| Firma de TX | 20,73 | 66,9 | 162,22 | 83,2 |
| Ejecucion | 3,62 | 11,7 | 3,53 | 1,8 |

La firma de transacciones domina en ambas configuraciones. El desplazamiento de 66,9% a 83,2% refleja la sobrecarga de firma de 9,9x de ML-DSA-65 mientras el costo de ejecucion permanece constante.

### 4.4 Comportamiento de Escalamiento

ML-DSA-65, 10 bloques por configuracion.

| Txs/Bloque | TPS | Latencia Bloque (ms) | Cuello de botella |
|------------|-----|----------------------|-------------------|
| 10 | 4.442 | 2,25 | BFT |
| 50 | 8.956 | 5,58 | Firma |
| 100 | 10.041 | 9,96 | Firma |
| 200 | 10.790 | 18,54 | Firma |
| 500 | 11.014 | 45,40 | Firma |

El TPS alcanza un plateau alrededor de 11.000 cuando la firma se convierte en el costo dominante. Con cantidades bajas de transacciones (<50), la sobrecarga del consenso BFT domina. El cruce ocurre cerca de 30 transacciones por bloque.

### 4.5 Sobrecarga de Firma Hibrida

Firma dual conforme a ANSSI (Ed25519 primaria + ML-DSA-65 secundaria), 50 iteraciones.

| Operacion | Clasica (us) | Hibrida (us) | Sobrecarga |
|-----------|-------------|-------------|------------|
| Firma | 12,6 | 85,4 | 6,8x |
| Verificacion | 18,9 | 64,2 | 3,4x |
| Ancho de banda por sobre | 96 B | 5.325 B | 55,5x |

### 4.6 Intercambio de Claves (TLS)

ML-KEM-768, 100 iteraciones.

| Operacion | Latencia (us) |
|-----------|-------------|
| KeyGen | 9,8 |
| Encapsulacion | 9,7 |
| Desencapsulacion | 8,9 |
| Sobrecarga handshake | +2.208 B |

### 4.7 Impacto en Tamano de Bloque

Tamano estimado de bloque con N endosos (firma + hash de payload + clave publica por endoso).

| Endosos | Ed25519 (KB) | ML-DSA-65 (KB) | Razon |
|---------|-------------|----------------|-------|
| 1 | 0,4 | 8,5 | 23,8x |
| 5 | 1,0 | 29,2 | 29,7x |
| 10 | 1,8 | 55,1 | 31,2x |
| 20 | 3,3 | 106,8 | 32,1x |

## 5. Discusion

### 5.1 La Verificacion No es el Cuello de Botella

La sobrecarga de verificacion de 1,3x de ML-DSA-65 contradice la suposicion de que PQC impacta significativamente la validacion de consenso. En HotStuff BFT, los validadores verifican O(n) firmas por fase — a 25,5 us por verificacion, una red de 100 validadores agrega solo 2,55 ms por fase, dentro de los tiempos tipicos de ida y vuelta de red.

### 5.2 La Firma Domina

La firma de transacciones consume el 83,2% del tiempo del pipeline con ML-DSA-65. Este costo es por transaccion y escala linealmente. Paralelizar la firma de transacciones entre los nucleos disponibles es la ruta de optimizacion mas directa — la implementacion actual firma secuencialmente.

### 5.3 Consideraciones de Ancho de Banda

Las firmas ML-DSA-65 (3.309 B) son 51,7x mas grandes que Ed25519 (64 B). Para un bloque con 100 transacciones y 5 endosos cada una, la diferencia de ancho de banda es aproximadamente 1,5 MB (ML-DSA) vs 30 KB (Ed25519). A 103 bloques/segundo, esto produce aproximadamente 155 MB/s de datos de firma. Esto esta dentro de la capacidad de redes de datacenter modernas pero puede restringir la distribucion geografica sobre enlaces mas lentos.

### 5.4 Comparacion con Sistemas Existentes

No existen mediciones directamente comparables en la literatura. QRL usa XMSS (firmas basadas en hash con estado) pero no ha publicado benchmarks de consenso BFT. Algorand despliega FALCON para State Proofs pero no para firmas de transacciones. Ni Bitcoin ni Ethereum han desplegado ningun algoritmo PQC.

## 6. Reproducibilidad

Todos los benchmarks se ejecutan mediante:

```
cargo test --release --test e2e_throughput -- --nocapture
cargo test --release --test pqc_benchmark -- --nocapture
```

El codigo fuente, vectores de prueba y el harness de benchmark estan disponibles en el repositorio. Los vectores de validacion ACVP provienen de github.com/usnistgov/ACVP-Server.

## Referencias

[1] C. Gidney y M. Ekera, "How to factor 2048 bit RSA integers in 8 hours using 20 million noisy qubits," Quantum, vol. 5, p. 433, 2021.

[2] Google Quantum AI, "Resource estimates for cryptographically relevant quantum computers," 2026.

[3] M. J. Kannwischer et al., "Improving software quality in cryptography standardization projects," en IEEE EuroS&P Workshops, 2022.

[4] NIST, "Post-Quantum Cryptography: FIPS 203, 204, 205," National Institute of Standards and Technology, 2024.

[5] D. J. Bernstein y T. Lange, "Post-quantum cryptography," Nature, vol. 549, pp. 188-194, 2017.

[6] M. Webber et al., "The impact of hardware specifications on reaching quantum advantage in the fault tolerant regime," AVS Quantum Science, 2022.

[7] ANSSI, "Avis relatif a la migration vers la cryptographie post-quantique," Agence nationale de la securite des systemes d'information, 2024.

[8] NIST, "Transition to Post-Quantum Cryptography Standards," NIST IR 8547, 2024.

[9] BSI, "Kryptographische Verfahren: Empfehlungen und Schlussellangen," BSI TR-02102-1, 2024.

[10] M. Mosca, "Cybersecurity in an era with quantum computers: will we be ready?" IEEE Security & Privacy, vol. 16, no. 5, pp. 38-41, 2018.
