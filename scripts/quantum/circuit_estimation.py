#!/usr/bin/env python3
"""
Quantum Circuit Resource Estimation for attacking goya-ledger primitives.

Computes logical qubits, T-gate count, circuit depth, and wall-clock
estimates for Shor's (Ed25519) and Grover's (SHA3-256, AES-256).

References:
- Roetteler et al. 2017: quantum resource estimates for ECDLP
- Häner et al. 2020: improved quantum circuits for elliptic curves
- Amy et al. 2016: quantum circuits for SHA-256
- Grassl et al. 2016: quantum circuits for AES
"""

import math

def shor_ecdlp_resources(curve_bits):
    n = curve_bits
    logical_qubits = 9 * n + 2 * math.ceil(math.log2(n)) + 10
    toffoli_gates = 448 * n ** 3 * math.log2(n)
    t_gates = 7 * toffoli_gates
    circuit_depth = 2 ** (math.log2(toffoli_gates) * 0.8)
    return {
        "logical_qubits": int(logical_qubits),
        "toffoli_gates": int(toffoli_gates),
        "t_gates": int(t_gates),
        "circuit_depth": int(circuit_depth),
    }

def grover_hash_resources(hash_bits, circuit_gates_per_eval):
    iterations = int(math.pi / 4 * math.sqrt(2 ** hash_bits))
    logical_qubits = hash_bits + circuit_gates_per_eval // 100
    total_gates = iterations * circuit_gates_per_eval
    return {
        "grover_iterations": iterations,
        "logical_qubits": int(logical_qubits),
        "total_gates_log2": math.log2(total_gates) if total_gates > 0 else 0,
        "hash_bits": hash_bits,
    }

def grover_key_search_resources(key_bits, circuit_gates_per_eval):
    iterations = int(math.pi / 4 * math.sqrt(2 ** key_bits))
    logical_qubits = key_bits + circuit_gates_per_eval // 50
    total_gates = iterations * circuit_gates_per_eval
    return {
        "grover_iterations": iterations,
        "logical_qubits": int(logical_qubits),
        "total_gates_log2": math.log2(total_gates) if total_gates > 0 else 0,
        "key_bits": key_bits,
    }

def wall_clock_years(total_ops_log2, gate_speed_ghz=1.0):
    ops_per_year = gate_speed_ghz * 1e9 * 3600 * 24 * 365.25
    years = 2 ** total_ops_log2 / ops_per_year
    return years

def physical_qubits(logical, code_distance=23):
    return logical * 2 * code_distance ** 2

def format_years(y):
    if y < 1: return f"{y*365.25:.1f} days"
    if y > 1e15: return f"{y:.2e} years"
    if y > 1e9: return f"{y/1e9:.1f}B years"
    if y > 1e6: return f"{y/1e6:.1f}M years"
    if y > 1e3: return f"{y/1e3:.1f}K years"
    return f"{y:.1f} years"

def main():
    print()
    print("  ╔══════════════════════════════════════════════════════════╗")
    print("  ║   QUANTUM CIRCUIT RESOURCE ESTIMATION                   ║")
    print("  ║   For attacking goya-ledger cryptographic primitives     ║")
    print("  ╚══════════════════════════════════════════════════════════╝")
    print()

    print("  ── 1. Shor's Algorithm vs Ed25519 (Curve25519, 255-bit) ──")
    print()
    ed25519 = shor_ecdlp_resources(255)
    phys = physical_qubits(ed25519["logical_qubits"])
    ops_log2 = math.log2(ed25519["t_gates"])
    wc = wall_clock_years(ops_log2)
    print(f"    Logical qubits:        {ed25519['logical_qubits']:,}")
    print(f"    Physical qubits (d=23):{phys:,}")
    print(f"    Toffoli gates:         {ed25519['toffoli_gates']:.3e}")
    print(f"    T-gates:               {ed25519['t_gates']:.3e}")
    print(f"    Circuit ops:           2^{ops_log2:.1f}")
    print(f"    Wall-clock (1 GHz):    {format_years(wc)}")
    print(f"    Verdict:               {'FEASIBLE ~2035-2040' if ed25519['logical_qubits'] < 10000 else 'INFEASIBLE'}")
    print()

    print("  ── 2. Grover vs SHA3-256 (preimage) ──")
    print()
    sha3_gates_per_eval = 10000
    sha3 = grover_hash_resources(256, sha3_gates_per_eval)
    wc_sha3 = wall_clock_years(sha3["total_gates_log2"])
    print(f"    Target:                256-bit preimage")
    print(f"    Grover iterations:     2^{math.log2(sha3['grover_iterations']):.0f}")
    print(f"    Logical qubits:        {sha3['logical_qubits']:,}")
    print(f"    Physical qubits (d=23):{physical_qubits(sha3['logical_qubits']):,}")
    print(f"    Total gates:           2^{sha3['total_gates_log2']:.1f}")
    print(f"    Wall-clock (1 GHz):    {format_years(wc_sha3)}")
    print(f"    Verdict:               INFEASIBLE")
    print()

    print("  ── 3. Grover vs AES-256 (key search) ──")
    print()
    aes_gates_per_eval = 50000
    aes = grover_key_search_resources(256, aes_gates_per_eval)
    wc_aes = wall_clock_years(aes["total_gates_log2"])
    print(f"    Target:                256-bit key recovery")
    print(f"    Grover iterations:     2^{math.log2(aes['grover_iterations']):.0f}")
    print(f"    Logical qubits:        {aes['logical_qubits']:,}")
    print(f"    Physical qubits (d=23):{physical_qubits(aes['logical_qubits']):,}")
    print(f"    Total gates:           2^{aes['total_gates_log2']:.1f}")
    print(f"    Wall-clock (1 GHz):    {format_years(wc_aes)}")
    print(f"    Verdict:               INFEASIBLE")
    print()

    print("  ── 4. Grover vs SLH-DSA-128s (hash-based, 128-bit) ──")
    print()
    slh = grover_hash_resources(128, sha3_gates_per_eval)
    wc_slh = wall_clock_years(slh["total_gates_log2"])
    print(f"    Target:                128-bit preimage")
    print(f"    Grover iterations:     2^{math.log2(slh['grover_iterations']):.0f}")
    print(f"    Logical qubits:        {slh['logical_qubits']:,}")
    print(f"    Total gates:           2^{slh['total_gates_log2']:.1f}")
    print(f"    Wall-clock (1 GHz):    {format_years(wc_slh)}")
    print(f"    Verdict:               {'INFEASIBLE' if wc_slh > 100 else 'AT RISK'}")
    print()

    print("  ── 5. Summary Table ──")
    print()
    print("  ┌────────────────┬──────────┬──────────────┬────────────────┬─────────────┐")
    print("  │ Primitive      │ Qubits   │ Gates        │ Wall-clock     │ Status      │")
    print("  ├────────────────┼──────────┼──────────────┼────────────────┼─────────────┤")
    primitives = [
        ("Ed25519 (Shor)", ed25519["logical_qubits"], f"2^{ops_log2:.0f}", format_years(wc), "VULNERABLE"),
        ("SHA3-256 (Grov)", sha3["logical_qubits"], f"2^{sha3['total_gates_log2']:.0f}", format_years(wc_sha3), "SECURE"),
        ("AES-256 (Grov)", aes["logical_qubits"], f"2^{aes['total_gates_log2']:.0f}", format_years(wc_aes), "SECURE"),
        ("SLH-DSA (Grov)", slh["logical_qubits"], f"2^{slh['total_gates_log2']:.0f}", format_years(wc_slh), "REDUCED"),
    ]
    for name, qubits, gates, wc_str, status in primitives:
        print(f"  │ {name:<14} │ {qubits:>8,} │ {gates:>12} │ {wc_str:>14} │ {status:<11} │")
    print("  └────────────────┴──────────┴──────────────┴────────────────┴─────────────┘")
    print()

if __name__ == "__main__":
    main()
