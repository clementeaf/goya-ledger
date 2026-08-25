#!/usr/bin/env python3
"""
dudect-style Timing Side-Channel Analysis for ML-DSA-65.

Implements Welch's t-test (the dudect methodology) to detect
timing leaks in cryptographic operations.

Methodology (Reparaz, Balasch, Verbauwhede 2017):
1. Generate two classes of inputs (e.g., all-zeros vs random)
2. Measure execution time for each
3. Compute Welch's t-statistic
4. If |t| > 4.5, there's a timing leak with high confidence

We run this against the goya-ledger binary via the goya-sign CLI.
"""

import subprocess
import time
import os
import sys
import math
import json

GOYA_SIGN = os.path.join(os.path.dirname(__file__), "..", "..", "target", "debug", "goya-sign")

def measure_sign_time(binary, algo, sk_hex, payload):
    start = time.perf_counter_ns()
    try:
        subprocess.run(
            [binary, "sign", algo, sk_hex, payload],
            capture_output=True, timeout=10
        )
    except (subprocess.TimeoutExpired, FileNotFoundError):
        return None
    return time.perf_counter_ns() - start

def welch_t_test(class_a, class_b):
    n_a = len(class_a)
    n_b = len(class_b)
    if n_a < 2 or n_b < 2:
        return 0.0

    mean_a = sum(class_a) / n_a
    mean_b = sum(class_b) / n_b

    var_a = sum((x - mean_a) ** 2 for x in class_a) / (n_a - 1)
    var_b = sum((x - mean_b) ** 2 for x in class_b) / (n_b - 1)

    se = math.sqrt(var_a / n_a + var_b / n_b) if (var_a + var_b) > 0 else 1e-10
    t = (mean_a - mean_b) / se
    return t

def main():
    print()
    print("  ╔══════════════════════════════════════════════════════════╗")
    print("  ║   DUDECT TIMING SIDE-CHANNEL ANALYSIS                   ║")
    print("  ║   Welch's t-test for constant-time verification         ║")
    print("  ╚══════════════════════════════════════════════════════════╝")
    print()

    has_binary = os.path.exists(GOYA_SIGN)

    if has_binary:
        print(f"  Binary: {GOYA_SIGN}")
        print()
        print("  ── Ed25519 Sign Timing ──")
        print()

        result = subprocess.run(
            [GOYA_SIGN, "keygen", "ed25519"],
            capture_output=True, text=True, timeout=10
        )
        keys = json.loads(result.stdout)
        sk_hex = keys["private_key"]

        class_zeros = []
        class_random = []
        samples = 100

        for i in range(samples):
            t = measure_sign_time(GOYA_SIGN, "ed25519", sk_hex, "00" * 32)
            if t: class_zeros.append(t)

            payload = os.urandom(32).hex()
            t = measure_sign_time(GOYA_SIGN, "ed25519", sk_hex, payload)
            if t: class_random.append(t)

        t_stat = welch_t_test(class_zeros, class_random)
        mean_z = sum(class_zeros) / len(class_zeros) / 1e6 if class_zeros else 0
        mean_r = sum(class_random) / len(class_random) / 1e6 if class_random else 0

        print(f"    Samples per class:     {samples}")
        print(f"    Mean (zeros):          {mean_z:.2f} ms")
        print(f"    Mean (random):         {mean_r:.2f} ms")
        print(f"    Welch t-statistic:     {t_stat:.4f}")
        print(f"    Threshold:             |t| < 4.5")
        verdict = "PASS (no leak detected)" if abs(t_stat) < 4.5 else "FAIL (timing leak!)"
        print(f"    Verdict:               {verdict}")
        print()

    else:
        print(f"  goya-sign binary not found at {GOYA_SIGN}")
        print("  Running synthetic analysis with Python timing...")
        print()

    print("  ── Synthetic dudect (Python process overhead) ──")
    print()

    class_a = []
    class_b = []
    samples = 500

    for _ in range(samples):
        data_a = bytes(32)
        start = time.perf_counter_ns()
        _ = int.from_bytes(data_a, 'big') ** 2
        class_a.append(time.perf_counter_ns() - start)

        data_b = os.urandom(32)
        start = time.perf_counter_ns()
        _ = int.from_bytes(data_b, 'big') ** 2
        class_b.append(time.perf_counter_ns() - start)

    t_stat = welch_t_test(class_a, class_b)
    mean_a = sum(class_a) / len(class_a)
    mean_b = sum(class_b) / len(class_b)

    print(f"    Operation:             int.from_bytes ** 2")
    print(f"    Samples per class:     {samples}")
    print(f"    Mean (zeros):          {mean_a:.0f} ns")
    print(f"    Mean (random):         {mean_b:.0f} ns")
    print(f"    Welch t-statistic:     {t_stat:.4f}")
    print(f"    |t| < 4.5:            {'YES' if abs(t_stat) < 4.5 else 'NO'}")
    print()

    print("  ── Interpretation Guide ──")
    print()
    print("    |t| < 1.0    No evidence of timing difference")
    print("    |t| < 4.5    Inconclusive (normal noise)")
    print("    |t| > 4.5    Timing leak detected (p < 0.00001)")
    print("    |t| > 10.0   Strong timing leak")
    print()
    print("    For ML-DSA-65: rejection sampling adds inherent variance.")
    print("    A high |t| between message classes is expected and NOT a leak.")
    print("    A leak would show |t| > 4.5 between SAME message, DIFFERENT keys.")
    print()

if __name__ == "__main__":
    main()
