/-!
# BFT Consensus Safety — Formal Verification
Mirrors: `src/consensus/bft/quorum.rs`

The safety property: two quorums of size ≥ 2f+1 from n = 3f+1 validators
overlap by ≥ f+1, so at least one node in the intersection is honest.
-/

theorem quorum_overlap (f q1 q2 union inter : Nat)
    (hq1 : 2 * f + 1 ≤ q1) (hq2 : 2 * f + 1 ≤ q2)
    (_hq1n : q1 ≤ 3 * f + 1) (_hq2n : q2 ≤ 3 * f + 1)
    (h_union : union ≤ 3 * f + 1)
    (h_ie : inter + union = q1 + q2) :
    f + 1 ≤ inter := by omega

theorem honest_in_overlap (f inter faulty : Nat)
    (h_overlap : f + 1 ≤ inter)
    (h_faulty : faulty ≤ f) :
    faulty < inter := by omega

theorem no_fork (f q1 q2 union inter faulty : Nat)
    (hq1 : 2 * f + 1 ≤ q1) (hq2 : 2 * f + 1 ≤ q2)
    (hq1n : q1 ≤ 3 * f + 1) (hq2n : q2 ≤ 3 * f + 1)
    (h_union : union ≤ 3 * f + 1)
    (h_ie : inter + union = q1 + q2)
    (h_faulty : faulty ≤ f) :
    faulty < inter := by
  have := quorum_overlap f q1 q2 union inter hq1 hq2 hq1n hq2n h_union h_ie
  omega

theorem safety_four_nodes :
    ∀ q1 q2 union inter : Nat,
      3 ≤ q1 → 3 ≤ q2 → q1 ≤ 4 → q2 ≤ 4 →
      union ≤ 4 → inter + union = q1 + q2 →
      2 ≤ inter := by intros; omega

theorem safety_seven_nodes :
    ∀ q1 q2 union inter : Nat,
      5 ≤ q1 → 5 ≤ q2 → q1 ≤ 7 → q2 ≤ 7 →
      union ≤ 7 → inter + union = q1 + q2 →
      3 ≤ inter := by intros; omega
