import Formal.Lattice.ModuleLWE

/-!
# ML-DSA-65 Scheme Definition (FIPS 204)

KeyGen, Sign, Verify as pure functions over R_q.
Parameters: k=6, l=5, n=256, q=8380417, η=4.
-/

namespace GoyaFormal

noncomputable section

open Polynomial

def eta : ℕ := 4

structure MlDsaPublicKey where
  seedRho : ByteArray
  vecT : MlDsaPublicVec

structure MlDsaSecretKey where
  seedRho : ByteArray
  seedK : ByteArray
  tr : ByteArray
  vecS1 : MlDsaSecretVec
  vecS2 : MlDsaPublicVec
  vecT : MlDsaPublicVec

structure MlDsaKeyPair where
  pk : MlDsaPublicKey
  sk : MlDsaSecretKey

structure MlDsaSignature where
  hint : Fin k_mldsa65 → Rq
  response : MlDsaSecretVec
  challenge : Rq

axiom expandA : ByteArray → MlDsaPublicMatrix

axiom sampleSecret : ByteArray → Nat → MlDsaSecretVec

axiom sampleNoise : ByteArray → Nat → MlDsaPublicVec

def keyGen (seed : ByteArray) (rho rhoPrime seedK : ByteArray) : MlDsaKeyPair :=
  let matA := expandA rho
  let s1 := sampleSecret rhoPrime 0
  let s2 := sampleNoise rhoPrime 1
  let t := fun i => matVecMul matA s1 i + s2 i
  let pk : MlDsaPublicKey := { seedRho := rho, vecT := t }
  let sk : MlDsaSecretKey := {
    seedRho := rho, seedK := seedK, tr := seed,
    vecS1 := s1, vecS2 := s2, vecT := t
  }
  { pk := pk, sk := sk }

theorem keygen_public_key_is_mlwe (seed rho rhoPrime seedK : ByteArray) :
    let kp := keyGen seed rho rhoPrime seedK
    let matA := expandA rho
    let s1 := sampleSecret rhoPrime 0
    let noise := sampleNoise rhoPrime 1
    isModuleLweSample
      { matA := matA, vecT := kp.pk.vecT }
      { vecS := s1 }
      noise := by
  simp [keyGen, isModuleLweSample, matVecMul]

end

end GoyaFormal
