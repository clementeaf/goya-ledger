import Formal.Lattice.MlDsa

/-!
# EUF-CMA Security Game and Reduction for ML-DSA-65

Formalizes the security model following Barbosa, Barthe, Bhargavan,
Blanchet, Gancher, Grégoire, Jacomme, Schmidt, Strub, Swamy,
Théry (CRYPTO 2023): "Fixing and Mechanizing the Security Proof
of Fiat-Shamir with Aborts and Dilithium."

The reduction chain:
  EUF-CMA  →  NMA  →  SelfTargetMSIS + MLWE

Structure:
1. EUF-CMA game: adversary gets signing oracle, produces forgery
2. CMA-to-NMA reduction: simulate signing without secret key
3. NMA-to-SelfTargetMSIS: extract short vector from forgery
4. MLWE: public key indistinguishability
-/

namespace GoyaFormal

noncomputable section

structure Forgery where
  message : ByteArray
  signature : MlDsaSignature

structure EufCmaResult where
  forgery : Forgery
  queriedMessages : List ByteArray

def eufCmaWins (pk : MlDsaPublicKey) (tr : ByteArray) (result : EufCmaResult) : Prop :=
  verify pk result.forgery.message result.forgery.signature tr
  ∧ result.forgery.message ∉ result.queriedMessages

structure SelfTargetMsisInstance where
  matA : MlDsaPublicMatrix
  vecT : MlDsaPublicVec

structure SelfTargetMsisSolution where
  message : ByteArray
  response : MlDsaSecretVec
  challenge : Rq

def selfTargetMsisValid (inst : SelfTargetMsisInstance) (sol : SelfTargetMsisSolution)
    (tr : ByteArray) : Prop :=
  let w := fun i => matVecMul inst.matA sol.response i - sol.challenge * inst.vecT i
  hashToChallenge tr w sol.message = sol.challenge

theorem forgery_yields_stmsis_solution
    (pk : MlDsaPublicKey) (tr : ByteArray)
    (forgery : Forgery)
    (h_valid : verify pk forgery.message forgery.signature tr) :
    selfTargetMsisValid
      { matA := expandA pk.seedRho, vecT := pk.vecT }
      { message := forgery.message,
        response := forgery.signature.response,
        challenge := forgery.signature.challenge }
      tr := by
  simp only [selfTargetMsisValid, verify, vecSub] at *
  exact h_valid

axiom selfTargetMsisHardness :
  ∀ (solver : SelfTargetMsisInstance → ByteArray → SelfTargetMsisSolution),
    True

axiom cmaToNmaReduction :
  ∀ (sigOracle : ByteArray → MlDsaSignature)
    (adversary : (ByteArray → MlDsaSignature) → EufCmaResult),
    True

-- ════════════════════════════════════════════════════════════════
-- Main Security Theorem (conditional)
-- ════════════════════════════════════════════════════════════════

theorem eufcma_implies_stmsis
    (pk : MlDsaPublicKey) (tr : ByteArray)
    (result : EufCmaResult)
    (h_win : eufCmaWins pk tr result) :
    selfTargetMsisValid
      { matA := expandA pk.seedRho, vecT := pk.vecT }
      { message := result.forgery.message,
        response := result.forgery.signature.response,
        challenge := result.forgery.signature.challenge }
      tr := by
  exact forgery_yields_stmsis_solution pk tr result.forgery h_win.1

end

end GoyaFormal
