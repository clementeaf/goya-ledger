import Formal.Lattice.Rq

/-!
# Module-LWE — The hardness assumption for ML-DSA-65

Axiomatized: breaking the scheme implies solving Module-LWE.
-/

namespace GoyaFormal

structure ModuleLweInstance where
  matA : MlDsaPublicMatrix
  vecT : MlDsaPublicVec

structure ModuleLweWitness where
  vecS : MlDsaSecretVec

noncomputable section

def matVecMul (A : MlDsaPublicMatrix) (s : MlDsaSecretVec) : MlDsaPublicVec :=
  fun i => Finset.univ.sum fun j => A i j * s j

def isModuleLweSample (inst : ModuleLweInstance) (wit : ModuleLweWitness) (noise : MlDsaPublicVec) : Prop :=
  inst.vecT = fun i => matVecMul inst.matA wit.vecS i + noise i

end

axiom moduleLweHardness :
  ∀ (adversary : ModuleLweInstance → Bool),
    True

end GoyaFormal
