/-!
# FIPS 140-3 State Machine — Formal Verification

Proves safety invariants of the 4-state module state machine
in `pqc_crypto_module/src/approved_mode.rs`.
-/

inductive ModuleState where
  | Uninitialized
  | SelfTesting
  | Approved
  | Error
  deriving DecidableEq, Repr

open ModuleState

def validTransition : ModuleState → ModuleState → Bool
  | Uninitialized, SelfTesting => true
  | SelfTesting, Approved      => true
  | SelfTesting, Error         => true
  | _, _                       => false

def canExecuteCrypto : ModuleState → Bool
  | Approved => true
  | _        => false

theorem error_is_terminal :
    ∀ t : ModuleState, validTransition Error t = false := by
  intro t; cases t <;> rfl

theorem approved_is_absorbing :
    ∀ t : ModuleState, validTransition Approved t = false := by
  intro t; cases t <;> rfl

theorem approved_only_from_self_testing :
    ∀ s : ModuleState, validTransition s Approved = true → s = SelfTesting := by
  intro s h; cases s <;> simp_all [validTransition]

theorem crypto_requires_approved :
    ∀ s : ModuleState, canExecuteCrypto s = true → s = Approved := by
  intro s h; cases s <;> simp_all [canExecuteCrypto]

theorem error_blocks_crypto : canExecuteCrypto Error = false := by rfl

theorem no_direct_uninitialized_to_approved :
    validTransition Uninitialized Approved = false := by rfl

theorem uninitialized_deterministic :
    ∀ t : ModuleState, validTransition Uninitialized t = true → t = SelfTesting := by
  intro t h; cases t <;> simp_all [validTransition]

theorem self_testing_exactly_two_successors :
    ∀ t : ModuleState,
      validTransition SelfTesting t = true → (t = Approved ∨ t = Error) := by
  intro t h; cases t <;> simp_all [validTransition]

def reachable : ModuleState → ModuleState → Prop
  | s, t => validTransition s t = true
            ∨ ∃ mid, validTransition s mid = true ∧ validTransition mid t = true

theorem approved_reachable_from_uninitialized :
    reachable Uninitialized Approved := by
  right; exact ⟨SelfTesting, rfl, rfl⟩

theorem error_reachable_from_uninitialized :
    reachable Uninitialized Error := by
  right; exact ⟨SelfTesting, rfl, rfl⟩

theorem approved_not_reachable_from_error :
    ¬ reachable Error Approved := by
  intro h
  cases h with
  | inl h => simp [validTransition] at h
  | inr h =>
    obtain ⟨mid, h1, _⟩ := h
    cases mid <;> simp [validTransition] at h1
