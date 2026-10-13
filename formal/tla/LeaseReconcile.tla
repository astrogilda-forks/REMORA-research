--------------------------- MODULE LeaseReconcile ---------------------------
(***************************************************************************)
(* Reconciling one `unknown` operation in federation-port (the v1          *)
(* candidate for aeoess/federation-port#2, v1-candidates/reconciliation).  *)
(* Attempt 1 has been sent and its outcome is unknown. Requests can still  *)
(* be pending at the provider and settle later, including after the        *)
(* authorization deadline. A read-only lookup by idempotency key reports   *)
(* the effect or its absence. Time is abstract: Tick passes the            *)
(* authorization deadline, RetentionTick passes the declared idempotency    *)
(* retention window, and only after that may the provider Forget the key.  *)
(*                                                                         *)
(* Constants select the rule and the environment:                          *)
(*   AbsentRule      "naive": an authoritative absence closes the           *)
(*                   operation as failed. "final": it closes only with      *)
(*                   key-scoped finality (a provider cancellation: no       *)
(*                   request with the key can settle afterwards) and inside  *)
(*                   the retention window.                                  *)
(*   RetentionBound  TRUE: no effect-producing retry and no lookup once the *)
(*                   retention window has passed; the operation goes to an  *)
(*                   operator instead.                                      *)
(*   DurableBudget   TRUE: the lookup count and the reconciliation status    *)
(*                   survive a restart. FALSE: a restart resets them.       *)
(*   MisreportFinal  TRUE: a faulty provider calls a pending request final   *)
(*                   absence.                                               *)
(*   BoundedDelivery TRUE: assumption T3, a request reaches the provider     *)
(*                   before the retention window it was sent in has passed  *)
(*                   (the timeout and skew margin in the retry formula).     *)
(*                   FALSE: a request can arrive arbitrarily late.           *)
(*                                                                         *)
(* The provider deduplicates when a request ARRIVES: a request that arrives *)
(* while the provider remembers an earlier one with the key is a replay and *)
(* never produces a second effect. One that arrives after it has forgotten  *)
(* the key is new, and can.                                                *)
(*                                                                         *)
(* A model of the abstraction, written to find counterexamples. It is not   *)
(* a proof about the TypeScript candidate; the correspondence is tested by  *)
(* reconciliation.test.ts, not established here.                           *)
(***************************************************************************)
EXTENDS Naturals, FiniteSets, Sequences, TLC

CONSTANTS AbsentRule, RetentionBound, DurableBudget, MisreportFinal, BoundedDelivery, Budget, MaxAttempts

VARIABLES
    lastAction,      \* the step that produced this state (see the note below)
    state,           \* the operation's effect state: "unknown" | "provider_confirmed" | "failed"
    status,          \* reconciliation status: "pending" | "operator_required" | "resolved_confirmed" | "resolved_absent"
    sent,            \* requests dispatched so far
    inTransit,       \* requests sent that have not reached the provider
    queued,          \* requests the provider accepted as new and has not settled or dropped
    owned,           \* the provider holds a record for the key (cleared when it forgets)
    refunds,         \* effects the provider performed
    late,            \* the authorization deadline has passed
    retentionPassed, \* the declared retention window has passed
    forgotten,       \* the provider no longer remembers the key
    cancelled,       \* the provider cancelled the key: nothing with it can settle any more
    lookups,         \* lookups counted against the budget
    closedAbsent,    \* reconciliation closed the operation as absent
    contradicted,    \* a confirmation arrived for an operation closed as absent
    effectLate       \* an effect was performed after the deadline

vars == <<lastAction, state, status, sent, inTransit, queued, owned, refunds, late, retentionPassed, forgotten, cancelled,
          lookups, closedAbsent, contradicted, effectLate>>

Init ==
    /\ lastAction = "Init"
    /\ state = "unknown" /\ status = "pending"
    /\ sent = 1 /\ inTransit = {1} /\ queued = {} /\ owned = FALSE /\ refunds = 0
    /\ late = FALSE /\ retentionPassed = FALSE /\ forgotten = FALSE /\ cancelled = FALSE
    /\ lookups = 0 /\ closedAbsent = FALSE /\ contradicted = FALSE /\ effectLate = FALSE

\* An effect-producing retry with the same key. Never after the deadline (the v0 rule), and with
\* RetentionBound never once the provider may have forgotten the key.
Dispatch ==
    /\ lastAction' = "Dispatch"
    /\ state = "unknown" /\ sent < MaxAttempts /\ ~late /\ ~cancelled
    /\ (RetentionBound => ~retentionPassed)
    /\ sent' = sent + 1 /\ inTransit' = inTransit \cup {sent + 1}
    /\ UNCHANGED <<state, status, queued, owned, refunds, late, retentionPassed, forgotten, cancelled, lookups, closedAbsent, contradicted, effectLate>>

\* A request reaches the provider. A cancelled key refuses it; a remembered key makes it a replay.
Receive(r) ==
    /\ lastAction' = "Receive(" \o ToString(r) \o ")"
    /\ r \in inTransit /\ inTransit' = inTransit \ {r}
    /\ IF cancelled \/ owned
       THEN UNCHANGED <<queued, owned>>
       ELSE /\ queued' = queued \cup {r} /\ owned' = TRUE
    /\ UNCHANGED <<state, status, sent, refunds, late, retentionPassed, forgotten, cancelled, lookups, closedAbsent, contradicted, effectLate>>

\* An accepted request settles: the effect happens, possibly after the deadline.
Settle(r) ==
    /\ lastAction' = "Settle(" \o ToString(r) \o ")"
    /\ r \in queued /\ ~cancelled
    /\ queued' = queued \ {r}
    /\ refunds' = refunds + 1
    /\ effectLate' = (effectLate \/ late)
    /\ UNCHANGED <<state, status, sent, inTransit, owned, late, retentionPassed, forgotten, cancelled, lookups, closedAbsent, contradicted>>

\* A request is lost in transit, or the provider drops an accepted one without an effect.
Drop(r) ==
    /\ lastAction' = "Drop(" \o ToString(r) \o ")"
    /\ \/ r \in inTransit /\ inTransit' = inTransit \ {r} /\ UNCHANGED queued
       \/ r \in queued /\ queued' = queued \ {r} /\ UNCHANGED inTransit
    /\ UNCHANGED <<state, status, sent, owned, refunds, late, retentionPassed, forgotten, cancelled, lookups, closedAbsent, contradicted, effectLate>>

\* The provider cancels the key out of band: accepted requests are dropped, later ones refused.
Cancel ==
    /\ lastAction' = "Cancel"
    /\ ~cancelled /\ cancelled' = TRUE /\ queued' = {}
    /\ UNCHANGED <<state, status, sent, inTransit, owned, refunds, late, retentionPassed, forgotten, lookups, closedAbsent, contradicted, effectLate>>

\* An attempt's own response confirms the effect, possibly late. A confirmation always wins.
AttemptConfirms ==
    /\ lastAction' = "AttemptConfirms"
    /\ refunds > 0 /\ state # "provider_confirmed"
    /\ state' = "provider_confirmed"
    /\ contradicted' = (contradicted \/ closedAbsent)
    /\ UNCHANGED <<status, sent, inTransit, queued, owned, refunds, late, retentionPassed, forgotten, cancelled, lookups, closedAbsent, effectLate>>

ExhaustedStatus == IF lookups + 1 >= Budget /\ status = "pending" THEN "operator_required" ELSE status

\* A read-only lookup by key. It is made while the status is pending, or to recheck an absence
\* this reconciler closed; never once the budget is spent, and with RetentionBound never outside
\* the retention window.
Lookup ==
    /\ lastAction' = "Lookup"
    /\ status \in {"pending", "resolved_absent"} /\ lookups < Budget
    /\ (RetentionBound => ~retentionPassed)
    /\ lookups' = lookups + 1
    /\ \/ \* inconclusive: the provider is unavailable or the lookup times out
          /\ status' = ExhaustedStatus
          /\ UNCHANGED <<state, closedAbsent, contradicted>>
       \/ \* the provider reports the effect
          /\ refunds > 0 /\ ~forgotten
          /\ state' = "provider_confirmed" /\ status' = "resolved_confirmed"
          /\ contradicted' = (contradicted \/ closedAbsent)
          /\ UNCHANGED closedAbsent
       \/ \* the provider reports no effect for the key (which it also does once it has forgotten it)
          /\ refunds = 0 \/ forgotten
          /\ LET final  == cancelled \/ (MisreportFinal /\ (queued \cup inTransit) # {})
                 closes == IF AbsentRule = "naive" THEN TRUE ELSE final /\ ~retentionPassed
             IN IF closes /\ state = "unknown" /\ status = "pending"
                THEN /\ state' = "failed" /\ status' = "resolved_absent" /\ closedAbsent' = TRUE
                     /\ UNCHANGED contradicted
                ELSE /\ status' = ExhaustedStatus
                     /\ UNCHANGED <<state, closedAbsent, contradicted>>
    /\ UNCHANGED <<sent, inTransit, queued, owned, refunds, late, retentionPassed, forgotten, cancelled, effectLate>>

\* With RetentionBound, an operation past its window goes to an operator without a lookup.
RequireOperator ==
    /\ lastAction' = "RequireOperator"
    /\ RetentionBound /\ retentionPassed /\ status = "pending"
    /\ status' = "operator_required"
    /\ UNCHANGED <<state, sent, inTransit, queued, owned, refunds, late, retentionPassed, forgotten, cancelled, lookups, closedAbsent, contradicted, effectLate>>

Reconcile == Lookup \/ RequireOperator

\* A restart of the reconciling process.
Restart ==
    /\ lastAction' = "Restart"
    /\ ~DurableBudget /\ (lookups > 0 \/ status = "operator_required")
    /\ lookups' = 0
    /\ status' = IF status = "operator_required" THEN "pending" ELSE status
    /\ UNCHANGED <<state, sent, inTransit, queued, owned, refunds, late, retentionPassed, forgotten, cancelled, closedAbsent, contradicted, effectLate>>

Tick == ~late /\ late' = TRUE /\ lastAction' = "Tick"
        /\ UNCHANGED <<state, status, sent, inTransit, queued, owned, refunds, retentionPassed, forgotten, cancelled, lookups, closedAbsent, contradicted, effectLate>>
\* T3: with BoundedDelivery, the window a request was sent in does not pass while it is in transit.
RetentionTick == ~retentionPassed /\ (BoundedDelivery => inTransit = {}) /\ retentionPassed' = TRUE /\ lastAction' = "RetentionTick"
        /\ UNCHANGED <<state, status, sent, inTransit, queued, owned, refunds, late, forgotten, cancelled, lookups, closedAbsent, contradicted, effectLate>>
\* Past the window the provider may forget the key; a request arriving after that is new to it.
Forget == retentionPassed /\ ~forgotten /\ forgotten' = TRUE /\ owned' = FALSE /\ lastAction' = "Forget"
        /\ UNCHANGED <<state, status, sent, inTransit, queued, refunds, late, retentionPassed, cancelled, lookups, closedAbsent, contradicted, effectLate>>

\* lastAction names the step that produced each state, with its parameters. It changes no
\* behaviour; it makes the counterexample trace readable from the states themselves, so the
\* expected traces do not depend on how a TLC version prints actions.
Next ==
    \/ Dispatch \/ Cancel \/ AttemptConfirms \/ Reconcile \/ Restart
    \/ \E r \in 1..MaxAttempts : Receive(r) \/ Settle(r) \/ Drop(r)
    \/ Tick \/ RetentionTick \/ Forget

Spec == Init /\ [][Next]_vars

\* Scheduling assumption S1: an operation that can be reconciled is eventually reconciled (a caller
\* resubmits, or the runtime sweeps). Without it nothing forces progress.
FairSpec == Spec /\ WF_vars(Reconcile)

TypeOK ==
    /\ state \in {"unknown", "provider_confirmed", "failed"}
    /\ status \in {"pending", "operator_required", "resolved_confirmed", "resolved_absent"}
    /\ sent \in 1..MaxAttempts /\ inTransit \subseteq 1..MaxAttempts /\ queued \subseteq 1..MaxAttempts
    /\ owned \in BOOLEAN /\ refunds \in 0..MaxAttempts
    /\ lookups \in 0..Budget

\* Never failed while the effect exists: the closing rule's whole purpose.
NoFailedWithEffect == state = "failed" => refunds = 0
\* The provider performs the refund at most once.
AtMostOneEffect == refunds <= 1
\* A confirmation is never invented.
ConfirmedIsReal == state = "provider_confirmed" => refunds > 0
\* Once a contradiction is seen, the confirmation stands.
ContradictionResolvesToConfirmed == contradicted => state = "provider_confirmed"
\* The runtime prevents a dispatch after the deadline; it cannot prevent an earlier request from
\* settling after it. Stated so that the model shows the difference.
NoEffectAfterExpiry == ~effectLate

\* Every unknown operation ends confirmed, closed on accepted absence, or with an operator, and stays there.
EventuallySettled == <>[](state # "unknown" \/ status = "operator_required")
=============================================================================
