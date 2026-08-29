// Package behavior lifts raw events and snapshot state into named behaviors.
//
// Events plus a snapshot become values such as sensitive-file-access,
// outbound-network or shell-spawn. This lifting is mandatory: rules read
// behaviors and snapshot state, never raw events, and no rule may skip this
// layer (AD-11). Classification is deterministic and local — no heuristic
// scoring, no model, no network (AD-9). Every behavior carries the
// epistemic status of the evidence it was derived from (AD-5).
//
// Populated in Block 5 of IMPLEMENTATION-SEQUENCE.md.
package behavior
