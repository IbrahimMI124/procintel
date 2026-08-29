// Package rules is the deterministic security rule engine.
//
// Every rule implements Evaluate(*model.Snapshot, []model.Behavior)
// []model.Finding and is registered in one ordered slice, so execution order
// — and therefore output — is stable (AD-6, AD-11). Every finding carries
// all five of rule_id, severity, evidence, reason and confidence, none
// optional and none empty. No rule fires on input whose availability is not
// observed, and a finding drawing on a degraded section is emitted at
// reduced confidence (AD-4). Finding language never asserts identity.
//
// Populated in Block 5 of IMPLEMENTATION-SEQUENCE.md.
package rules
