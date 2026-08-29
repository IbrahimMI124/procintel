// Package correlate compounds individual findings into one assessment.
//
// Single signals are weak; combinations are strong. A weighted evidence
// model over []model.Finding produces exactly one model.Assessment (AD-11).
// The shape is fixed; the weights are tuning owned by this package. Output
// is inference and is tagged as such — it never appears in the same block as
// observed fact (AD-5).
//
// Populated in Block 5 of IMPLEMENTATION-SEQUENCE.md.
package correlate
