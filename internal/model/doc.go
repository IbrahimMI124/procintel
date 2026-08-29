// Package model is the contract layer every other package is written
// against.
//
// It holds values and nothing else: no I/O, no parsing, no policy. It
// imports no in-project package, and none of os, syscall or os/exec (AD-2) —
// only encoding/json's tags and time. Every field carries an explicit
// snake_case JSON tag; no key is left to Go's field-name default. Sizes and
// counts stay raw through every layer and are humanised only inside a
// renderer, and clock ticks stay in USER_HZ units until the diff layer.
//
// Three closed enums are fixed here and referenced everywhere:
// [Availability] for observation gaps (AD-4), and [Severity] and
// [Confidence] for findings (AD-11).
package model
