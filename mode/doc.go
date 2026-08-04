// Package mode defines the Scheduler contract between the rendr
// engine and a mode strategy (selector / bond / race).
//
// The engine owns the frame stream and the path set; the Scheduler
// is a pure function from (frame, available paths) → (paths to send
// on). Receive-side fan-in (dedupe for race, reorder for bond) is
// also Scheduler responsibility, but exposed through OnRecv.
//
// The Scheduler does NOT decide when to migrate due to quality; that
// is the engine's job, driven by Path quality measurements.
// Scheduler reacts to "which path is alive now"; engine reacts to
// "which path is best now".
package mode
