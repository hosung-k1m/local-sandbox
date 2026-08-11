// Package e2e holds a deterministic, host-only end-to-end test of the BoxedAi
// session pipeline. It drives session.Run's real broker, recorder, snapshot,
// verify and view code paths together — with a fake in-process guest that talks
// to the broker over HTTP instead of booting a Lima VM — so the full
// multi-producer recording, sealing and offline-verification flow is exercised
// without a hypervisor.
//
// It is a test-only package. This doc.go carries the package clause so the
// directory still builds when the _test.go files are excluded (e.g. under
// `go build ./...`); all behavior lives in e2e_test.go.
package e2e
