module irscan

go 1.27

// No require block, deliberately. irscan uses the Go standard library only, so the deployed
// binary has no third-party runtime dependency to license, hash or audit. See NOTICE and
// build/sources.lock.json (runtime_dependencies.go_modules is intentionally empty).
