package collect

import (
	"crypto/sha256"
	"encoding/hex"
)

// sha256Hex is the single hashing primitive used across collectors, so every evidence hash
// in a report is computed the same way and is comparable between runs and between hosts.
func sha256Hex(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// SHA256Hex is the exported form for checks that need to hash an artifact they assembled
// themselves (for example a concatenation of registry values).
func SHA256Hex(b []byte) string { return sha256Hex(b) }
