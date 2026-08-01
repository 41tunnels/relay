package proto

// ErrorCode maps a proto error to the stable string used in test vectors'
// "expect_error" field. This indirection exists because Go error identity
// (via errors.Is) is not something Rust or TypeScript can share — vectors
// need a plain string every implementation agrees on.
func ErrorCode(err error) string {
	switch err {
	case ErrBadLength:
		return "bad_length"
	case ErrBadMAC:
		return "bad_mac"
	case ErrPairMismatch:
		return "pair_mismatch"
	case ErrRoleReflection:
		return "role_reflection"
	case ErrBadVersion:
		return "bad_version"
	case ErrBadPoint:
		return "bad_point"
	case ErrConfirmMismatch:
		return "confirm_mismatch"
	case ErrConfirmRole:
		return "confirm_role"
	case ErrCounterMismatch:
		return "counter_mismatch"
	case ErrCounterExhausted:
		return "counter_exhausted"
	case ErrAuthFailed:
		return "auth_failed"
	default:
		return "unknown"
	}
}
