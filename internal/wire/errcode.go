package wire

// DecodeErrorCode maps a wire package decode/encode error to the stable
// string used in test vectors' "expect_error" field — see the parallel
// proto.ErrorCode and the same rationale: a plain string is what Rust/
// TypeScript can compare against, Go error identity is not. (Named
// DecodeErrorCode, not ErrorCode, because ErrorCode is already the
// control-channel message type defined in control.go.)
func DecodeErrorCode(err error) string {
	switch err {
	case ErrFrameTooShort:
		return "frame_too_short"
	case ErrReservedFlagsSet:
		return "reserved_flags_set"
	case ErrConnIDNotV1:
		return "conn_id_not_v1"
	case ErrInnerFrameTooShort:
		return "inner_frame_too_short"
	case ErrInnerPayloadTooLong:
		return "inner_payload_too_long"
	case ErrInnerTruncated:
		return "inner_truncated"
	case ErrInnerReservedType:
		return "inner_reserved_type"
	default:
		return "unknown"
	}
}
