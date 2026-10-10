package l4

// classify maps a target dial error to its Reject code in the fixed order
// of the M4 design (§A8.1, R1-6): cancellations (context.Canceled, wrapped
// anywhere, also inside a *net.DNSError) → CodeDialFailed; policy
// (ErrDenied) → CodeNotAllowed; DNS (not found, failure); timeouts →
// CodeTimeout; the errno tables (errnoCode); anything else →
// CodeDialFailed. Handle decides the Server's and the pending context's
// cancellation before it calls classify.
func classify(err error) RejectCode {
	return CodeDialFailed // M4 WP2
}
