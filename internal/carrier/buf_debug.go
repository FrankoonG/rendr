//go:build rendrdebug

package carrier

// bufDebug enables buffer misuse detection (design §4.1): a double Release
// or a Ref on a released Buf panics, a Budget released below zero panics,
// and a released Buf is poisoned (0xdb) so that a use after release shows
// up as corrupted data. Run tests with -tags rendrdebug to enable it.
const bufDebug = true
