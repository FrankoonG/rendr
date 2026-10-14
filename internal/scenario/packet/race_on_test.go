//go:build race

package packet

// raceEnabled: see race_off_test.go.
const raceEnabled = true

// goldRateBA under the race detector: half the G3, G4 and G5 miniatures'
// 2 kpps, so that the race-unit pass stays within its 5-minute budget (m3
// R1-23's first lever: the race lane's work only). Every bound, window and
// ratio is unchanged: each is a time or a share of the offered rate. The
// non-race lane runs the full rate (race_off_test.go); the fseq jump rows
// run jumpRateBA in both lanes (their stimulus needs a window of datagrams
// in 1 s).
const goldRateBA = fullRateBA / 2
