package main

import (
	"cmp"
	"fmt"
	"reflect"
	"slices"
	"sync/atomic"

	"github.com/FrankoonG/rendr/v2"
)

// carrierDeaths counts a Runtime's EventCarrierDown events by cause, the
// ends that are no death (local_close, retired) left out.
type carrierDeaths [16]atomic.Uint64

func (c *carrierDeaths) event(ev rendr.Event) {
	if ev.Kind == rendr.EventCarrierDown && ev.Cause != rendr.CauseLocalClose && ev.Cause != rendr.CauseRetired && int(ev.Cause) < len(c) {
		c[ev.Cause].Add(1)
	}
}

// statusLine is "<kind>:" and every non-zero field of the l4 status st by
// its name: numbers as Name=n, nested structs as Outer.Name=n, ByCode
// entries as ByCode(<code text>)=n, LastErr quoted; then the carrier
// deaths as CarrierDeaths(<cause>)=n.
func statusLine(kind string, st any, d *carrierDeaths) []byte {
	b := appendFields([]byte(kind+":"), "", reflect.ValueOf(st))
	for i := range d {
		if n := d[i].Load(); n != 0 {
			b = fmt.Appendf(b, " CarrierDeaths(%v)=%d", rendr.Cause(i), n)
		}
	}
	return b
}

func appendFields(b []byte, prefix string, v reflect.Value) []byte {
	for i := range v.NumField() {
		f, name := v.Field(i), prefix+v.Type().Field(i).Name
		switch {
		case f.Kind() == reflect.Struct:
			b = appendFields(b, name+".", f)
		case f.Kind() == reflect.Map:
			keys := f.MapKeys()
			slices.SortFunc(keys, func(x, y reflect.Value) int { return cmp.Compare(x.Uint(), y.Uint()) })
			for _, k := range keys {
				b = fmt.Appendf(b, " %s(%v)=%v", name, k, f.MapIndex(k))
			}
		case f.Kind() == reflect.Interface && !f.IsNil():
			b = fmt.Appendf(b, " %s=%q", name, fmt.Sprint(f.Interface()))
		case (f.CanInt() || f.CanUint()) && !f.IsZero():
			b = fmt.Appendf(b, " %s=%v", name, f)
		}
	}
	return b
}
