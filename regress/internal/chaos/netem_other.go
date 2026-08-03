//go:build !linux

package chaos

import "errors"

func ApplyChecked(p Profile) (Fixture, error) {
	if err := validateProfile(p); err != nil {
		return nil, err
	}
	if profileIsNoOp(p) {
		return noOpFixture{}, nil
	}
	return nil, errors.New("chaos.ApplyChecked: tc/netem is only supported on Linux")
}
