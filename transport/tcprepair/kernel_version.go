package tcprepair

type linuxKernelVersion struct {
	major int
	minor int
}

func (v linuxKernelVersion) lessThan(major, minor int) bool {
	if v.major != major {
		return v.major < major
	}
	return v.minor < minor
}

func parseLinuxKernelRelease(release string) (linuxKernelVersion, bool) {
	major, rest, ok := parseLeadingUint(release)
	if !ok || rest == "" || rest[0] != '.' {
		return linuxKernelVersion{}, false
	}
	minor, _, ok := parseLeadingUint(rest[1:])
	if !ok {
		return linuxKernelVersion{}, false
	}
	return linuxKernelVersion{major: major, minor: minor}, true
}

func parseLeadingUint(s string) (int, string, bool) {
	if s == "" || s[0] < '0' || s[0] > '9' {
		return 0, s, false
	}
	n := 0
	i := 0
	for i < len(s) && s[i] >= '0' && s[i] <= '9' {
		n = n*10 + int(s[i]-'0')
		i++
	}
	return n, s[i:], true
}
