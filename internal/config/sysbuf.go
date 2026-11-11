package config

import (
	"os"
	"strconv"
	"strings"
)

// SmallUDPBuffers reports whether the kernel caps socket buffers low
// enough that a burst can overflow them, costing kcp, hop, faketcp and quic
// speed (quic-go warns about the same). `pol tune` raises the cap. False
// where it cannot tell (not Linux).
func SmallUDPBuffers() bool {
	b, err := os.ReadFile("/proc/sys/net/core/rmem_max")
	if err != nil {
		return false
	}
	n, err := strconv.Atoi(strings.TrimSpace(string(b)))
	return err == nil && n < 4<<20
}

// SmallBuffersHint is what pol says when SmallUDPBuffers.
const SmallBuffersHint = "UDP buffers are small on this machine: kcp, hop, faketcp and quic may lose speed under load - `pol tune` raises them"
