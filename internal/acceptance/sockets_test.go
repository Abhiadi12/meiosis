package acceptance

import (
	"net"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"testing"
)

// connection is one TCP/UDP socket a process has open.
type connection struct {
	local, remote string // remote is empty for a listener
	state         string
}

// socketsOf lists the network sockets pid has open, using lsof. ok is false when
// lsof is not available, in which case the caller should say what it could not
// check rather than pass silently.
func socketsOf(t *testing.T, pid int) (conns []connection, ok bool) {
	t.Helper()
	if _, err := exec.LookPath("lsof"); err != nil {
		if os.Getenv("MEI_REQUIRE_SOCKET_CHECK") != "" {
			t.Fatal("lsof is required to inspect sockets (MEI_REQUIRE_SOCKET_CHECK is set) but is not installed")
		}
		return nil, false
	}
	// lsof exits 1 when the process has no network files, which is a valid answer.
	out, _ := exec.Command("lsof", "-nP", "-a", "-p", strconv.Itoa(pid), "-i").Output()
	for i, line := range strings.Split(string(out), "\n") {
		fields := strings.Fields(line)
		if i == 0 || len(fields) < 9 {
			continue
		}
		name := strings.Join(fields[8:], " ")
		state := ""
		if open := strings.Index(name, " ("); open >= 0 {
			state = strings.Trim(name[open+1:], "()")
			name = name[:open]
		}
		local, remote, _ := strings.Cut(name, "->")
		conns = append(conns, connection{local: local, remote: remote, state: state})
	}
	return conns, true
}

func hostOf(addr string) string {
	i := strings.LastIndex(addr, ":")
	if i < 0 {
		return addr
	}
	return strings.Trim(addr[:i], "[]")
}

func isLoopback(host string) bool {
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// nonLoopback returns a description of every socket in conns that is not purely
// loopback: a connection to another host, or a socket another host could reach.
func nonLoopback(conns []connection) []string {
	var bad []string
	for _, c := range conns {
		if c.remote != "" && !isLoopback(hostOf(c.remote)) {
			bad = append(bad, "connection to "+c.remote+" ("+c.state+")")
		}
		if !isLoopback(hostOf(c.local)) {
			bad = append(bad, "socket on "+c.local+" ("+c.state+")")
		}
	}
	return bad
}

// assertLoopbackOnly fails if pid has any socket that is not purely loopback:
// no connection to another host, and no listener reachable from one (NFR-4.5).
// It returns how many listeners it saw.
func assertLoopbackOnly(t *testing.T, what string, pid int) (listeners int) {
	t.Helper()
	conns, ok := socketsOf(t, pid)
	if !ok {
		t.Logf("%s: lsof is not available, so its sockets were not inspected", what)
		return 0
	}
	for _, problem := range nonLoopback(conns) {
		t.Errorf("%s has a %s: the default configuration makes no outbound connections and listens on loopback only", what, problem)
	}
	for _, c := range conns {
		if c.remote == "" && c.state == "LISTEN" {
			listeners++
		}
	}
	return listeners
}
