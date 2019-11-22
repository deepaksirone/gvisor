package guard

import (
	//"fmt"
	//"encoding/json"
	zmq "github.com/deepaksirone/goczmq"
	"os"
	"strings"
	"syscall"
)

const (
	ioWhitelist  int = 0
	ipWhitelist  int = 1
	urlWhitelist int = 2
)

type Guard struct {
	id int
	// IO Rate
	ior int
	// Requests rate limit
	netr int
	// No. of request
	requestNo int
	// Number of IO
	ioNo int
	// Start time
	startTime int64
	// Running time
	runningTime uint
	// Event mapping table
	eventMap map[uint64]int
	// State table
	stateTable map[string]int
	// IO whitelist
	ioWhitelist map[string]int
	// IP whitelist
	ipWhitelist map[string]int
	// URL whitelist
	urlWhitelist map[string]int
	// Policy table
	policyTable map[string]int
	// Controller IP
	ctrIP string
	// Controller Port
	ctrPort uint
}

func (g *Guard) get_func_name() string {
	if os.Getenv("AWS_LAMBDA_FUNCTION_NAME") == "" {
		return "test0"
	}
	return os.Getenv("AWS_LAMBDA_FUNCTION_NAME")
}

func (g *Guard) get_region_name() string {
	if os.Getenv("AWS_REGION") == "" {
		return "AWS_EAST"
	}
	return os.Getenv("AWS_REGION")
}

func split_str(s, sep string) []string {
	return strings.Split(s, sep)
}

func strip(s string, c byte) string {
	var res string
	for i := 0; i < len(s); i++ {
		if s[i] != c {
			res += string(s[i])
		}
	}
	return res
}

func get_time() int64 {
	var r syscall.Timeval
	err := syscall.Gettimeofday(&r)
	if err != nil {
		return 0
	}
	return 1000000*r.Sec + int64(r.Usec)
}

func djb2hash(func_name, event, url, action string) uint64 {
	inp := func_name + event + url + action
	var hash uint64 = 5381
	for i := 0; i < len(inp); i++ {
		hash = ((hash << 5) + hash) + uint64(inp[i])
	}
	return hash
}

func (g *Guard) get_event_id(event_hash uint64) (int, bool) {
	id, present := g.eventMap[event_hash]
	return id, present
}

func (g *Guard) GuardInit() {
	g.startTime = get_time()
	g.requestNo = 0
	g.ioNo = 0
	g.runningTime = 0
}

func (g *Guard) Lookup(hash_id int, key string) bool {
	switch hash_id {
	case ioWhitelist:
		_, present := g.ioWhitelist[key]
		return present
	case ipWhitelist:
		_, present := g.ipWhitelist[key]
		return present
	case urlWhitelist:
		_, present := g.urlWhitelist[key]
		return present
	default:
		return false
	}
}

func KeyInitReq(guard_id []byte) {
	m := []byte("helloworld!")
	router, _ := zmq.NewRouter("tcp://*:5555")
	router.SendFrame(m, zmq.FlagNone)
}
