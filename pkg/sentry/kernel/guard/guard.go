package guard

import (
	//"fmt"
	"encoding/json"
	zmq "github.com/deepaksirone/goczmq"
	//"github.com/grpc/grpc-go"
	"gvisor.dev/gvisor/pkg/log"
	//"net"
	"os"
	"strconv"
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
	eventMap map[int64]int
	// State table
	stateTable map[string]int
	// IO whitelist
	ioWhitelist map[string]int
	// IP whitelist
	ipWhitelist map[string]int
	// URL whitelist
	urlWhitelist map[string]int
	// Policy table
	policyTable map[string]*ListNode
	// Controller IP
	ctrIP string
	// Controller Port
	ctrPort int64
	// Local Function Graph
	graph *ListNode
	// Current State
	curState *ListNode
}

type Policy struct {
	//NAME    string
	//EVENTID []map[string]float64
	URL  []string
	IP   []string
	IOR  float64
	IO   []string
	NETR float64
	//GLOBALGRAPH map[string][]map[string]interface{}
	GRAPH map[string]interface{}
}

type KernMsg struct {
	eventName [4]byte
	jsonData  []byte
}

func get_func_name() string {
	if os.Getenv("AWS_LAMBDA_FUNCTION_NAME") == "" {
		return "test0"
	}
	return os.Getenv("AWS_LAMBDA_FUNCTION_NAME")
}

func get_region_name() string {
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

func (g *Guard) get_event_id(event_hash int64) (int, bool) {
	id, present := g.eventMap[event_hash]
	return id, present
}

func New(ctrIP string, ctrPort int64) Guard {
	var g Guard
	g.startTime = get_time()
	g.requestNo = 0
	g.ioNo = 0
	g.runningTime = 0
	g.ctrIP = ctrIP
	g.ctrPort = ctrPort
	return g
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

/*
func KeyInitReq(s *zmq.Sock, guard_id []byte) {
	m := MsgInit(guard_id)
	s.SendFrame(m, zmq.FlagNone)
}

func SendToCtr(s *zmq.Sock, typ, action byte, data []byte) {
	m := MsgBasic(typ, action, data)
	s.SendFrame(m, zmq.FlagNone)
}
*/
func (g *Guard) PolicyInitHandler(msg []byte) {
	var f Policy
	err := json.Unmarshal(msg, &f)
	if err != nil {
		return
	}
	g.ior = int(f.IOR)
	g.netr = int(f.NETR)
	for i := 0; i < len(f.IO); i++ {
		g.ioWhitelist[f.IO[i]] = 1
	}

	for i := 0; i < len(f.IP); i++ {
		g.ipWhitelist[f.IP[i]] = 1
	}

	for i := 0; i < len(f.URL); i++ {
		g.urlWhitelist[f.URL[i]] = 1
	}

	func_name := f.GRAPH["NAME"].(string)
	eventid := f.GRAPH["EVENTID"].([]interface{})

	var eventid_map []map[string]int

	for _, v := range eventid {
		switch vv := v.(type) {
		case map[string]interface{}:
			m := make(map[string]int)
			for i, u := range vv {
				m[i] = int(u.(float64))
			}
			eventid_map = append(eventid_map, m)
		}
	}

	for _, m := range eventid_map {
		h := int64(m["h"])
		k := m["e"]
		g.eventMap[h] = k
	}

	g.graph = ListInit()
	var ns_map []map[string]int
	ns := f.GRAPH["ns"].([]interface{})
	for _, v := range ns {
		switch vv := v.(type) {
		case map[string]interface{}:
			m := make(map[string]int)
			for i, u := range vv {
				//fmt.Printf("%T %T\n", i, u)
				//fmt.Println(i, u)
				//f, _ := strconv.ParseInt(i, 10, 64)
				m[i] = int(u.(float64))
			}
			ns_map = append(ns_map, m)
		}
	}

	for _, m := range ns_map {
		var tnode Node
		tnode.id = int(m["id"])
		tnode.next_cnt = 0
		tnode.loop_cnt = int(m["cnt"])
		g.graph.Append(&tnode)
	}

	es := f.GRAPH["es"].([]interface{})
	for _, v := range es {
		switch vv := v.(type) {
		case map[string]interface{}:
			var dsts []int
			var src []int
			for i, u := range vv {
				if i == "1" {
					d := u.([]interface{})
					for _, v1 := range d {
						dsts = append(dsts, int(v1.(float64)))
					}
				} else {
					src = append(src, int(u.(float64)))
				}
			}
			p_ns := g.graph.GetElement(src[0] + 1)
			for _, d := range dsts {
				if d != -1 {
					p_nd := g.graph.GetPtr(d + 1)
					p_ns.successors[p_ns.next_cnt] = p_nd
					p_ns.next_cnt = p_ns.next_cnt + 1
				} else {
					p_ns.successors[p_ns.next_cnt] = g.graph
					p_ns.next_cnt = p_ns.next_cnt + 1
				}
			}

		}
	}
	g.policyTable[func_name] = g.graph
	g.curState = g.graph
}

func (g *Guard) PolicyInit() {
	p := g.graph.next
	for p != g.graph {
		nptr := p.data
		nptr.ctr = nptr.loop_cnt
		p = p.next
	}
	g.curState = g.graph
}

func (g *Guard) CheckPolicy(event_id int) bool {
	fname := get_func_name()
	_, present := g.policyTable[fname]
	if !present {
		return false
	}

	p := g.curState
	if g.graph == g.curState {
		g.PolicyInit()
		g.curState = g.curState.next
		p = g.curState
	}

	nptr := p.data
	if nptr.id == event_id {
		if nptr.ctr > 0 {
			nptr.ctr = nptr.ctr - 1
			return true
		}
		return false
	}

	for i := 0; i < nptr.next_cnt; i++ {
		next_ptr := nptr.successors[i]
		next_d_ptr := next_ptr.data

		if (next_d_ptr.ctr > 0) && (next_d_ptr.id == event_id) {
			next_d_ptr.ctr = next_d_ptr.ctr - 1
			g.curState = next_ptr
			return true
		}
	}
	return false
}

func (g *Guard) Run(ch chan KernMsg, ctr chan int) {
	// Connect to the controller
	id := get_func_name() + strconv.FormatInt(get_time(), 10)
	log.Infof("Started Guard with id: " + id)

	idOpt := zmq.SockSetIdentity(id)
	updater := zmq.NewDealerChanneler("tcp://127.0.0.1:5000", idOpt)

	/*
		if err != nil {
			log.Infof("[ZMQ] Error attaching to Controller")
		}*/
	/*
		e := updater.Connect("tcp://127.0.0.1:5000")
		if e != nil {
			log.Infof("Error connecting to Controller")
		}*/

	log.Infof("Started Guard with id: " + id)
	keyInitMsg := MsgInit([]byte(id))
	//log.Infof("Sending message: " + keyInitMsg)
	updater.SendChan <- [][]byte{keyInitMsg}

	/*
		if er != nil {
			log.Infof("[ZMQ] Error sending message to Controller")
		}*/
	/*
		_, ero := net.Dial("tcp", "127.0.0.1:7777")
		if ero != nil {
			log.Infof("Unable to connect to Controller")
			log.Infof(ero.Error())
		}
	*/
	/*
		conn, err := grpc.Dial("127.0.0.1:7777", grpc.WithInsecure(), grpc.WithBlock())
		if err != nil {
			log.Infof("[GRPC] Unable to connect to localhost")
		}
		defer conn.Close()
		c := pb.NewGreeterClient(conn)
	*/
	log.Infof("Send KeyInitReq to controller")
	for {
		// Receive signal from kernel
		// and break out of this loop
		select {
		case <-ch:
			log.Infof("[Guard] Received a message from the kernel")

		case <-ctr:
			log.Infof("[Guard] Exiting the go routine")
			break
		}

	}
}
