package guard

import (
	"encoding/gob"
	"encoding/json"
	"sync"
	"time"
	//"fmt"
	//zmq "github.com/deepaksirone/goczmq"
	//"runtime"
	//"github.com/grpc/grpc-go"
	//specs "github.com/opencontainers/runtime-spec/specs-go"
	//"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/log"
	//"gvisor.dev/gvisor/runsc/specutils"
	//"net/http"
	"os"
	//"strconv"
	"strings"
	"syscall"
)

const (
	ioWhitelist  int = 0
	ipWhitelist  int = 1
	urlWhitelist int = 2
)

var respTime time.Time
var msgID = int64(0)
var MapMutex = sync.RWMutex{}

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
	runningTime uint64
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
	// Seclambda exitied
	seclambda_exited bool
	// Function name
	funcName string
	// Encoder for sandbox to seclambda
	Encoder *gob.Encoder
	// Decore for seclamda to sandbox
	Decoder *gob.Decoder
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
	EventName [4]byte
	MetaData  []byte
	Data      []byte
	RecvChan  chan int
	FuncName  string
	IsFunc    bool
}

type transMsg struct {
	EventName [4]byte
	MetaData  []byte
	Data      []byte
	MsgID     int64
	IsExit    bool
	FuncName  string
	IsFunc    bool
}

type ReturnMsg struct {
	Allowed bool
	MsgID   int64
	Policy  []byte
}

func get_region_name() string {
	if os.Getenv("AWS_REGION") == "" {
		return "AWS_EAST"
	}
	return os.Getenv("AWS_REGION")
}

func get_inst_id() []byte {
	return []byte("instid0")
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

func Djb2hash(func_name, event, url, action string) uint64 {
	inp := func_name + event + url + action
	var hash uint64 = 5381
	for i := 0; i < len(inp); i++ {
		hash = ((hash << 5) + hash) + uint64(inp[i])
	}
	return hash
}

func (g *Guard) Get_event_id(event_hash int64) (int, bool) {
	id, present := g.eventMap[event_hash]
	return id, present
}

func get_time() int64 {
	var r syscall.Timeval
	err := syscall.Gettimeofday(&r)
	if err != nil {
		return 0
	}
	return 1000000*r.Sec + int64(r.Usec)
}

func New(ctrIP string, ctrPort int64, sandboxSide int, seclambdaSide int) Guard {
	var g Guard
	g.startTime = get_time()
	g.requestNo = 0
	g.ioNo = 0
	g.runningTime = 0
	g.ctrIP = ctrIP
	g.ctrPort = ctrPort
	g.eventMap = make(map[int64]int)
	g.ioWhitelist = make(map[string]int)
	g.ipWhitelist = make(map[string]int)
	g.urlWhitelist = make(map[string]int)
	g.stateTable = make(map[string]int)
	g.policyTable = make(map[string]*ListNode)

	sandboxFile := os.NewFile(uintptr(sandboxSide), "sandbox-file")
	g.Encoder = gob.NewEncoder(sandboxFile)

	seclambdaFile := os.NewFile(uintptr(seclambdaSide), "seclambda-file")
	g.Decoder = gob.NewDecoder(seclambdaFile)

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
}*/

func keyInitHandler(msg []byte) {
	return
}

/*
func SendToCtr(s *zmq.Channeler, typ, action byte, data []byte) {
	m := MsgBasic(typ, action, data)
	s.SendChan <- [][]byte{m}
}*/
/*
func (g *Guard) PolicyInitHandler(msg []byte) {
	var f Policy
	err := json.Unmarshal(msg, &f)
	if err != nil {
		log.Infof("[Guard] Error parsing json: %v", msg)
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
	log.Infof("[Guard] The eventid map : %v", eventid)
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
}*/
func (g *Guard) PolicyInitHandler(msg []byte) {
	var f Policy
	err := json.Unmarshal(msg, &f)
	if err != nil {
		//log.Println("[Guard] Error parsing json: %v", msg)
		return
	}

	g.ior = int(f.IOR)
	g.netr = int(f.NETR)

	//log.Println("[Seclambda] Here 1")
	for i := 0; i < len(f.IO); i++ {
		g.ioWhitelist[f.IO[i]] = 1
	}

	for i := 0; i < len(f.IP); i++ {
		g.ipWhitelist[f.IP[i]] = 1
	}

	for i := 0; i < len(f.URL); i++ {
		g.urlWhitelist[f.URL[i]] = 1
	}

	//log.Println("[Seclambda] Here 2")

	func_name := f.GRAPH["NAME"].(string)
	eventid := f.GRAPH["EVENTID"].([]interface{})
	//log.Infof("[Guard] The eventid map : %v", eventid)
	var eventid_map []map[string]int
	//log.Println("[Seclambda] Here 3")
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

	//log.Println("[Seclambda] Here 4")
	for _, m := range eventid_map {
		h := int64(m["h"])
		k := m["e"]
		g.eventMap[h] = k
	}
	//log.Println("[Seclambda] Here 5")
	g.graph = ListInit()
	var ns_map []map[string]int
	ns := f.GRAPH["NS"].([]interface{})
	//log.Println("[Seclambda] Here 5 1")
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
	//log.Println("[Seclambda] Here 6")
	for _, m := range ns_map {
		var tnode Node
		tnode.id = int(m["id"])
		tnode.next_cnt = 0
		tnode.loop_cnt = int(m["cnt"])
		g.graph.Append(&tnode)
	}
	//log.Println("[Seclambda] Here 7")
	es := f.GRAPH["ES"].([]interface{})
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
	//log.Println("[Seclambda] Here 7")
	g.policyTable[func_name] = g.graph
	g.curState = g.graph
	//log.Println("[Seclambda] Here 8")
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

func MakeTransMsg(msg KernMsg) transMsg {
	var m transMsg
	m.EventName = msg.EventName
	m.MetaData = msg.MetaData
	m.Data = msg.Data
	m.IsExit = false
	m.MsgID = msgID
	m.IsFunc = msg.IsFunc
	msgID += 1
	m.FuncName = msg.FuncName
	return m
}

func (g *Guard) Get_func_name() string {
	return g.funcName
}

func (g *Guard) CheckPolicy(event_id int) bool {
	fname := g.Get_func_name()
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

/*
func (g *Guard) SendKeyInitReq() (string, *zmq.Channeler) {
	id := get_func_name() + strconv.FormatInt(get_time(), 10)
	log.Infof("[Guard] SendKeyInitReq starting")
	idOpt := zmq.SockSetIdentity(id)
	updater := zmq.NewDealerChanneler("tcp://127.0.0.1:5000", idOpt)
	keyInitMsg := MsgInit([]byte(id))
	updater.SendChan <- [][]byte{keyInitMsg}
	<-updater.RecvChan

	return id, updater
}

func joinNetNS(nsPath string) (func()log.Printf, error) {
	runtime.LockOSThread()
	restoreNS, err := specutils.ApplyNS(specs.LinuxNamespace{
		Type: specs.NetworkNamespace,
		Path: nsPath,
	})
	if err != nil {
		runtime.UnlockOSThread()
		return nil, fmt.Errorf("joining net namespace %q: %v", nsPath, err)
	}
	return func() {
		restoreNS()
		runtime.UnlockOSThread()
	}, nil
}

func applyNS(nsFD int) (func(), error) {
	runtime.LockOSThread()
	log.Infof("Applying namespace network root curPid: %v", os.Getpid())
	newNS := os.NewFile(uintptr(nsFD), "root-ns")
	///*if err != nil {
	//	return nil, fmt.Errorf("error opening %q: %v", ns.Path, err)
	//
	defer newNS.Close()

	// Store current namespace to restore back.
	curPath := "/proc/self/ns/net"
	oldNS, err := os.Open(curPath)
	if err != nil {
		return nil, fmt.Errorf("error opening %q: %v", curPath, err)
	}

	// Set namespace to the one requested and setup function to restore it back.
	flag := nsCloneFlag(specs.NetworkNamespace)
	if err := setNS(newNS.Fd(), flag); err != nil {
		oldNS.Close()
		return nil, fmt.Errorf("error setting namespace of type %v and path %q: %v", "network", "root-netns", err)
	}
	return func() {
		log.Infof("Restoring namespace %v from path: %v to path: %v, pid: %v", "network", "root-netns", curPath, os.Getpid())
		defer oldNS.Close()
		if err := setNS(oldNS.Fd(), flag); err != nil {
			panic(fmt.Sprintf("error restoring namespace: of type %v: %v", "network", err))
		}
	}, nil
}

func nsCloneFlag(nst specs.LinuxNamespaceType) uintptr {
	switch nst {
	case specs.IPCNamespace:
		return unix.CLONE_NEWIPC
	case specs.MountNamespace:
		return unix.CLONE_NEWNS
	case specs.NetworkNamespace:
		return unix.CLONE_NEWNET
	case specs.PIDNamespace:
		return unix.CLONE_NEWPID
	case specs.UTSNamespace:
		return unix.CLONE_NEWUTS
	case specs.UserNamespace:
		return unix.CLONE_NEWUSER
	case specs.CgroupNamespace:
		return unix.CLONE_NEWCGROUP
	default:
		panic(fmt.Sprintf("unknown namespace %v", nst))
	}
}

func setNS(fd, nsType uintptr) error {
	if _, _, err := syscall.RawSyscall(unix.SYS_SETNS, fd, nsType, 0); err != 0 {
		return err
	}log.Printf
	return nil
}*/

func (g *Guard) receiveSeclambdaMsgs(seclambdaSide int, eventChanMap *map[int64]chan int, isRunning *bool, rcvMsgCtr chan int) {

	//seclambdaFile := os.NewFile(uintptr(seclambdaSide), "seclambda-file")
	//decoder := gob.NewDecoder(seclambdaFile)
	for {
		// Non-blocking receive
		/*select {
		case <-rcvMsgCtr:
			//rcvMsgCtr <- 1sandboxSide int
			//*isRunning = false
			log.Println("[Guard] receiveSeclambdaMsgs exiting by control channel")
			rcvMsgCtr <- 1
			return
		default:

		}*/
		var recv ReturnMsg
		isExit := false
		//s := time.Now()
		//seclambdaFile.SetDeadline(time.Now().Add(1 * time.Microsecond))
		err := g.Decoder.Decode(&recv)

		/*if os.IsTimeout(err) {
			//log.Printf("[Guard] Decode timeout %v", err)
			continue
		}*/
		//s1 := time.Now()
		//log.Printf("[receiveSeclambdaMsgs] Wallclock time after decoding message with ID: %v : %v", recv.MsgID, s1.UnixNano())
		//log.Printf("[receiveSeclambdaMsgs] Time to decode a received message: %v", time.Since(s))
		//start := time.Now()
		if err != nil {
			// Other end closed the file
			//log.Printf("[Guard] Error decoding message")
			//	log.Println("[Guard] Killing receiveSeclambdaMsgs")
			//var end ReturnMsg
			isExit = true

			//replyChan <- end
			//return
		}

		log.Infof("[Guard] Got response for MsgID: %v", recv.MsgID)

		if len(recv.Policy) > 0 {
			g.PolicyInitHandler(recv.Policy)
			log.Infof("[Guard] Initializing Policy")
		}

		//replyChan <- q
		if isExit {
			g.seclambda_exited = true
			MapMutex.RLock()
			for _, v := range *eventChanMap {
				v <- 0
				//delete(eventChanMap, k)
			}
			MapMutex.RUnlock()
			MapMutex.Lock()
			*eventChanMap = make(map[int64]chan int)
			MapMutex.Unlock()

			//log.Println("[Guard] Seclambda proxy exited; replying false to all new reqs")
			//*isRunning = false
			//return
		}

		//log.Infof("[Guard] Got response for MsgID: %v", recv.MsgID)
		if !g.seclambda_exited {
			MapMutex.RLock()
			if recv.Allowed {
				//s := time.Now()
				//log.Printf("[receiveSeclambdaMsgs] Timestamp just before delivering response to caller: %v", s.UnixNano())
				log.Infof("[Guard] Sending allowed reply back: %v", recv.MsgID)
				(*eventChanMap)[recv.MsgID] <- 1
				//elapsed1 := time.Since(start)
				//log.Printf("[receiveSeclambdaMsgs] Time spent sending response back: %v", elapsed1)

			} else {
				//s := time.Now()
				respTime = time.Now()
				//log.Printf("[receiveSeclambdaMsgs] Timestamp just before delivering response to caller: %v", s.UnixNano())
				log.Infof("[Guard] Sending denied reply back: %v", recv.MsgID)
				(*eventChanMap)[recv.MsgID] <- 0
				//elapsed1 := time.Since(start)
				//log.Printf("[receiveSeclambdaMsgs] Time spent sending response back: %v", elapsed1)
			}
			MapMutex.RUnlock()

			MapMutex.Lock()
			delete(*eventChanMap, recv.MsgID)
			MapMutex.Unlock()

			//log.Printf("[Guard] Getting reply from seclambdaSide: %v", recv)
		} else {
			MapMutex.RLock()
			ch, pr := (*eventChanMap)[recv.MsgID]
			MapMutex.RUnlock()
			if pr {
				ch <- 0
			}
		}
	}
}

func (g *Guard) sendSeclambdaMsgs(sandboxSide int, ch chan KernMsg, sendMsgCtr chan int, eventChanMap *map[int64]chan int) {

	//sandboxFile := os.NewFile(uintptr(sandboxSide), "sandbox-file")
	//encoder := gob.NewEncoder(sandboxFile)
	for {
		select {
		case msg := <-ch:
			log.Infof("[Guard] Received a message from the kernel")
			log.Infof("[Guard] The message struct : %v", msg)
			//g.requestNo += 1

			s3 := time.Now()
			//log.Printf("[sendSeclambdaMsgs] Wallclock time before processing message with ID: %v : %v", msgID, s3.UnixNano())
			//log.Println("[Guard] Received a message from the kernel")
			//log.Printf("[Guard] The message struct : %v\n", msg)
			//g.requestNo += 1

			if g.seclambda_exited {
				msg.RecvChan <- 0
				log.Infof("[Guard] Proxy Exited: Sending all false")
				continue
			}

			trans := MakeTransMsg(msg)
			if msg.IsFunc || string(msg.EventName[:]) == "GETE" {
				log.Infof("[Guard] The trans message struct : %v", trans)
				MapMutex.Lock()
				(*eventChanMap)[trans.MsgID] = msg.RecvChan
				MapMutex.Unlock()
				if g.funcName == "" && msg.IsFunc {
					g.funcName = msg.FuncName
				}
			}
			//log.Printf("[Guard] Sending message to proxy with msgID: %v", trans.MsgID)

			//s := time.Now()
			//log.Printf("[sendSeclambdaMsgs] Wallclock time before encoding message with ID: %v : %v", trans.MsgID, s.UnixNano())
			var err error
			//for {
			//sandboxFile.SetDeadline(time.Now().Add(1 * time.Microsecond))
			err = g.Encoder.Encode(&trans)

			/*	if os.IsTimeout(err) {
					log.Infof("[Guard] Error timed out %v", err)
					continue
				} else {
					break
				}
			}*/

			if msg.IsFunc {
				continue
			}
			//replied := false
			/*
				if len(msg.Data) == 0 {
					//msg.RecvChan <- 0 // [TODO] Respond with appropriate error
					continue
				}*/

			event := string(msg.EventName[:])
			//log.Println("[SeclambdaMeasure] Request Number: %d, Event: %s", g.requestNo, event)
			//start := time.Now()
			if event == "CHCK" {
				/*SendToCtr(updater, TYPE_CHECK_STATUS, ACTION_NOOP, []byte(fname))
				//TODO: Change this to a seclambdaFD comm
				//encoder.Encode(ReturnMsg{Allowed: true, MsgID: msg.MsgID})
				msg.RecvChan <- 1 //[TODO] Need to augment this structure
				replied = true*/
				msg.RecvChan <- 1
				continue
			}

			//log.Println("[SeclambdaMeasure] Time for event check: %s", time.Since(start1))
			//log.Println("[Seclambda] info[0]: %v, info[1]: %v ev_id: %v, present: %v, msgID: %v", info[0], info[1], ev_id, present, msg.MsgID)
			if event == "GETE" {
				// TODO: Change this to a seclambdaFD comm
				// TODO: Make this synchronous
				//log.Println("[SeclambdaMeasure] GETE: Time for Aux processing: %s", time.Since(start))
				//start1 := time.Now()

				//encoder.Encode(ReturnMsg{Allowed: true, MsgID: msg.MsgID})

				//log.Println("[SeclambdaMeasure] GETE: Time to send to sandbox: %s", time.Since(start1))
				//msg.RecvChan <- 1
				//start2 := time.Now()

				/*SendToCtr(updater, TYPE_CHECK_EVENT, ACTION_NOOP, []byte(out))
				//log.Println("[SeclambdaMeasure] GETE: Time for async controller notif: %s", time.Since(start2))
				resp := <-checkChannel
				if resp == 1 {
					encoder.Encode(ReturnMsg{Allowed: true, MsgID: msg.MsgID})
				} else {
				  encoder.Encode(ReturnMsg{Allowed: false, MsgID: msg.MsgID})*/

			} else if event == "ENDE" {
				//log.Println("[SeclambdaMeasure] ENDE: Time for Aux processing: %s", time.Since(start))
				//start1 := time.Now()
				g.PolicyInit()
				//log.Println("[SeclambdaMeasure] ENDE: Time for PolicyInit: %s", time.Since(start1))
				//TODO: Change this to a seclambdaFD comm
				//start2 := time.Now()

				//encoder.Encode(ReturnMsg{Allowed: true, MsgID: msg.MsgID})
				msg.RecvChan <- 1 // [TODO] Send an empty message to the hypercall
				//log.Println("[SeclambdaMeasure] ENDE: Time to send to sandbox: %s", time.Since(start2))
				//replied = true
				//start3 := time.Now()
				//SendToCtr(updater, TYPE_EVENT, ACTION_NOOP, []byte(out))
				//log.Println("[SeclambdaMeasure] ENDE: Time for async controller notif: %s", time.Since(start3))
			} else if event == "SEND" || event == "RESP" {
				log.Infof("[SeclambdaMeasure] SEND-RESP: Time for Aux processing: %s", time.Since(s3))
				start1 := time.Now()
				meta := string(msg.MetaData)
				//out := fmt.Sprintf("%s:%s:%s:%s", fname, event, meta, string(rid))
				//log.Infof("[Seclambda] Out string: %s", out)
				fname := g.Get_func_name()
				info := strings.Split(meta, ":")
				//log.Println("[Seclambda] info[0]: %v, info[1]: %v", info[0], info[1])
				ev_hash := Djb2hash(fname, event, info[0], info[1])
				//start1 := time.Now()
				ev_id, present := g.Get_event_id(int64(ev_hash))

				if present && g.CheckPolicy(ev_id) {
					//TODO: Change this to a seclambdaFD comm
					//log.Println("[SeclambdaMeasure] SEND-RESP-present: Time for Policy Check : %s", time.Since(start1))
					//start2 := time.Now()

					//encoder.Encode(ReturnMsg{Allowed: true, MsgID: msg.MsgID})

					//log.Println("[SeclambdaMeasure] SEND-RESP-present: Time to send to sandbox: %s", time.Since(start2))
					msg.RecvChan <- 1
					//start3 := time.Now()
					//SendToCtr(updater, TYPE_EVENT, ACTION_NOOP, []byte(out))
					//log.Println("[SeclambdaMeasure] SEND-RESP-present: Time for async controller notif %s", time.Since(start3))
				} else {
					//log.Infof("[Seclambda] Event: %v not present or not allowed by policy", ev_id)
					//TODO: Change this to a seclambdaFD comm
					log.Infof("[SeclambdaMeasure] SEND-RESP-absent: Time for Policy Check (absent): %s", time.Since(start1))
					start2 := time.Now()

					//encoder.Encode(ReturnMsg{Allowed: false, MsgID: msg.MsgID})

					//s := time.Now()
					//log.Printf("[Seclambda] Timestamp of replying to  message with ID: %v : %v", msg.MsgID, s.UnixNano())
					//log.Println("[SeclambdaMeasure] SEND-RESP-absent: Time to send to sandbox: %s", time.Since(start2))
					msg.RecvChan <- 0
					log.Infof("[SeclambdaMeasure] SEND-RESP-absent: Time to send to sandbox: %s", time.Since(start2))
					//start3 := time.Now()
					//SendToCtr(updater, TYPE_EVENT, ACTION_NOOP, []byte(out))
					//log.Println("[SeclambdaMeasure] SEND-RESP-absent: Time for async controller notif: %s", time.Since(start3))
				}
				//replied = true
			}
			//s1 := time.Now()
			//log.Printf("[sendSeclambdaMsgs] Wallclock time after encoding message with ID: %v : %v", trans.MsgID, s1.UnixNano())

			if err != nil {
				msg.RecvChan <- 0
				log.Infof("[Guard] Error encoding message %v", trans)

				g.seclambda_exited = true
				continue
			}

			/*if msg.IsFunc {
				msg.RecvChan <- 1
			}*/

		case <-sendMsgCtr:
			log.Infof("[Guard] Shutting down sendSeclambdaMsgs")
			g.Encoder.Encode(&transMsg{IsExit: true})
			sendMsgCtr <- 1
			return
		}
	}
}

func (g *Guard) Run(ch chan KernMsg, ctr chan int, done chan int, sandboxSide int, seclambdaSide int) {

	//sandboxFile := os.NewFile(uintptr(sandboxSide), "sandbox-file")
	//encoder := gob.NewEncoder(sandboxFile)
	//replyChan := make(chan ReturnMsg)
	eventChanMap := make(map[int64]chan int)
	sendMsgCtr := make(chan int)
	rcvMsgCtr := make(chan int)
	isRunning := true
	//seclambda_exited := false
	go g.receiveSeclambdaMsgs(seclambdaSide, &eventChanMap, &isRunning, rcvMsgCtr)
	go g.sendSeclambdaMsgs(sandboxSide, ch, sendMsgCtr, &eventChanMap)

	// Connect to the controller
	/*
		resp, err := http.Get("http://pages.cs.wisc.edu/")
		if err != nil {
			// handle error
			log.Debugf("[Bleeding] #1Connect to golang.org failed")
		} else {
			log.Debugf("[Bleeding] #1 Connect succeeded!")
			log.Debugf("[Bleeding] #1 Response: %v", resp)
		}

		restore, err := applyNS(netns)
		resp, err = http.Get("http://pages.cs.wisc.edu/")
		if err != nil {
			// handle error
			log.Debugf("[Bleeding] #2 Connect to golang.org failed")
		} else {
			log.Debugf("[Bleeding] #2 Connect succeeded!")
			log.Debugf("[Bleeding] #2 Response: %v", resp)
		}

		log.Infof("[Guard] NetNS fd: %v, curPID: ", netns, os.Getpid())
		if err != nil {
			log.Infof("[Guard] Failed to join host net namespace: %v", err)
		}

		id := get_func_name() + strconv.FormatInt(get_time(), 10)
		log.Infof("Started Guard with id: " + id)
		fname := get_func_name()
		idOpt := zmq.SockSetIdentity(id)
		updater := zmq.NewDealerChanneler("tcp://node4.kubernetes.cs799-serverless-pg0.wisc.cloudlab.us:5000", idOpt)
		rid := get_inst_id()*/

	/*
		if err != nil {
			log.Infof("[ZMQ] Error attaching to Controller")
		}*/
	/*
		e := updater.Connect("tcp://127.0.0.1:5000")
		if e != nil {
			log.Infof("Error connecting to Controller")
		}*/

	log.Infof("[Guard] Started Guard")
	//keyInitMsg := MsgInit([]byte(id))
	//log.Infof("Sending message: " + keyInitMsg)
	//updater.SendChan <- [][]byte{keyInitMsg}

	/*
		if er != nil {
			log.Infof("[ZMQ] Error sending message to Controller")
		}*/ /*
		_, ero := net.Dial("tcp", "golang.org:80")
		if ero != nil {
			log.Infof("Unable to connect to Controller")
			log.Infof(ero.Error())
		}*/
	/*
		conn, err := grpc.Dial("127.0.0.1:7777", grpc.WithInsecure(), grpc.WithBlock())
		if err != nil {
			log.Infof("[GRPC] Unable to connect to localhost")
		}
		efer conn.Close()
		c := pb.NewGreeterClient(conn)
	*/
	//log.Infof("[Guard] Send KeyInitReq to controller " + fname)
	//recv := <-updater.RecvChan
	//log.Infof("[Guard] Received: %s", string(recv[0]))

	for {
		// Receive signal from kernel
		// and break out of this loop
		select {
		/*case msg := <-ch:
		log.Infof("[Guard] Received a message from the kernel")
		log.Infof("[Guard] The message struct : %v", msg)
		g.requestNo += 1

		if seclambda_exited {
			msg.RecvChan <- 0
			log.Infof("[Guard] Proxy Exited: Sending all false")
			continue
		}

		trans := makeTransMsg(msg)
		if !msg.IsFunc {
			eventChanMap[trans.MsgID] = msg.RecvChan
		}
		log.Infof("[Guard] Sending message to proxy with msgID: %v", trans.MsgID)
		encoder.Encode(&trans)
		if msg.IsFunc {
			msg.RecvChan <- 1
		}

		/*
			replied := false
			/*
				if len(msg.Data) == 0 {
					//msg.RecvChan <- 0 // [TODO] Respond with appropriate error
					continue
				}*/
		/*
			event := string(msg.EventName[:])
			if event == "CHCK" {
				SendToCtr(updater, TYPE_CHECK_STATUS, ACTION_NOOP, []byte(fname))
				msg.RecvChan <- 1 //[TODO] Need to augment this structure
				replied = true
				continue
			}

			meta := string(msg.MetaData)
			out := fmt.Sprintf("%s:%s:%s:%s", fname, event, meta, string(rid))
			log.Infof("[Guard] Out string: %s", out)

			info := strings.Split(meta, ":")
			log.Infof("[Guard] info[0]: %v, info[1]: %v", info[0], info[1])
			ev_hash := djb2hash(fname, event, info[0], info[1])
			ev_id, present := g.get_event_id(int64(ev_hash))
			if event == "GETE" {
				SendToCtr(updater, TYPE_CHECK_EVENT, ACTION_NOOP, []byte(out))
				msg.RecvChan <- 1
				replied = true
			} else if event == "ENDE" {
				g.PolicyInit()
				msg.RecvChan <- 1 // [TODO] Send an empty message to the hypercall
				replied = true
				SendToCtr(updater, TYPE_EVENT, ACTION_NOOP, []byte(out))
			} else if event == "SEND" || event == "RESP" {
				if present && g.CheckPolicy(ev_id) {
					msg.RecvChan <- 1
					SendToCtr(updater, TYPE_EVENT, ACTION_NOOP, []byte(out))
				} else {

					log.Infof("[Guard] Event: %v not present or not allowed by policy", ev_id)
					msg.RecvChan <- 0
					SendToCtr(updater, TYPE_EVENT, ACTION_NOOP, []byte(out))
				}
				replied = true
			}

			if !replied {
				msg.RecvChan <- 0 //[TODO] Invalid message!
			}*/

		case <-ctr:
			log.Infof("[Guard] Exiting the go routine")
			//encoder.Encode(&transMsg{IsExit: true})
			//rcvMsgCtr <- 1
			//<-rcvMsgCtr

			sendMsgCtr <- 1
			<-sendMsgCtr

			done <- 1
			/*
							for k, v := range eventChanMap {
				 				   v <- 0
							}*/
			//restore()
			return

			/*case recv := <-replyChan:
			if recv.IsExit {
				seclambda_exited = true
				for _, v := range eventChanMap {
					v <- 0
					//delete(eventChanMap, k)
				}
				eventChanMap = make(map[int64]chan int)
				log.Infof("[Guard] Seclambda proxy exited; replying false to all new reqs")
			}

			if !seclambda_exited {
				if recv.allowed {
					eventChanMap[recv.MsgID] <- 1
				} else {
					eventChanMap[recv.MsgID] <- 0
				}
				delete(eventChanMap, recv.MsgID)
				log.Infof("[Guard] Getting reply from seclambdaSide: %v", recv)
			} else {
				ch, pr := eventChanMap[recv.MsgID]
				if pr {
					ch <- 0
				}
			}
			//delete(eventChanMap, recv.MsgID)
			//log.Infof("[Guard] Getting reply from seclambdaSide: %v", recv)
			/*
				if len(recv[0]) <= 1 {
					continue
				}
				msg := MsgParser(recv[0])
				typ := msg.header.typ
				action := msg.header.action
				//msg.header.length[MAX_LEN_SIZE] = 0
				_, err := strconv.ParseInt(string(msg.header.length[:MAX_LEN_SIZE]), 16, 64)
				if err != nil {
					log.Infof("[Guard] failed to parse message length: %s", string(msg.header.length[:]))
				}
				switch typ {
				case TYPE_KEY_DIST:
					keyInitHandler(msg.body)
					log.Infof("[Guard] Registered Keys: " + fname)
					SendToCtr(updater, TYPE_POLICY, ACTION_POLICY_INIT, []byte(fname))
				case TYPE_POLICY:
					if action == ACTION_POLICY_ADD {
						g.PolicyInitHandler(msg.body)
						log.Infof("[Guard] Finish registration; get policy")
						//ctr <- 1
					}
				case TYPE_CHECK_RESP:
					log.Infof("[Guard] Get Check Resp")
				case TYPE_CHECK_STATUS:
					log.Infof("[Guard] Send status to guard")
					g.runningTime = uint64(get_time() - g.startTime)
					s := strconv.FAllowedormatInt(int64(g.requestNo), 10) + string(":") + strconv.FormatUint(g.runningTime, 10)
					SendToCtr(updater, TYPE_CHECK_STATUS, ACTION_GD_RESP, []byte(s))
				case TYPE_TEST:
			*/
		}

	}
	log.Infof("[Guard] Exiting the go routine for loop")
}
