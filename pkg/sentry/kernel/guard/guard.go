package guard

import (
	"encoding/gob"
	"encoding/json"
	"gvisor.dev/gvisor/pkg/log"
	"sync"
	"time"
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
	// CheckPolicy Mutex
	checkPolicyMu sync.Mutex
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
	//MetaData  []byte
	Url       string
	Method    string
	PeerAddr  string
	PeerPort  int
	HasBody   int
	SessionId string
	//Data      []byte
	RecvChan chan int
	FuncName string
	IsFunc   bool
}

type transMsg struct {
	EventName [4]byte
	//MetaData  []byte
	Url       string
	Method    string
	PeerAddr  string
	PeerPort  int
	HasBody   int
	SessionId string
	//Data      []byte
	MsgID    int64
	IsExit   bool
	FuncName string
	IsFunc   bool
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
	//log.Infof("[Djb2hash] Hashing string: %v", inp)
	var hash uint64 = 5381
	for i := 0; i < len(inp); i++ {
		hash = ((hash << 5) + hash) + uint64(inp[i])
	}
	return hash & 0xFFFFFFFF
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

func keyInitHandler(msg []byte) {
	return
}

func (g *Guard) PolicyInitHandler(msg []byte) {
	var f Policy
	err := json.Unmarshal(msg, &f)
	if err != nil {
		//log.Infof("[PolicyInitHandler] Error parsing json: %v", msg)
		return
	}

	g.ior = int(f.IOR)
	g.netr = int(f.NETR)

	//log.Infof("[PolicyInitHandler] Here 1")
	for i := 0; i < len(f.IO); i++ {
		g.ioWhitelist[f.IO[i]] = 1
	}

	for i := 0; i < len(f.IP); i++ {
		g.ipWhitelist[f.IP[i]] = 1
	}

	for i := 0; i < len(f.URL); i++ {
		g.urlWhitelist[f.URL[i]] = 1
	}

	//log.Infof("[PolicyInitHandler] Here 2")

	func_name := f.GRAPH["NAME"].(string)
	eventid := f.GRAPH["EVENTID"].([]interface{})
	//log.Infof("[Guard] The eventid map : %v", eventid)
	var eventid_map []map[string]int
	//log.Infof("[PolicyInitHandler] Here 3")
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

	//log.Infof("[PolicyInitHandler] Here 4")
	for _, m := range eventid_map {
		h := int64(m["h"])
		k := m["e"]
		//log.Infof("[PolicyInitHandler] assigning h:%v = k:%v", h, k)
		g.eventMap[h] = k
	}
	//log.Infof("[PolicyInitHandler] Here 5")
	g.graph = ListInit()
	var ns_map []map[string]int
	ns := f.GRAPH["NS"].([]interface{})
	//log.Infof("[PolicyInitHandler] Here 5 1")
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
	//log.Infof("[PolicyInitHandler] Here 6")
	for _, m := range ns_map {
		var tnode Node
		tnode.id = int(m["id"])
		tnode.next_cnt = 0
		tnode.loop_cnt = int(m["cnt"])
		g.graph.Append(&tnode)
	}
	//log.Infof("[PolicyInitHandler] Here 7")
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
	//log.Infof("[PolicyInitHandler] Here 7")
	g.policyTable[func_name] = g.graph
	g.curState = g.graph
	//log.Infof("[PolicyInitHandler] Here 8")
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
	//m.MetaData = msg.MetaData
	m.Url = msg.Url
	m.Method = msg.Method
	m.PeerAddr = msg.PeerAddr
	m.PeerPort = msg.PeerPort
	m.HasBody = msg.HasBody
	m.SessionId = msg.SessionId

	//m.Data = msg.Data
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
	g.checkPolicyMu.Lock()
	defer g.checkPolicyMu.Unlock()
	fname := g.Get_func_name()
	_, present := g.policyTable[fname]
	//log.Infof("[CheckPolicy] Checking Policy from policy table")
	if !present {
		return false
	}
	//log.Infof("[CheckPolicy] Found Policy from policy table")
	p := g.curState
	if g.graph == g.curState {
		//log.Infof("[CheckPolicy] Before InitPolicy")
		g.PolicyInit()
		g.curState = g.curState.next
		p = g.curState
		//log.Infof("[CheckPolicy] InitPolicy")
	}

	nptr := p.data
	if nptr.id == event_id {
		if nptr.ctr > 0 {
			nptr.ctr = nptr.ctr - 1
			//log.Infof("[CheckPolicy] Return true on event_id check")
			//return true
		}
		//log.Infof("[CheckPolicy] Return false on event_id check")
		//return false
	}

	for i := 0; i < 1000; i++ {
		next_ptr := nptr.successors[0]
		next_d_ptr := next_ptr.data

		if (next_d_ptr != nil) && (next_d_ptr.ctr > 0) && (next_d_ptr.id == event_id) {
			next_d_ptr.ctr = next_d_ptr.ctr - 1
			g.curState = next_ptr
			//log.Infof("[CheckPolicy] Return true after %v iterations", i)
			//return true
		}
	}
	//log.Infof("[CheckPolicy] Return false after 1000 iterations")
	return true
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

		//log.Infof("[Guard] Got response for MsgID: %v", recv.MsgID)

		if len(recv.Policy) > 0 {
			g.PolicyInitHandler(recv.Policy)
			//log.Infof("[Guard] Initializing Policy")
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
				//log.Infof("[Guard] Sending allowed reply back: %v", recv.MsgID)
				(*eventChanMap)[recv.MsgID] <- 1
				if recv.MsgID == 0 {
					return
				}
				//elapsed1 := time.Since(start)
				//log.Printf("[receiveSeclambdaMsgs] Time spent sending response back: %v", elapsed1)

			} else {
				//s := time.Now()
				//respTime = time.Now()
				//log.Printf("[receiveSeclambdaMsgs] Timestamp just before delivering response to caller: %v", s.UnixNano())
				(*eventChanMap)[recv.MsgID] <- 0
				if recv.MsgID == 0 {
					return
				}
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
					//g.funcName = msg.FuncName
					n := strings.Split(msg.FuncName, "-")
					if len(n) <= 2 {
						g.funcName = strings.Join(n, "-")
					} else {
						g.funcName = strings.Join(n[:len(n)-2], "-")
					}

				}
			}

			var err error
			err = g.Encoder.Encode(&trans)

			if msg.IsFunc {
				continue
			}

			event := string(msg.EventName[:])
			if event == "CHCK" {
				msg.RecvChan <- 1 //[TODO] Need to augment this structure
				//replied = true
				msg.RecvChan <- 1
				continue
			}

			if event == "GETE" {
			} else if event == "ENDE" {
				g.PolicyInit()

				msg.RecvChan <- 1 // [TODO] Send an empty message to the hypercall
			} else if event == "SEND" || event == "RESP" {
				//log.Infof("[SeclambdaMeasure] SEND-RESP: Time for Aux processing: %s", time.Since(s3))
				//start1 := time.Now()
				//meta := string(msg.MetaData)
				//out := fmt.Sprintf("%s:%s:%s:%s", fname, event, meta, string(rid))
				//log.Infof("[Seclambda] Out string: %s", out)
				fname := g.Get_func_name()
				//info := strings.Split(meta, ":")
				//log.Println("[Seclambda] info[0]: %v, info[1]: %v", info[0], info[1])
				ev_hash := Djb2hash(fname, event, msg.Url, msg.Method)
				//start1 := time.Now()
				ev_id, present := g.Get_event_id(int64(ev_hash))

				if present && g.CheckPolicy(ev_id) {
					msg.RecvChan <- 1
				} else {

					msg.RecvChan <- 0
				}
			}

			if err != nil {
				msg.RecvChan <- 0
				log.Infof("[Guard] Error encoding message %v", trans)

				g.seclambda_exited = true
				continue
			}

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
	log.Infof("[Guard] Started Guard")
	for {
		// Receive signal from kernel
		// and break out of this loop
		select {
		case <-ctr:
			log.Infof("[Guard] Exiting the go routine")

			sendMsgCtr <- 1
			<-sendMsgCtr

			done <- 1
		}
		return

	}

	log.Infof("[Guard] Exiting the go routine for loop")
}
