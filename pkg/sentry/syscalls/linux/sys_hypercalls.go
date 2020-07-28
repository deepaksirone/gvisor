package linux

import (
	"encoding/hex"
	"fmt"
	"gvisor.dev/gvisor/pkg/sentry/arch"
	"gvisor.dev/gvisor/pkg/sentry/kernel"
	"gvisor.dev/gvisor/pkg/usermem"
	"strings"
	"time"
)

func Hypercall1(t *kernel.Task, args arch.SyscallArguments) (uintptr, *kernel.SyscallControl, error) {
	fd := args[0].Int()
	ip := usermem.Addr(t.Arch().IP())
	ar, err := ip.RoundDown().ToRange(usermem.PageSize)
	valid := t.GetValid(fd)
	t.Infof("Hypercall1: The current IP value is %x", ip)
	t.Infof("Hypercall1: The current valid bit for fd: %v is %v", fd, valid)
	if err := t.FDTable().SetValid(fd, true); err == nil {
		t.Infof("Hypercall1: Validated descriptor %v", fd)
	} else {
		t.Infof("Hypercall1: Unable to validate descriptor %v", fd)
	}

	t.Infof("Hypercall1: The new valid bit: %v", t.GetValid(fd))

	if err == false {
		t.Infof("Hypercall1 Failed to get Range")
		return 0, nil, nil
	}

	t.Infof("Hypercall1 Just before GetVMAsLocked")

	vma, _, e := t.MemoryManager().GetVMA(t, ar, usermem.AnyAccess, true)
	if e != nil {
		t.Infof("Hypercall1 Failed to get VMA")
		return 0, nil, nil
	}

	t.Infof("Hypercall1 Just before GetName")
	v := vma.ValuePtr().GetName(t)
	i := vma.ValuePtr().GetInodeID()
	d := vma.ValuePtr().GetDeviceID()

	t.Infof("Hypercall1: Mapped name of VMA: %s, Inode Number: %x, Device Number: %x", v, i, d)
	//t.Kernel().SendDummyGuard()
	return 0, nil, nil
}

func generateUrl(hostname string, port string, data []byte) string {
	var url string
	if hostname == "" {
		url = fmt.Sprintf("*;*/%s", hex.EncodeToString(data))
	} else {
		url = fmt.Sprintf("%s;%s/%s", hostname, port, hex.EncodeToString(data))
	}
	return url
}

// args[0] = fd; args[1] = hostname ptr; args[2] = payload ptr
// Assuming the payload contains plaintext HTTP data
func ValidateSSLSend(t *kernel.Task, args arch.SyscallArguments) (uintptr, *kernel.SyscallControl, error) {
	start := time.Now()
	//fd := args[0].Int()
	hostname_ptr := args[1].Pointer()
	ip_ptr := args[2].Pointer()
	//port := args[2].Int()
	//has_body := args[3].Int()
	session_id_ptr := args[3].Pointer()
	data_ptr := args[4].Pointer()
	data_len := args[5].SizeT()

	// Max hostname length is 255 for now
	hostname, _ := t.CopyInString(hostname_ptr, 255)
	if hostname == "" {
		return 0, nil, nil
	}

	ip, _ := t.CopyInString(ip_ptr, 22)
	split := strings.Split(ip, ":")
	ip = split[0]
	port := split[1]

	session_id, _ := t.CopyInString(session_id_ptr, 255)
	data_slice := make([]byte, int(data_len))
	//data_s, _ := t.CopyInString(data_ptr, int(data_len))

	src, _ := t.SingleIOSequence(data_ptr, int(data_len), usermem.IOOpts{
		AddressSpaceActive: true,
	})
	src.Reader(t).Read(data_slice)

	//data_str := string(data_slice)
	url := generateUrl(hostname, port, data_slice)

	//t.Infof("[ValidateSSLSend] fd: %v, hostname: %v, ip: %v, session_id: %v, data: %s, data", fd, hostname, ip, session_id,
	//	data_str)
	method := ""
	if data_slice[0] == 'G' && data_slice[1] == 'E' && data_slice[2] == 'T' {
		method = "GET"
	} else {
		method = "POST"
	}

	has_body := 0

	if method == "POST" {
		//tmp := strings.Split(data_str, "\r\n")[0]
		has_body = 1
	} else if method == "GET" {
		//t.Infof("[ValidateSSLSend] GET encountered!")
	}

	meta_str := fmt.Sprintf("%s:%s:%s:%s:%d:%s", url, method, ip, port, has_body, session_id)
	//t.Infof("[ValidateSSLSend] The meta str: %s", meta_str)
	event := []byte("SEND")
	if method == "GET" {
		event = []byte("GETE")
	}

	if r := t.Kernel().SendEventGuard(event, meta_str, data_slice, *t.ContainerName()); r == 1 {
		//t.Infof("[ValidateSSLSend] Guard allowed the action")
	} else {
		//t.Infof("[ValidateSSLSend] Guard disallowed action")
	}

	t.Infof("[ValidateSSLSend] Time taken for ValidateSSLSend: %v", time.Since(start))
	// Need to write protect the payload ptr address range
	return 0, nil, nil
}
