package linux

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"gvisor.dev/gvisor/pkg/sentry/arch"
	"gvisor.dev/gvisor/pkg/sentry/kernel"
	"gvisor.dev/gvisor/pkg/usermem"
	"strconv"
	"strings"
)

const AES_GCM_TAGLEN = 16

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

	//t.Infof("[ValidateSSLSend] fd: %v, hostname: %v, ip: %v, session_id: %v, data: %s, data", fd, hostname, ip, session_id,
	//	data_str)
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

	//meta_str := fmt.Sprintf("%s:%s:%s:%s:%d:%s", url, method, ip, port, has_body, session_id)
	var m kernel.MetaStruct
	m.Url = url
	m.Method = method
	m.PeerAddr = string(ip)
	m.PeerPort, _ = strconv.Atoi(port)
	m.HasBody = has_body
	m.SessionId = session_id

	//t.Infof("[ValidateSSLSend] The meta str: %s", meta_str)
	event := []byte("SEND")
	if method == "GET" {
		event = []byte("GETE")
	}

	if r := t.Kernel().SendEventGuard(event, m, data_slice, *t.ContainerName()); r == 1 {
		//t.Infof("[ValidateSSLSend] Guard allowed the action")
	} else {
		//t.Infof("[ValidateSSLSend] Guard disallowed action")
	}

	// Need to write protect the payload ptr address range
	return 0, nil, nil
}

type AESEncrypt struct {
	IV            uintptr
	IV_len        uint64
	Plaintext     uintptr
	Plaintext_len uint64
	Key           uintptr
	Key_len       uint64
	Addl_data     uintptr
	Addl_data_len uint64
}

func marshal_aes(struct_data []byte) AESEncrypt {
	var res AESEncrypt
	start := 0
	end := 8

	iv := binary.LittleEndian.Uint64(struct_data[start:end])
	res.IV = uintptr(iv)
	start += 8
	end += 8

	res.IV_len = binary.LittleEndian.Uint64(struct_data[start:end])
	start += 8
	end += 8

	res.Plaintext = uintptr(binary.LittleEndian.Uint64(struct_data[start:end]))
	start += 8
	end += 8

	res.Plaintext_len = binary.LittleEndian.Uint64(struct_data[start:end])
	start += 8
	end += 8

	res.Key = uintptr(binary.LittleEndian.Uint64(struct_data[start:end]))
	start += 8
	end += 8

	res.Key_len = binary.LittleEndian.Uint64(struct_data[start:end])
	start += 8
	end += 8

	res.Addl_data = uintptr(binary.LittleEndian.Uint64(struct_data[start:end]))
	start += 8
	end += 8

	res.Addl_data_len = binary.LittleEndian.Uint64(struct_data[start:end])
	start += 8
	end += 8

	return res

}

// key, key_len, iv, iv_len, plaintext, plaintext_len, additional data, additional data length
func AES_GCM_encrypt(t *kernel.Task, args arch.SyscallArguments) (uintptr, *kernel.SyscallControl, error) {
	t.Infof("[AES_GCM_encrypt] In the hypercall")
	struct_ptr := args[0].Pointer()
	struct_size := args[1].SizeT()

	t.Infof("[AES_GCM_encrypt] Pointer: %x, Struct size: %v", struct_ptr, int(struct_size))
	src, _ := t.SingleIOSequence(struct_ptr, int(struct_size), usermem.IOOpts{
		AddressSpaceActive: true,
	})

	struct_data := make([]byte, int(struct_size))
	src.Reader(t).Read(struct_data)
	t.Infof("[AES_GCM_encrypt] Read struct data")
	aes_struct := marshal_aes(struct_data)
	t.Infof("[AES_GCM_encrypt] Marshalled the struct")

	// Get IV
	t.Infof("[AES_GCM_encrypt] IV Length: %v", int(aes_struct.IV_len))
	iv := make([]byte, int(aes_struct.IV_len))
	src, _ = t.SingleIOSequence(usermem.Addr(aes_struct.IV), int(aes_struct.IV_len), usermem.IOOpts{
		AddressSpaceActive: true,
	})
	src.Reader(t).Read(iv)

	// Get Plaintext
	t.Infof("[AES_GCM_encrypt] Plaintext_len : %v", int(aes_struct.Plaintext_len))
	plaintext := make([]byte, int(aes_struct.Plaintext_len)-AES_GCM_TAGLEN)
	src_pt, _ := t.SingleIOSequence(usermem.Addr(aes_struct.Plaintext), int(aes_struct.Plaintext_len), usermem.IOOpts{
		AddressSpaceActive: true,
	})
	src_pt.Reader(t).Read(plaintext)

	//Get Key
	t.Infof("[AES_GCM_encrypt] Key len: %v", int(aes_struct.Key_len))
	key := make([]byte, int(aes_struct.Key_len))
	src, _ = t.SingleIOSequence(usermem.Addr(aes_struct.Key), int(aes_struct.Key_len), usermem.IOOpts{
		AddressSpaceActive: true,
	})
	src.Reader(t).Read(key)

	//Get Addl Data
	t.Infof("[AES_GCM_encrypt] Additional data len: %v", int(aes_struct.Addl_data_len))
	addl_data := make([]byte, int(aes_struct.Addl_data_len))
	src, _ = t.SingleIOSequence(usermem.Addr(aes_struct.Addl_data), int(aes_struct.Addl_data_len), usermem.IOOpts{
		AddressSpaceActive: true,
	})
	src.Reader(t).Read(addl_data)

	t.Infof("[AES_GCM_encrypt] The IV: %v", hex.EncodeToString(iv))
	t.Infof("[AES_GCM_encrypt] The Plaintext: %v", hex.EncodeToString(plaintext))
	t.Infof("[AES_GCM_encrypt] The Key: %v", hex.EncodeToString(key))
	t.Infof("[AES_GCM_encrypt] The Additional data: %v", hex.EncodeToString(addl_data))

	block, err := aes.NewCipher(key)
	if err != nil {
		t.Infof("[AES_GCM_encrypt] Failed to create AES cipher")
		return 0, nil, nil
	}

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		t.Infof("[AES_GCM_encrypt] Failed to create AES cipher")
		return 0, nil, nil
	}

	ciphertext := aesgcm.Seal(nil, iv, plaintext, addl_data)
	t.Infof("[AES_GCM_encrypt] Generated ciphertext: %v", hex.EncodeToString(ciphertext))
	t.Infof("[AES_GCM_encrypt] Copying the ciphertext back into the buffer")

	t.Infof("[AES_GCM_encrypt] Finished Hypercall")
	src_pt.Writer(t).Write(ciphertext)
	return 0, nil, nil
}
