package linux

import (
	"gvisor.dev/gvisor/pkg/sentry/arch"
	"gvisor.dev/gvisor/pkg/sentry/kernel"
	"gvisor.dev/gvisor/pkg/sentry/usermem"
)

func Hypercall1(t *kernel.Task, args arch.SyscallArguments) (uintptr, *kernel.SyscallControl, error) {
	ip := usermem.Addr(t.Arch().IP())
	ar, err := ip.RoundDown().ToRange(usermem.PageSize)
	t.Infof("Hypercall1: The current IP value is %x", ip)

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
	return 0, nil, nil
}

/*
// args[0] = fd; args[1] = hostname ptr; args[2] = payload ptr
// Assuming the payload contains plaintext HTTP data
func ValidateDescriptor(t *kernel.Task, args arch.SyscallArguments) (uintptr, *kernel.SyscallControl, error) {
	fd := args[0].Int()
	hostname_ptr := args[1].Pointer()
	payload_ptr := args[2].Pointer()

	// Max hostname length is 255 for now
	hostname := t.CopyInString(addr, linux.NAME_MAX)
	if hostname == "" {
		return 0, nil, nil
	}

	// Need to write protect the payload ptr address range

}*/
