package finder

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"math/big"
	"unicode/utf16"
	"unsafe"

	wc "github.com/carved4/go-wincall"
)

const (
	scanSize = 128 // Scan size for byte matching :3
)

type ChecksumVariant int

const (
	ChecksumAt0 ChecksumVariant = iota // 0x10aded040410aded - checks *arg1 (Table[0])
	ChecksumAt2                        // 0x10aded020210aded - checks arg1[2] (Table[2])
)

type VulkanFunction struct {
	Name            string
	Address         uintptr
	Index           uint64
	Index2          uint64 // secondary index for conditional logic (0 if not used)
	ChecksumVariant ChecksumVariant
}

func utf16ToString(s []uint16) string {
	for i, v := range s {
		if v == 0 {
			return string(utf16.Decode(s[0:i]))
		}
	}
	return string(utf16.Decode(s))
}

func getModuleFileName(moduleHandle uintptr) (string, error) {
	b := make([]uint16, 1024)
	ret, _, err := wc.Call("kernel32.dll", "GetModuleFileNameW", moduleHandle, uintptr(unsafe.Pointer(&b[0])), uintptr(len(b)))
	if ret == 0 {
		return "", err
	}
	if err != nil && err.Error() != "The operation completed successfully." {
		return "", err
	}
	return utf16ToString(b), nil
}

func FindVulkanFunction() (*VulkanFunction, error) {
	dllPath := "C:\\Windows\\System32\\vulkan-1.dll"
	wc.LoadLibraryW(dllPath)
	moduleBase := wc.GetModuleBase(wc.GetHash("vulkan-1.dll"))
	if moduleBase == 0 {
		return nil, fmt.Errorf("could not get module base for %s", dllPath)
	}

	exports, err := getVulkanExports(moduleBase)
	if err != nil {
		return nil, fmt.Errorf("could not get vulkan exports: %w", err)
	}

	var compatibleFunctions []*VulkanFunction

	for _, funcName := range exports {
		funcAddr := wc.GetFunctionAddress(moduleBase, wc.GetHash(funcName))
		if funcAddr == 0 {
			continue
		}

		funcBytes := readMemory(funcAddr, scanSize)

		if len(funcBytes) > 0 && funcBytes[0] == 0xE9 {
			if len(funcBytes) < 5 {
				continue
			}
			offset := int32(binary.LittleEndian.Uint32(funcBytes[1:5]))
			jmpTarget := funcAddr + 5 + uintptr(offset)
			funcBytes = readMemory(jmpTarget, scanSize)
		}

		if index, index2, variant, ok := analyzeFunction(funcBytes); ok {
			compatibleFunctions = append(compatibleFunctions, &VulkanFunction{
				Name:            funcName,
				Address:         funcAddr,
				Index:           uint64(index),
				Index2:          uint64(index2),
				ChecksumVariant: variant,
			})
		}
	}

	if len(compatibleFunctions) > 0 {
		// randomly select from compatible functions to use
		n, _ := rand.Int(rand.Reader, big.NewInt(int64(len(compatibleFunctions))))
		selected := compatibleFunctions[n.Int64()]
		return selected, nil
	}

	fmt.Println("No compatible function found, using fallback.")
	fallbackAddr := wc.GetFunctionAddress(moduleBase, wc.GetHash("vkCreateSamplerYcbcrConversion"))
	if fallbackAddr == 0 {
		return nil, fmt.Errorf("could not find fallback function vkCreateSamplerYcbcrConversion")
	}
	// use a known good one if we dont find a compatible func (unlikely)
	return &VulkanFunction{
			Name:            "vkCreateSamplerYcbcrConversion",
			Address:         fallbackAddr,
			Index:           132,
			Index2:          0,
			ChecksumVariant: ChecksumAt0,
		},
		nil
}

func getVulkanExports(moduleBase uintptr) ([]string, error) {
	var exports []string
	// simple export directory parse to identify vk* funcs
	dosHeader := (*uint16)(unsafe.Pointer(moduleBase))
	if *dosHeader != 0x5A4D {
		return nil, fmt.Errorf("invalid DOS header")
	}

	ntOffset := *(*uint32)(unsafe.Pointer(moduleBase + 0x3C))
	ntHeaders := moduleBase + uintptr(ntOffset)

	if *(*uint32)(unsafe.Pointer(ntHeaders)) != 0x00004550 {
		return nil, fmt.Errorf("invalid PE signature")
	}

	dataDirs := ntHeaders + 0x88
	exportDirRVA := *(*uint32)(unsafe.Pointer(dataDirs))

	if exportDirRVA == 0 {
		return exports, nil // no exports
	}

	exportDir := moduleBase + uintptr(exportDirRVA)
	numberOfNames := *(*uint32)(unsafe.Pointer(exportDir + 24))
	namesArrayRVA := *(*uint32)(unsafe.Pointer(exportDir + 32))

	namesArray := moduleBase + uintptr(namesArrayRVA)

	for i := uint32(0); i < numberOfNames; i++ {
		nameRVA := *(*uint32)(unsafe.Pointer(namesArray + uintptr(i*4)))
		namePtr := moduleBase + uintptr(nameRVA)
		name := ""
		for j := 0; j < 256; j++ {
			b := *(*byte)(unsafe.Pointer(namePtr + uintptr(j)))
			if b == 0 {
				break
			}
			name += string(b)
		}
		// check if vk* func
		if len(name) >= 2 && name[:2] == "vk" {
			exports = append(exports, name)
		}
	}

	return exports, nil
}

func readMemory(address uintptr, size int) []byte {
	b := make([]byte, size)
	p := unsafe.Pointer(address)
	for i := 0; i < size; i++ {
		b[i] = *(*byte)(unsafe.Pointer(uintptr(p) + uintptr(i)))
	}
	return b
}

func analyzeFunction(funcBytes []byte) (int, int, ChecksumVariant, bool) {
	// these are mov instructions that load the checksum into registers :3
	checksumMovPatterns := map[ChecksumVariant][]byte{
		ChecksumAt0: {0x49, 0xBA, 0xED, 0xAD, 0x10, 0x04, 0x04, 0xED, 0xAD, 0x10}, // mov r10, 0x10aded040410aded
		ChecksumAt2: {0x49, 0xB8, 0xED, 0xAD, 0x10, 0x02, 0x02, 0xED, 0xAD, 0x10}, // mov r8, 0x10aded020210aded
	}

	// these are the actual checksum bytes to look for in comparisons
	checksumBytes := map[ChecksumVariant][]byte{
		ChecksumAt0: {0xED, 0xAD, 0x10, 0x04, 0x04, 0xED, 0xAD, 0x10}, // 0x10aded040410aded in little endian
		ChecksumAt2: {0xED, 0xAD, 0x10, 0x02, 0x02, 0xED, 0xAD, 0x10}, // 0x10aded020210aded in little endian
	}

	// additional patterns for the 0x02 variant
	alt02Patterns := [][]byte{
		{0x48, 0xB8, 0xED, 0xAD, 0x10, 0x02, 0x02, 0xED, 0xAD, 0x10}, // mov rax, 0x10aded020210aded (32-bit)
	}

	var detectedVariant ChecksumVariant
	var checksumIndex = -1

	// first, detect which checksum variant we have by looking for mov patterns
	for variant, pattern := range checksumMovPatterns {
		if idx := bytes.Index(funcBytes, pattern); idx != -1 {
			detectedVariant = variant
			checksumIndex = idx
			break
		}
	}

	// then check alternative patterns for 0x02 variant
	if checksumIndex == -1 {
		for _, pattern := range alt02Patterns {
			if idx := bytes.Index(funcBytes, pattern); idx != -1 {
				detectedVariant = ChecksumAt2
				checksumIndex = idx
				break
			}
		}
	}

	// if no mov patterns found, look for embedded checksum bytes (for direct comparison functions)
	if checksumIndex == -1 {
		for variant, checksumPattern := range checksumBytes {
			if idx := bytes.Index(funcBytes, checksumPattern); idx != -1 {
				detectedVariant = variant
				checksumIndex = idx
				break
			}
		}
	}

	if checksumIndex == -1 {
		return 0, 0, ChecksumAt0, false
	}

	// for 0x02 variant, we need to detect arg1[2] access pattern
	if detectedVariant == ChecksumAt2 {
		// look for specific patterns that indicate arg1[2] access and arg1[3] usage:
		// 1. cmp qword [rcx+16], r8/rax (comparing arg1[2])
		// 2. mov r9, qword [rcx+24] (loading arg1[3] for parameter)

		// pattern: cmp qword [rcx+16], reg (48 39 41 10 or 4C 39 41 10) i hate writing code comments but they're so helpful
		arg2AccessPatterns := [][]byte{
			{0x48, 0x39, 0x41, 0x10}, // cmp qword [rcx+16], rax
			{0x4C, 0x39, 0x41, 0x10}, // cmp qword [rcx+16], r8
			{0x48, 0x8B, 0x41, 0x10}, // mov rax, qword [rcx+16]
			{0x4C, 0x8B, 0x49, 0x18}, // mov r9, qword [rcx+24] - loading arg1[3]
		}

		hasArg2Access := false
		for _, pattern := range arg2AccessPatterns {
			if bytes.Index(funcBytes, pattern) != -1 {
				hasArg2Access = true
				break
			}
		}

		if hasArg2Access {
			// for 0x02 variant with arg1[2] access, look for table access pattern
			// check if this function has conditional logic with two possible indices
			index1, index2 := findConditionalTableIndices(funcBytes, checksumIndex)
			if index1 > 0 {
				return index1, index2, ChecksumAt2, true
			}

			// fallback to single index detection
			index := findTableIndex(funcBytes, checksumIndex)
			return index, 0, ChecksumAt2, index > 0
		}
	}

	// for 0x04 variant (standard case), look for different patterns
	if detectedVariant == ChecksumAt0 {
		// first try to find the direct array access pattern (rax_1[index])
		if index := findDirectArrayAccess(funcBytes, checksumIndex); index > 0 {
			return index, 0, ChecksumAt0, true
		}

		// fallback to original table index detection
		if index := findTableIndex(funcBytes, checksumIndex); index > 0 {
			return index, 0, ChecksumAt0, true
		}
	}

	return 0, 0, ChecksumAt0, false
}

func findTableIndex(funcBytes []byte, checksumIndex int) int {
	// look for tailcall after checksum (within 60 bytes)
	for i := checksumIndex; i <= len(funcBytes)-6 && i < checksumIndex+60; i++ {
		if funcBytes[i] == 0xFF && funcBytes[i+1] == 0x25 {
			//  we found a tailcall, now we search backwards for mov rax, [rax + offset] to avoid case of
			//  our search window containing multiple funcs with multiple tailcalls :3
			for j := i - 7; j >= checksumIndex && j >= i-20; j-- {
				if j+7 <= len(funcBytes) &&
					funcBytes[j] == 0x48 && funcBytes[j+1] == 0x8B && funcBytes[j+2] == 0x80 {

					offset := binary.LittleEndian.Uint32(funcBytes[j+3 : j+7])
					if offset%8 == 0 {
						index := int(offset / 8)
						if index > 0 && index < 256 {
							return index
						}
					}
				}
			}
		}
	}

	// fallback: look for double dereference pattern
	for i := 0; i <= len(funcBytes)-15; i++ {
		// look for mov rax, [rcx] (48 8B 01) followed by mov rax, [rax + offset] (48 8B 80)
		if funcBytes[i] == 0x48 && funcBytes[i+1] == 0x8B && funcBytes[i+2] == 0x01 && // mov rax, [rcx]
			i+10 < len(funcBytes) {

			// look for the second mov rax, [rax + offset] within the next few bytes
			for k := i + 3; k <= i+10 && k+7 <= len(funcBytes); k++ {
				if funcBytes[k] == 0x48 && funcBytes[k+1] == 0x8B && funcBytes[k+2] == 0x80 {
					offset := binary.LittleEndian.Uint32(funcBytes[k+3 : k+7])

					// look for call [rax] (FF D0) or similar patterns within next 10 bytes
					// there has to be a better way to do this
					for j := k + 7; j <= len(funcBytes)-2 && j < k+17; j++ {
						if (funcBytes[j] == 0xFF && funcBytes[j+1] == 0xD0) || // call rax
							(funcBytes[j] == 0xFF && funcBytes[j+1] == 0x15) { // call [rip+offset]
							if offset%8 == 0 {
								index := int(offset / 8)
								if index > 0 && index < 256 {
									return index
								}
							}
						}
					}
				}
			}
		}
	}

	return 0
}

// findConditionalTableIndices detects the conditional pattern:
// if (r9 && *(uint8_t*)((char*)r9 + offset))
//
//	return (*(uint64_t*)((char*)r10 + offset1))(rax_1);
//
// return (*(uint64_t*)((char*)r10 + offset2))(rax_1);
func findConditionalTableIndices(funcBytes []byte, checksumIndex int) (int, int) {
	// look for the conditional pattern after checksum
	// pattern: mov r9, [rcx+8] (arg1[1]) followed by conditional logic
	movR9Pattern := []byte{0x4C, 0x8B, 0x49, 0x08}

	for i := checksumIndex; i < len(funcBytes)-20; i++ {
		if bytes.Equal(funcBytes[i:i+4], movR9Pattern) {
			// found mov r9, [rcx+8], now look for the conditional logic

			// look for two different offset patterns in the next 50 bytes
			var offsets []uint32

			// pattern: mov rax, [r10+offset] or similar (48 8B 82 XX XX XX XX)
			for j := i; j < len(funcBytes)-7 && j < i+50; j++ {
				if funcBytes[j] == 0x48 && funcBytes[j+1] == 0x8B && funcBytes[j+2] == 0x82 {
					offset := binary.LittleEndian.Uint32(funcBytes[j+3 : j+7])
					if offset%8 == 0 {
						index := int(offset / 8)
						if index > 0 && index < 256 {
							offsets = append(offsets, uint32(index))
						}
					}
				}
			}

			// if we found exactly 2 offsets, return them
			if len(offsets) >= 2 {
				// sort to have consistent ordering (smaller idx first)
				if offsets[0] > offsets[1] {
					return int(offsets[1]), int(offsets[0])
				}
				return int(offsets[0]), int(offsets[1])
			}
		}
	}

	return 0, 0
}

// findDirectArrayAccess detects the pattern: rax_1[index](arg1)
// this looks for: mov rax, [rcx]; cmp [rax], checksum; call [rax+offset]
func findDirectArrayAccess(funcBytes []byte, checksumIndex int) int {
	// look for the pattern after checksum
	// pattern: call qword [rax+offset] where offset = index * 8

	// search for call [rax+offset] pattern (FF 50 XX or FF 90 XX XX XX XX)
	for i := checksumIndex; i < len(funcBytes)-6 && i < checksumIndex+60; i++ {
		// pattern: call qword [rax+offset8] (FF 50 XX)
		if funcBytes[i] == 0xFF && funcBytes[i+1] == 0x50 {
			offset := uint32(funcBytes[i+2])
			if offset%8 == 0 {
				index := int(offset / 8)
				if index > 0 && index < 64 { // reasonable range mayb?
					return index
				}
			}
		}

		// pattern: call qword [rax+offset32] (FF 90 XX XX XX XX)
		if i+6 <= len(funcBytes) && funcBytes[i] == 0xFF && funcBytes[i+1] == 0x90 {
			offset := binary.LittleEndian.Uint32(funcBytes[i+2 : i+6])
			if offset%8 == 0 {
				index := int(offset / 8)
				if index > 0 && index < 256 {
					return index
				}
			}
		}
	}

	return 0
}
