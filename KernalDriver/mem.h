#ifndef MEM_H // Check if the header file is already included.
#define MEM_H // Define this preprocessor directive if the MEM_H is not defined, to avoid double inclusion.

// Your necessary includes and definitions
#include "imports.h"
#include <memory>

#pragma warning(disable:4595)
#pragma warning(default:4595)

#define to_lowers(c_char) ((c_char >= 'A' && c_char <= 'Z') ? (c_char + 32) : c_char)

namespace nt
{
	typedef struct _SYSTEM_MODULE
	{
		HANDLE Section;
		PVOID MappedBase;
		PVOID ImageBase;
		ULONG ImageSize;
		ULONG Flags;
		USHORT LoadOrderIndex;
		USHORT InitOrderIndex;
		USHORT LoadCount;
		USHORT OffsetToFileName;
		UCHAR FullPathName[256];
	} SYSTEM_MODULE, * PSYSTEM_MODULE;

	typedef struct _SYSTEM_MODULE_INFORMATION
	{
		ULONG NumberOfModules;
		SYSTEM_MODULE Modules[1];
	} SYSTEM_MODULE_INFORMATION, * PSYSTEM_MODULE_INFORMATION;

	typedef enum _SYSTEM_INFORMATION_CLASS
	{
		SystemBasicInformation,
		SystemProcessorInformation,
		SystemPerformanceInformation,
		SystemTimeOfDayInformation,
		SystemPathInformation,
		SystemProcessInformation,
		SystemCallCountInformation,
		SystemDeviceInformation,
		SystemProcessorPerformanceInformation,
		SystemFlagsInformation,
		SystemCallTimeInformation,
		SystemModuleInformation = 0x0B
	} SYSTEM_INFORMATION_CLASS,
		* PSYSTEM_INFORMATION_CLASS;
}

namespace mem
{
    // Function declarations
    template <typename T>
    std::unique_ptr<T> query_system_info(nt::SYSTEM_INFORMATION_CLASS info_class,
                                         uintptr_t size = 0x1000) noexcept;

    uintptr_t get_kernel_module(const char* module_name) noexcept;

    PIMAGE_NT_HEADERS getHeader(PVOID module);

    DWORD getoffsets();

    auto getprocessdirbase(PEPROCESS targetprocess) -> ULONG_PTR;

    PBYTE FindPattern(PVOID module, DWORD size, LPCSTR pattern, LPCSTR mask);

    PBYTE FindPattern(PVOID base, LPCSTR pattern, LPCSTR mask);

    NTSTATUS FindProcessByName(const char* process_name, PEPROCESS* process);

    auto readphysaddress(PVOID address, PVOID buffer, SIZE_T size, SIZE_T* read) -> NTSTATUS;

    auto translateaddress(uint64_t processdirbase, uint64_t address) -> uint64_t;

    auto readprocessmemory(PEPROCESS process, PVOID address, PVOID buffer, SIZE_T size, SIZE_T* read) -> NTSTATUS;

    template <typename str_type, typename str_type_2>
    bool cstrcmp(str_type str, str_type_2 in_str, bool two);

    NTSTATUS get_module_base(PEPROCESS process, const char* module_name, uint64_t* allocated_buffer,
        SIZE_T readed);
}

#endif // Finish the include guard MEM_H.