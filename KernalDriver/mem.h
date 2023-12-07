#pragma once
#pragma warning(disable:4595)
#pragma warning(default:4595)

#include "imports.h"
#include <memory>
#define MZ 0x5A4D


inline void* operator new(std::size_t count) {
	return ExAllocatePool(PagedPool, count);
}

inline void* operator new[](std::size_t count) {
	return ExAllocatePool(PagedPool, count);
}

inline void operator delete(void* ptr) {
	ExFreePoolWithTag(ptr, 0);
}

inline void operator delete[](void* ptr) {
	ExFreePoolWithTag(ptr, 0);
}

inline void operator delete(void* ptr, std::size_t sz) {
	UNREFERENCED_PARAMETER(sz);
	ExFreePoolWithTag(ptr, 0);
}


namespace nt {
	typedef struct _SYSTEM_MODULE {
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

	typedef struct _SYSTEM_MODULE_INFORMATION {
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
    template <typename T>
    inline std::unique_ptr<T> query_system_info(nt::SYSTEM_INFORMATION_CLASS info_class, uintptr_t size = 0x1000) noexcept {
        ULONG buffer_size = static_cast<ULONG>(size);
        auto system_info_buffer = std::unique_ptr<T>(reinterpret_cast<T*>(new uint8_t[buffer_size]));

        auto status = ZwQuerySystemInformation(info_class, system_info_buffer.get(), buffer_size, &buffer_size);

        while (status == 0xC0000004) {
            system_info_buffer = std::unique_ptr<T>(reinterpret_cast<T*>(new uint8_t[buffer_size]));
            status = ZwQuerySystemInformation(info_class, system_info_buffer.get(), buffer_size, &buffer_size);

            if (!NT_SUCCESS(status) && (buffer_size == 0x100000 || buffer_size == size))
                break;
        }

        if (!NT_SUCCESS(status))
            return nullptr;

        return system_info_buffer;
    }

	uintptr_t get_kernel_module(const char* module_name) noexcept {
        const auto system_module_info = query_system_info<nt::SYSTEM_MODULE_INFORMATION>(nt::SystemModuleInformation);

        if (!system_module_info)
            return 0;

        for (auto i = 0ul; i != system_module_info->NumberOfModules; ++i) {
            const auto& module_info = system_module_info->Modules[i];

			Printf("module: %s\n", module_info.FullPathName);

            if (strcmp((char*)module_info.FullPathName, module_name) == 0)
                return uintptr_t(module_info.ImageBase);
        }

        return 0;
    }
    PIMAGE_NT_HEADERS getHeader(PVOID module) {
        return (PIMAGE_NT_HEADERS)((PBYTE)module + PIMAGE_DOS_HEADER(module)->e_lfanew);
    }

    ULONG64 GetModuleBasex64(PEPROCESS proc, UNICODE_STRING module_name, BOOL get_size) {
        PPEB pPeb = (PPEB)PsGetProcessPeb(proc); // get Process PEB, function is unexported and undoc

        if (!pPeb) {
            return 0; // failed
        }

        KAPC_STATE state;

        KeStackAttachProcess(proc, &state);

        PPEB_LDR_DATA pLdr = (PPEB_LDR_DATA)pPeb->Ldr;

        if (!pLdr) {
            KeUnstackDetachProcess(&state);
            return 0; // failed
        }

        UNICODE_STRING name;

        // loop the linked list
        for (PLIST_ENTRY list = (PLIST_ENTRY)pLdr->InLoadOrderModuleList.Flink;
            list != &pLdr->InLoadOrderModuleList; list = (PLIST_ENTRY)list->Flink)
        {
            PLDR_DATA_TABLE_ENTRY pEntry =
                CONTAINING_RECORD(list, LDR_DATA_TABLE_ENTRY, InLoadOrderLinks);

            Printf("Module Name: %wZ\n", pEntry->BaseDllName);
            Printf("Module Base: %p\n", pEntry->DllBase);
            Printf("Module Size: %d\n", pEntry->SizeOfImage);

            if (RtlCompareUnicodeString(&pEntry->BaseDllName, &module_name, TRUE) ==
                0) {
                ULONG64 baseAddr = (ULONG64)pEntry->DllBase;
                ULONG64 moduleSize = (ULONG64)pEntry->SizeOfImage; // get the size of the module
                KeUnstackDetachProcess(&state);
                if (get_size) {
                    return moduleSize; // return the size of the module if get_size is TRUE
                }
                return baseAddr;
            }
        }

        KeUnstackDetachProcess(&state);

        return 0; // failed
    }

    DWORD getoffsets()
    {
        RTL_OSVERSIONINFOW ver = { 0 };
        RtlGetVersion(&ver);

        switch (ver.dwBuildNumber)
        {
        case WINDOWS_1803:
            return 0x0278;
            break;
        case WINDOWS_1809:
            return 0x0278;
            break;
        case WINDOWS_1903:
            return 0x0280;
            break;
        case WINDOWS_1909:
            return 0x0280;
            break;
        case WINDOWS_2004:
            return 0x0388;
            break;
        case WINDOWS_20H2:
            return 0x0388;
            break;
        case WINDOWS_21H1:
            return 0x0388;
            break;
        default:
            return 0x0388;
        }
    }

    auto getprocessdirbase(PEPROCESS targetprocess) -> ULONG_PTR
    {
        if (!targetprocess)
            return 0;

        PUCHAR process = (PUCHAR)targetprocess;
        ULONG_PTR process_dirbase = *(PULONG_PTR)(process + 0x28);
        if (process_dirbase == 0)
        {
            auto userdiroffset = getoffsets();
            ULONG_PTR process_userdirbase = *(PULONG_PTR)(process + userdiroffset);
            return process_userdirbase;
        }
        return process_dirbase;
    }

    PBYTE FindPattern(PVOID module, DWORD size, LPCSTR pattern, LPCSTR mask) {

        auto checkMask = [](PBYTE buffer, LPCSTR pattern, LPCSTR mask) -> BOOL
            {
                for (auto x = buffer; *mask; pattern++, mask++, x++) {
                    auto addr = *(BYTE*)(pattern);
                    if (addr != *x && *mask != '?')
                        return FALSE;
                }

                return TRUE;
            };

        for (auto x = 0; x < size - strlen(mask); x++) {

            auto addr = (PBYTE)module + x;
            if (checkMask(addr, pattern, mask))
                return addr;
        }

        return NULL;
    }

    PBYTE FindPattern(PVOID base, LPCSTR pattern, LPCSTR mask) {

        auto header = getHeader(base);
        auto section = IMAGE_FIRST_SECTION(header);

        for (auto x = 0; x < header->FileHeader.NumberOfSections; x++, section++) {

            /*
            * Avoids non paged memory,
            * As well as greatly speeds up the process of scanning 30+ sections.
            */
            if (!memcmp(section->Name, ".text", 5) || !memcmp(section->Name, "PAGE", 4)) {
                auto addr = FindPattern((PBYTE)base + section->VirtualAddress, section->Misc.VirtualSize, pattern, mask);
                if (addr) {
                    Printf("[mapper] Found in Section -> [ %s ]", section->Name);
                    return addr;
                }
            }
        }

        return NULL;
    }

    NTSTATUS FindProcessByName(const char* process_name, PEPROCESS* process)
    {
        PEPROCESS sys_process = PsInitialSystemProcess;
        PEPROCESS cur_entry = sys_process;

        CHAR image_name[15];

        do
        {
            RtlCopyMemory((PVOID)(&image_name), (PVOID)((uintptr_t)cur_entry + 0x5a8) /*EPROCESS->ImageFileName*/, sizeof(image_name));

            if (strstr(image_name, process_name))
            {
                DWORD active_threads;
                RtlCopyMemory((PVOID)&active_threads, (PVOID)((uintptr_t)cur_entry + 0x5f0) /*EPROCESS->ActiveThreads*/, sizeof(active_threads));
                if (active_threads)
                {
                    *process = cur_entry;
                    return STATUS_SUCCESS;
                }
            }

            PLIST_ENTRY list = (PLIST_ENTRY)((uintptr_t)(cur_entry)+0x448) /*EPROCESS->ActiveProcessLinks*/;
            cur_entry = (PEPROCESS)((uintptr_t)list->Flink - 0x448);

        } while (cur_entry != sys_process);

        return STATUS_NOT_FOUND;
    }

    auto readphysaddress(PVOID address, PVOID buffer, SIZE_T size, SIZE_T* read) -> NTSTATUS
    {
        if (!address)
            return STATUS_UNSUCCESSFUL;

        MM_COPY_ADDRESS addr = { 0 };
        addr.PhysicalAddress.QuadPart = (LONGLONG)address;
        return MmCopyMemory(buffer, addr, size, MM_COPY_MEMORY_PHYSICAL, read);
    }

    auto translateaddress(uint64_t processdirbase, uint64_t address) -> uint64_t
    {
        processdirbase &= ~0xf;

        uint64_t pageoffset = address & ~(~0ul << PAGE_OFFSET_SIZE);
        uint64_t pte = ((address >> 12) & (0x1ffll));
        uint64_t pt = ((address >> 21) & (0x1ffll));
        uint64_t pd = ((address >> 30) & (0x1ffll));
        uint64_t pdp = ((address >> 39) & (0x1ffll));

        SIZE_T readsize = 0;
        uint64_t pdpe = 0;
        readphysaddress((void*)(processdirbase + 8 * pdp), &pdpe, sizeof(pdpe), &readsize);
        if (~pdpe & 1)
            return 0;

        uint64_t pde = 0;
        readphysaddress((void*)((pdpe & mask) + 8 * pd), &pde, sizeof(pde), &readsize);
        if (~pde & 1)
            return 0;

        if (pde & 0x80)
            return (pde & (~0ull << 42 >> 12)) + (address & ~(~0ull << 30));

        uint64_t ptraddr = 0;
        readphysaddress((void*)((pde & mask) + 8 * pt), &ptraddr, sizeof(ptraddr), &readsize);
        if (~ptraddr & 1)
            return 0;

        if (ptraddr & 0x80)
            return (ptraddr & mask) + (address & ~(~0ull << 21));

        address = 0;
        readphysaddress((void*)((ptraddr & mask) + 8 * pte), &address, sizeof(address), &readsize);
        address &= mask;

        if (!address)
            return 0;

        return address + pageoffset;
    }


    auto readprocessmemory(PEPROCESS process, PVOID address, PVOID buffer, SIZE_T size, SIZE_T* read) -> NTSTATUS
    {
        auto process_dirbase = getprocessdirbase(process);

        SIZE_T curoffset = 0;
        while (size)
        {
            auto addr = translateaddress(process_dirbase, (ULONG64)address + curoffset);
            if (!addr) return STATUS_UNSUCCESSFUL;

            ULONG64 readsize = min(PAGE_SIZE - (addr & 0xFFF), size);
            SIZE_T readreturn = 0;
            auto readstatus = readphysaddress((void*)addr, (PVOID)((ULONG64)buffer + curoffset), readsize, &readreturn);
            size -= readreturn;
            curoffset += readreturn;
            if (readstatus != STATUS_SUCCESS) break;
            if (readreturn == 0) break;
        }

        *read = curoffset;
        return STATUS_SUCCESS;
    }
}