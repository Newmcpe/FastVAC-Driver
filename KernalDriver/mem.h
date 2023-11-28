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

	uintptr_t get_module(const char* module_name) noexcept {
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
}