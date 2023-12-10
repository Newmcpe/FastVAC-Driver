#pragma once
#pragma warning(disable:4595)
#pragma warning(default:4595)

#include "imports.h"
#include <memory>

#define to_lowers(c_char) ((c_char >= 'A' && c_char <= 'Z') ? (c_char + 32) : c_char)

inline void* operator new(std::size_t count)
{
	return ExAllocatePool(PagedPool, count);
}

inline void* operator new[](std::size_t count)
{
	return ExAllocatePool(PagedPool, count);
}

inline void operator delete(void* ptr)
{
	ExFreePoolWithTag(ptr, 0);
}

inline void operator delete[](void* ptr)
{
	ExFreePoolWithTag(ptr, 0);
}

inline void operator delete(void* ptr, std::size_t sz)
{
	UNREFERENCED_PARAMETER(sz);
	ExFreePoolWithTag(ptr, 0);
}


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
	} SYSTEM_MODULE, *PSYSTEM_MODULE;

	typedef struct _SYSTEM_MODULE_INFORMATION
	{
		ULONG NumberOfModules;
		SYSTEM_MODULE Modules[1];
	} SYSTEM_MODULE_INFORMATION, *PSYSTEM_MODULE_INFORMATION;

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
	  *PSYSTEM_INFORMATION_CLASS;
}

namespace mem
{
	template <typename T>
	inline std::unique_ptr<T> query_system_info(nt::SYSTEM_INFORMATION_CLASS info_class,
	                                            uintptr_t size = 0x1000) noexcept
	{
		ULONG buffer_size = static_cast<ULONG>(size);
		auto system_info_buffer = std::unique_ptr<T>(reinterpret_cast<T*>(new uint8_t[buffer_size]));

		auto status = ZwQuerySystemInformation(info_class, system_info_buffer.get(), buffer_size, &buffer_size);

		while (status == 0xC0000004)
		{
			system_info_buffer = std::unique_ptr<T>(reinterpret_cast<T*>(new uint8_t[buffer_size]));
			status = ZwQuerySystemInformation(info_class, system_info_buffer.get(), buffer_size, &buffer_size);

			if (!NT_SUCCESS(status) && (buffer_size == 0x100000 || buffer_size == size))
				break;
		}

		if (!NT_SUCCESS(status))
			return nullptr;

		return system_info_buffer;
	}

	uintptr_t get_kernel_module(const char* module_name) noexcept
	{
		const auto system_module_info = query_system_info<nt::SYSTEM_MODULE_INFORMATION>(nt::SystemModuleInformation);

		if (!system_module_info)
			return 0;

		for (auto i = 0ul; i != system_module_info->NumberOfModules; ++i)
		{
			const auto& module_info = system_module_info->Modules[i];

			//Printf("module: %s\n", module_info.FullPathName);

			if (strcmp((char*)module_info.FullPathName, module_name) == 0)
				return uintptr_t(module_info.ImageBase);
		}

		return 0;
	}

	PIMAGE_NT_HEADERS getHeader(PVOID module)
	{
		return reinterpret_cast<PIMAGE_NT_HEADERS>(static_cast<PBYTE>(module) + static_cast<PIMAGE_DOS_HEADER>(module)->
			e_lfanew);
	}

	DWORD getoffsets()
	{
		RTL_OSVERSIONINFOW ver = {0};
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

	PBYTE FindPattern(PVOID module, DWORD size, LPCSTR pattern, LPCSTR mask)
	{
		auto checkMask = [](PBYTE buffer, LPCSTR pattern, LPCSTR mask) -> BOOL
		{
			for (auto x = buffer; *mask; pattern++, mask++, x++)
			{
				auto addr = *(BYTE*)(pattern);
				if (addr != *x && *mask != '?')
					return FALSE;
			}

			return TRUE;
		};

		for (auto x = 0; x < size - strlen(mask); x++)
		{
			auto addr = (PBYTE)module + x;
			if (checkMask(addr, pattern, mask))
				return addr;
		}

		return NULL;
	}

	PBYTE FindPattern(PVOID base, LPCSTR pattern, LPCSTR mask)
	{
		auto header = getHeader(base);
		auto section = IMAGE_FIRST_SECTION(header);

		for (auto x = 0; x < header->FileHeader.NumberOfSections; x++, section++)
		{
			/*
			* Avoids non paged memory,
			* As well as greatly speeds up the process of scanning 30+ sections.
			*/
			if (!memcmp(section->Name, ".text", 5) || !memcmp(section->Name, "PAGE", 4))
			{
				auto addr = FindPattern((PBYTE)base + section->VirtualAddress, section->Misc.VirtualSize, pattern,
				                        mask);
				if (addr)
				{
					//     Printf("[mapper] Found in Section -> [ %s ]", section->Name);
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
			RtlCopyMemory((PVOID)(&image_name), (PVOID)((uintptr_t)cur_entry + 0x5a8) /*EPROCESS->ImageFileName*/,
			              sizeof(image_name));

			if (strstr(image_name, process_name))
			{
				DWORD active_threads;
				RtlCopyMemory((PVOID)&active_threads, (PVOID)((uintptr_t)cur_entry + 0x5f0) /*EPROCESS->ActiveThreads*/,
				              sizeof(active_threads));
				if (active_threads)
				{
					*process = cur_entry;
					return STATUS_SUCCESS;
				}
			}

			PLIST_ENTRY list = (PLIST_ENTRY)((uintptr_t)(cur_entry) + 0x448) /*EPROCESS->ActiveProcessLinks*/;
			cur_entry = (PEPROCESS)((uintptr_t)list->Flink - 0x448);
		}
		while (cur_entry != sys_process);

		return STATUS_NOT_FOUND;
	}

	auto readphysaddress(PVOID address, PVOID buffer, SIZE_T size, SIZE_T* read) -> NTSTATUS
	{
		if (!address)
			return STATUS_UNSUCCESSFUL;

		MM_COPY_ADDRESS addr = {0};
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


	template <typename str_type, typename str_type_2>
	inline bool cstrcmp(str_type str, str_type_2 in_str, bool two)
	{
		if (!str || !in_str)
			return false;

		wchar_t c1, c2;
		do
		{
			c1 = *str++;
			c2 = *in_str++;
			c1 = to_lowers(c1);
			c2 = to_lowers(c2);

			if (!c1 && (two ? !c2 : 1))
				return true;
		}
		while (c1 == c2);

		return false;
	}


	inline NTSTATUS get_module_base(PEPROCESS process, const char* module_name, uint64_t* allocated_buffer,
	                                SIZE_T readed)
	{
		NTSTATUS status = STATUS_INVALID_PARAMETER;

		if (!process)
			return status;

		PVOID peb_addr = PsGetProcessPeb(process);

		if (!peb_addr)
			return status;

		PEB peb = {NULL};
		status = readprocessmemory(process, peb_addr, &peb, sizeof(PEB), &readed);
		if (!NT_SUCCESS(status))
			return status;

		PEB_LDR_DATA peb_ldr_data = {NULL};
		status = readprocessmemory(process, (PVOID)peb.Ldr, &peb_ldr_data, sizeof(PEB_LDR_DATA), &readed);
		if (!NT_SUCCESS(status))
			return status;

		LIST_ENTRY* ldr_list_head = (LIST_ENTRY*)peb_ldr_data.InLoadOrderModuleList.Flink;
		LIST_ENTRY* ldr_current_node = peb_ldr_data.InLoadOrderModuleList.Flink;

		do
		{
			LDR_DATA_TABLE_ENTRY lst_entry = {NULL};
			status = readprocessmemory(process, (PVOID)ldr_current_node, &lst_entry, sizeof(LDR_DATA_TABLE_ENTRY),
			                           &readed);
			if (!NT_SUCCESS(status))
				return status;

			ldr_current_node = lst_entry.InLoadOrderLinks.Flink;

			if (lst_entry.BaseDllName.Length > NULL)
			{
				WCHAR str_base_dll_name[MAX_PATH] = {NULL};
				status = readprocessmemory(process, (PVOID)lst_entry.BaseDllName.Buffer, &str_base_dll_name,
				                           lst_entry.BaseDllName.Length, &readed);
				if (!NT_SUCCESS(status))
					return status;

				if (cstrcmp(str_base_dll_name, module_name, true))
				{
					if (lst_entry.DllBase != nullptr && lst_entry.SizeOfImage != NULL)
					{
						*allocated_buffer = (uint64_t)lst_entry.DllBase;
						status = STATUS_SUCCESS;
						break;
					}
				}
			}
		}
		while (ldr_list_head != ldr_current_node);

		return status;
	}
}
