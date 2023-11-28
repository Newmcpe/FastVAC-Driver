#include "mem.h"
#include "imports.h"

#define RVA(addr, size)			((PBYTE)(addr + *(DWORD*)(addr + ((size) - 4)) + size))

typedef INT64(__fastcall* fQword)(PVOID);
fQword original_qword;

INT64 __fastcall NtUserGetPointerProprietaryId_hk(PVOID a1) {
	Printf("[+]Function hooked, a1: 0x%llx\n", a1);

	INFORMATION information = *reinterpret_cast<PINFORMATION>(a1);

	Printf("address %d\n", information.key);

	return 0;
}

extern "C" NTSTATUS CustomEntry(PDRIVER_OBJECT DriverObj, PUNICODE_STRING RegistryPath) {
	UNREFERENCED_PARAMETER(DriverObj);
	UNREFERENCED_PARAMETER(RegistryPath);

	Printf("Driver Loaded!\n");

	PEPROCESS gui_process;
	mem::FindProcessByName(R"(explorer.exe)", &gui_process);
	if (!gui_process) {
		Printf("Gui process not found\n");
		return STATUS_FAILED_DRIVER_ENTRY;
	}
	KeAttachProcess(gui_process);

	auto win32k = mem::get_module(R"(\SystemRoot\System32\win32k.sys)");
	if (!win32k) {
		Printf("win32kbase not found\n", win32k);
		return STATUS_FAILED_DRIVER_ENTRY;
	}

	Printf("win32kbase: 0x%p\n", win32k);

	uintptr_t dataPtr = win32k + 0xEC38;
	dataPtr = reinterpret_cast<uintptr_t>(RVA(dataPtr, 7));

	if (!dataPtr) {
		Printf("Error! NtUserGetPointerProprietaryId not found!\n");
		return STATUS_FAILED_DRIVER_ENTRY;
	}

	Printf("dataPtr: 0x%x\n", dataPtr);
	
	original_qword = reinterpret_cast<fQword>(InterlockedExchangePointer(reinterpret_cast<PVOID*>(dataPtr),
		reinterpret_cast<PVOID>(NtUserGetPointerProprietaryId_hk)));
	
	KeDetachProcess();
	ObDereferenceObject(gui_process);

	Printf("HOOKED\n");
	return STATUS_SUCCESS;
}
