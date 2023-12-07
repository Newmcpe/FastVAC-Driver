#include "mem.h"
#include "imports.h"

#define RVA(addr, size)			((PBYTE)(addr + *(DWORD*)(addr + ((size) - 4)) + size))

typedef INT64(__fastcall* fQword)(PVOID);
fQword original_qword;

auto readvm(PINFORMATION in) -> bool
{
	Printf("Read opertaion\n");
	PEPROCESS source_process;
	NTSTATUS status = mem::FindProcessByName(R"(cs2.exe)", &source_process);
	if (status != STATUS_SUCCESS)
	{

		Printf("status != STATUS_SUCCESS");
		return false;
	}
	size_t memsize = 0;

	if (!NT_SUCCESS(
		mem::readprocessmemory(source_process, (void*)in->src_addr, (void*)in->dst_addr, in->size, &memsize))) {
		Printf("read failed");
		return false;
	}

	ObDereferenceObject(source_process);

	return true;
}

ULONG64 get_client_address(PINFORMATION in)
{
	PEPROCESS source_process = NULL;
	NTSTATUS status = mem::FindProcessByName(R"(cs2.exe)", &source_process);
	if (status != STATUS_SUCCESS) return 0;
	UNICODE_STRING moduleName;
	RtlInitUnicodeString(&moduleName, L"client.dll");
	ULONG64 base_address = mem::GetModuleBasex64(source_process, moduleName, false);
	return base_address;
}

INT64 __fastcall NtUserGetPointerProprietaryId_hk(PVOID a1)
{
	Printf("Hook called, a1: 0x%llx\n", a1);

	PINFORMATION information = static_cast<PINFORMATION>(a1);
	Printf("Operation = %x\n", information->operation);

	switch (information->operation)
	{
	case READVM:
	{
		readvm(information);
	}
	case CLIENT_BASE:
	{
		ULONG64 base = get_client_address(information);
		information->client_base = base;
		return information->client_base;
	}
	}
	return 0;
}

extern "C" NTSTATUS CustomEntry(PDRIVER_OBJECT DriverObj, PUNICODE_STRING RegistryPath)
{
	UNREFERENCED_PARAMETER(DriverObj);
	UNREFERENCED_PARAMETER(RegistryPath);

	Printf("Driver Loaded!\n");

	PEPROCESS gui_process;
	mem::FindProcessByName(R"(explorer.exe)", &gui_process);
	if (!gui_process)
	{
		Printf("Gui process not found\n");
		return STATUS_FAILED_DRIVER_ENTRY;
	}
	KeAttachProcess(gui_process);

	auto win32k = mem::get_kernel_module(R"(\SystemRoot\System32\win32k.sys)");
	if (!win32k)
	{
		Printf("win32kbase not found\n");
		return STATUS_FAILED_DRIVER_ENTRY;
	}

	Printf("win32kbase: 0x%p\n", win32k);

	uintptr_t dataPtr = win32k + 0xEC38;
	dataPtr = reinterpret_cast<uintptr_t>(RVA(dataPtr, 7));

	if (!dataPtr)
	{
		Printf("Error! NtUserGetPointerProprietaryId not found!\n");
		return STATUS_FAILED_DRIVER_ENTRY;
	}

	Printf("dataPtr: 0x%x\n", dataPtr);

	original_qword = reinterpret_cast<fQword>(InterlockedExchangePointer(reinterpret_cast<PVOID*>(dataPtr),
		reinterpret_cast<PVOID>(
			NtUserGetPointerProprietaryId_hk)));

	KeDetachProcess();
	ObDereferenceObject(gui_process);

	Printf("HOOKED\n");
	return STATUS_SUCCESS;
}
