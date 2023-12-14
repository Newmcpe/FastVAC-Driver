#include <thread>

#include "mem.h"
#include "spoofer.h"
#include "cleaning.h"
#include "file.h"
#include "skCrypter.h"

typedef INT64(__fastcall* fQword)(PVOID);
fQword original_qword;

#define PROCESS_NAME skCrypt(R"(cs2.exe)")

auto readvm(PINFORMATION in) -> bool
{
	//	SPOOF_FUNC;
	PEPROCESS source_process;
	NTSTATUS status = mem::FindProcessByName(PROCESS_NAME, &source_process);
	if (status != STATUS_SUCCESS) return false;
	size_t memsize = 0;

	if (!NT_SUCCESS(
		mem::readprocessmemory(source_process, reinterpret_cast<void*>(in->src_addr), reinterpret_cast<void*>(in->
			dst_addr), in->size, &memsize))
		)
		return false;

	ObDereferenceObject(source_process);

	return true;
}

auto get_client_address(PINFORMATION in)
{
	//	SPOOF_FUNC
	PEPROCESS source_process = nullptr;
	NTSTATUS status = mem::FindProcessByName(PROCESS_NAME, &source_process);
	if (status != STATUS_SUCCESS) return false;

	uint64_t base_address;
	size_t memsize = 0;
	mem::get_module_base(source_process, PROCESS_NAME, &base_address, memsize);

	in->client_base = base_address;


	return true;
}

INT64 __fastcall NtUserGetPointerProprietaryId_hk(PVOID a1)
{
	//	SPOOF_FUNC

	if (!a1 || ExGetPreviousMode() != UserMode || !static_cast<PINFORMATION>(a1)->operation) return original_qword(a1);

	PINFORMATION information = static_cast<PINFORMATION>(a1);

	switch (information->operation)
	{
	case READVM:
	{
		readvm(information);
	}
	case CLIENT_BASE:
	{
		get_client_address(information);
	}
	}
	return 0;
}

void DoFuckingWork()
{
	PEPROCESS gui_process;
	mem::FindProcessByName(skCrypt(R"(explorer.exe)"), &gui_process);
	if (!gui_process)return;
	KeAttachProcess(gui_process);

	auto win32k = mem::get_kernel_module(skCrypt(R"(\SystemRoot\System32\win32k.sys)"));
	if (!win32k) return;

	uintptr_t dataPtr = win32k + 0x5824;
	dataPtr = reinterpret_cast<uintptr_t>(RVA(dataPtr, 7));

	if (!dataPtr) return;

	Printf("dataPtr: 0x%x\n", dataPtr);

	original_qword = reinterpret_cast<fQword>(InterlockedExchangePointer(reinterpret_cast<PVOID*>(dataPtr),
		reinterpret_cast<PVOID>(
			NtUserGetPointerProprietaryId_hk)));

	KeDetachProcess();
	ObDereferenceObject(gui_process);
}

typedef struct _REQUEST
{
	int test1;
	int test2;
} TESTREQUEST, * PTESTREQUEST;


extern "C" NTSTATUS CustomEntry(PDRIVER_OBJECT DriverObj, PUNICODE_STRING RegistryPath)
{
	UNREFERENCED_PARAMETER(DriverObj);
	UNREFERENCED_PARAMETER(RegistryPath);

	Printf("Driver Loaded %p\n", DriverObj);

	const auto fileName = LR"(\DosDevices\C:\Users\WDKRemoteUser.newmcpe-virtual\Desktop\mrpenis.log.txt)";

	HANDLE hFile = NULL;
	NTSTATUS status;
	IO_STATUS_BLOCK sb;
	UNICODE_STRING unFilePathName;
	OBJECT_ATTRIBUTES object_attr;
	LARGE_INTEGER      byteOffset;

	RtlInitUnicodeString(&unFilePathName, fileName);
	InitializeObjectAttributes(&object_attr, &unFilePathName,
		OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
		NULL, NULL);

	status = ZwCreateFile(&hFile, GENERIC_WRITE, &object_attr, &sb, NULL, FILE_ATTRIBUTE_NORMAL, 0,
		FILE_OVERWRITE_IF, FILE_SYNCHRONOUS_IO_NONALERT, NULL, 0);

	Printf("ZwCreateFile %x\n", status);

	TESTREQUEST outRequest = TESTREQUEST{

	};

	outRequest.test1 = 1337;
	outRequest.test2 = 228;

	status = ZwWriteFile(hFile, nullptr, nullptr, nullptr, &sb, &outRequest, sizeof(TESTREQUEST), nullptr, nullptr);
	Printf("ZwWriteFile %x\n", status);

	//char inBuffer[sizeof(TESTREQUEST)];
	TESTREQUEST inRequest;
	byteOffset.LowPart = byteOffset.HighPart = 0;
	status = ZwReadFile(hFile, nullptr, nullptr, nullptr, &sb, &inRequest, sizeof(TESTREQUEST), &byteOffset, nullptr);
//	memcpy(&inRequest, inBuffer, sizeof(TESTREQUEST));
	Printf("ZwReadFile %x\n", status);

	Printf("Value #1 %d\n", inRequest.test1);
	Printf("Value #2 %d\n", inRequest.test2);

	ZwClose(hFile);

	return STATUS_SUCCESS;
}
