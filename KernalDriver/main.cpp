
#include "mem.h"
#include "spoofer.h"
#include "cleaning.h"
#include "file.h"
#include "skCrypter.h"

#define PROCESS_NAME skCrypt(R"(r5apex.exe)")
#define COMMUNICATION_FILE_NAME skCrypt(LR"(\DosDevices\C:\Users\Newmcpe\Desktop\mrpenis.log.txt)")

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
	////	SPOOF_FUNC
	PEPROCESS source_process = nullptr;
	NTSTATUS status = mem::FindProcessByName(PROCESS_NAME, &source_process);
	if (status != STATUS_SUCCESS) return false;

	uint64_t base_address;
	size_t memsize = 0;
	mem::get_module_base(source_process, PROCESS_NAME, &base_address, memsize);

	in->client_base = RtlRandomEx(reinterpret_cast<PULONG>(in));

	return true;
}

VOID Communication()
{

	HANDLE hFile = NULL;
	NTSTATUS status;
	IO_STATUS_BLOCK sb;
	UNICODE_STRING unFilePathName;
	OBJECT_ATTRIBUTES object_attr;
	LARGE_INTEGER      byteOffset = RtlConvertLongToLargeInteger(0);

	RtlInitUnicodeString(&unFilePathName, COMMUNICATION_FILE_NAME);
	InitializeObjectAttributes(&object_attr, &unFilePathName,
		NULL,
		NULL, NULL);

	status = ZwCreateFile(&hFile,
		GENERIC_ALL,
		&object_attr,
		&sb,
		NULL,
		FILE_ATTRIBUTE_NORMAL,
		FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
		FILE_OPEN_IF,
		FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_ALERT,
		NULL,
		0
	);
	Printf("ZwCreateFile %x\n", status);

	CommunicationDTO inDto;

	status = ZwReadFile(hFile, nullptr, nullptr, nullptr, &sb, &inDto, sizeof(CommunicationDTO), &byteOffset, nullptr);
	Printf("ZwReadFile %x, mode = %i, requeust = %i\n", status, inDto.mode, inDto.request.operation);

	if(inDto.mode == 2)
	{
		Printf("Skipping...");
		return;
	}

	get_client_address(&inDto.request);
	inDto.mode = 2;

	byteOffset = RtlConvertLongToLargeInteger(0);

	status = ZwWriteFile(hFile, nullptr, nullptr, nullptr, &sb, &inDto, sizeof(CommunicationDTO),& byteOffset, nullptr);
	Printf("ZwWriteFile %x, SB = %x\n", status, sb.Information);

	RtlZeroMemory(&inDto, sizeof(CommunicationDTO));
	ZwClose(hFile);
}

VOID CommunicationThread(PVOID Context)
{
	UNREFERENCED_PARAMETER(Context);

	ULONG Counter = 0;
	//PEPROCESS gameProcess;
	//auto status = mem::FindProcessByName(PROCESS_NAME, &gameProcess);


	while (1)
	{

	Communication();
	}

	//Communication();
	PsTerminateSystemThread(0);
}

NTSTATUS CreateCommunicationThread()
{
	HANDLE hThread = nullptr;

	NTSTATUS Status = PsCreateSystemThread(
		&hThread,
		GENERIC_ALL,
		nullptr,
		nullptr,
		nullptr,
		CommunicationThread,
		nullptr
	);

	if (!NT_SUCCESS(Status))
	{
		Printf("[!] Failed to start thread\n");
		return NULL;
	}

	return STATUS_SUCCESS;
}


extern "C" NTSTATUS CustomEntry(PDRIVER_OBJECT DriverObj, PUNICODE_STRING RegistryPath)
{
	UNREFERENCED_PARAMETER(DriverObj);
	UNREFERENCED_PARAMETER(RegistryPath);

	Printf("Driver Loaded %p\n", DriverObj);

	Cleaning::CreateThreadSpoofed(CreateCommunicationThread);

	return STATUS_SUCCESS;
}
