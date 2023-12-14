#include "file.h"


NTSTATUS EzWriteFile(IN const char* FileName, IN char* Data, IN SIZE_T Size)
{
	HANDLE hFile = NULL;
	OBJECT_ATTRIBUTES object_attr = { 0 };
	ANSI_STRING anFilePath = { 0 };
	UNICODE_STRING unFilePathName = { 0 };
	NTSTATUS status = 0;
	IO_STATUS_BLOCK sb = { 0 };

	// Open the file
	RtlInitAnsiString(&anFilePath, FileName);
	status = RtlAnsiStringToUnicodeString(&unFilePathName, &anFilePath, TRUE);
	if (!NT_SUCCESS(status))
	{
		return status;
	}
	InitializeObjectAttributes(&object_attr, &unFilePathName, OBJ_CASE_INSENSITIVE, NULL, NULL);
	status = ZwCreateFile(&hFile, GENERIC_ALL, &object_attr, &sb, NULL, FILE_ATTRIBUTE_NORMAL, FILE_SHARE_READ | FILE_SHARE_WRITE,
		FILE_OPEN_IF, FILE_SYNCHRONOUS_IO_NONALERT | FILE_NON_DIRECTORY_FILE, NULL, 0);
	if (!NT_SUCCESS(status))
	{
		return status;
	}
	RtlFreeUnicodeString(&unFilePathName);

	// Write a file
	LARGE_INTEGER Offset = { 0 };
	status = ZwWriteFile(hFile, NULL, NULL, NULL, &sb, (PVOID)Data, Size, &Offset, NULL);
	if (!NT_SUCCESS(status))
	{
		return status;
	}
	return ZwClose(hFile);
}

NTSTATUS EzReadFile(IN const char* FileName, OUT char** Data, OUT SIZE_T* DataSize)
{
	HANDLE hFile = NULL;
	IO_STATUS_BLOCK sb = { 0 };
	NTSTATUS status = 0;
	LARGE_INTEGER Offset = { 0 };
	OBJECT_ATTRIBUTES object_attr = { 0 };
	ANSI_STRING anFilePath = { 0 };
	UNICODE_STRING unFilePathName = { 0 };
	FILE_STANDARD_INFORMATION fsi = { 0 };
	LARGE_INTEGER Size = { 0 };

	// Open the file and get the handle
	RtlInitAnsiString(&anFilePath, FileName);
	status = RtlAnsiStringToUnicodeString(&unFilePathName, &anFilePath, TRUE);
	if (!NT_SUCCESS(status))
	{
		return status;
	}
	
	InitializeObjectAttributes(&object_attr, &unFilePathName, OBJ_CASE_INSENSITIVE, NULL, NULL);
	status = ZwCreateFile(&hFile, GENERIC_READ, &object_attr, &sb, NULL, FILE_ATTRIBUTE_NORMAL, 0,
		FILE_OPEN, FILE_SYNCHRONOUS_IO_NONALERT , NULL, 0);
	RtlFreeUnicodeString(&unFilePathName);
	if (!NT_SUCCESS(status))
	{
		return status;
	}

	// Get the file size
	memset(&sb, 0, sizeof(sb));
	status = ZwQueryInformationFile(hFile, &sb, &fsi, sizeof(FILE_STANDARD_INFORMATION), FileStandardInformation);
	if (!NT_SUCCESS(status))
	{
		ZwClose(hFile);
		return status;
	}
	Size.QuadPart = fsi.EndOfFile.QuadPart;

	// Apply for memory
	*Data = static_cast<char*>(ExAllocatePool(NonPagedPool, Size.QuadPart));
	if (*Data == NULL)
	{
		ZwClose(hFile);
		return STATUS_INSUFFICIENT_RESOURCES;
	}

	// Read the file
	status = ZwReadFile(hFile, NULL, NULL, NULL, &sb, *Data, Size.QuadPart, &Offset, nullptr);
	if (!NT_SUCCESS(status))
	{
		return status;
	}

	*DataSize = Size.QuadPart;
	return ZwClose(hFile);
}

NTSTATUS EzDeleteFile(IN const char* FileName)
{
	HANDLE hFile = NULL;
	IO_STATUS_BLOCK sb = { 0 };
	FILE_DISPOSITION_INFORMATION dinfo = { 0 };
	NTSTATUS status = 0;
	ANSI_STRING anFilePath = { 0 };
	UNICODE_STRING unFilePathName = { 0 };
	OBJECT_ATTRIBUTES object_attr = { 0 };

	// Open the file and get the handle
	RtlInitAnsiString(&anFilePath, FileName);
	status = RtlAnsiStringToUnicodeString(&unFilePathName, &anFilePath, TRUE);
	if (!NT_SUCCESS(status))
	{
		return status;
	}
	InitializeObjectAttributes(&object_attr, &unFilePathName, OBJ_CASE_INSENSITIVE, NULL, NULL);
	status = ZwCreateFile(&hFile, GENERIC_ALL, &object_attr, &sb, NULL, FILE_ATTRIBUTE_NORMAL, FILE_SHARE_READ | FILE_SHARE_WRITE,
		FILE_OPEN, FILE_SYNCHRONOUS_IO_NONALERT | FILE_NON_DIRECTORY_FILE, NULL, 0);
	RtlFreeUnicodeString(&unFilePathName);
	if (!NT_SUCCESS(status))
	{
		return status;
	}

	dinfo.DeleteFile = TRUE;
	status = ZwSetInformationFile(hFile, &sb, &dinfo, sizeof(FILE_DISPOSITION_INFORMATION), FileDispositionInformation);
	if (!NT_SUCCESS(status))
	{
		return status;
	}
	return ZwClose(hFile);
}