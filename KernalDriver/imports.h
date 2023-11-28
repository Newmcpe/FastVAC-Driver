#pragma once
#include <ntdef.h>
#include <ntifs.h>
#include <ntddk.h>
#include <windef.h>
#include <ntstrsafe.h>
#include <ntimage.h>

#define Printf(...) DbgPrintEx( DPFLTR_SYSTEM_ID, DPFLTR_ERROR_LEVEL, "[+]" __VA_ARGS__ )
#define get_byte( x )    (get_bits(x[0]) << 4 | get_bits(x[1]))
#define get_bits( x )    (in_range((x&(~0x20)),'A','F') ? ((x&(~0x20)) - 'A' + 0xA) : (in_range(x,'0','9') ? x - '0' : 0))
#define in_range(x,a,b)    (x >= a && x <= b) 

#define SPECIAL_CALL 1337

typedef struct _INFORMATION {
	INT key;
	CHAR operation;
	HANDLE process_id;
	PVOID address;
	SIZE_T size;

}INFORMATION, * PINFORMATION;

extern "C" NTSTATUS ZwQuerySystemInformation(ULONG InfoClass, PVOID Buffer, ULONG Length, PULONG ReturnLength);