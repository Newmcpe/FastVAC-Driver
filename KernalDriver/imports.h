#pragma once
#include <cstdint>
#include <ntdef.h>
#include <ntifs.h>
#include <ntddk.h>
#include <windef.h>
#include <ntstrsafe.h>
#include <ntimage.h>

using u8 = unsigned char;
using u16 = unsigned short;
using u32 = unsigned long;
using u64 = unsigned long long;

static const uint64_t mask = (~0xfull << 8) & 0xfffffffffull;
#define PAGE_OFFSET_SIZE 12
#define WINDOWS_1803 17134
#define WINDOWS_1809 17763
#define WINDOWS_1903 18362
#define WINDOWS_1909 18363
#define WINDOWS_2004 19041
#define WINDOWS_20H2 19569
#define WINDOWS_21H1 20180

#define Printf(fmt, ...) DbgPrintEx(0, 0, "[+] " fmt, ##__VA_ARGS__)
#define RVA(addr, size)			((PBYTE)(addr + *(DWORD*)(addr + ((size) - 4)) + size))
#define READVM				0x80000001
#define CLIENT_BASE			0x80000002
#define GET_PROCESS_ID		0x80000003

typedef struct _LDR_DATA_TABLE_ENTRY
{
	LIST_ENTRY InLoadOrderLinks;
	LIST_ENTRY InMemoryOrderLinks;
	LIST_ENTRY InInitializationOrderLinks;
	PVOID DllBase;
	PVOID EntryPoint;
	ULONG SizeOfImage;
	UNICODE_STRING FullDllName;
	UNICODE_STRING BaseDllName;
	ULONG Flags;
	USHORT LoadCount;
	USHORT TlsIndex;
	LIST_ENTRY HashLinks;
	ULONG TimeDateStamp;
} LDR_DATA_TABLE_ENTRY, * PLDR_DATA_TABLE_ENTRY;

typedef struct _PEB_LDR_DATA
{
	ULONG Length;
	UCHAR Initialized;
	PVOID SsHandle;
	LIST_ENTRY InLoadOrderModuleList;
	LIST_ENTRY InMemoryOrderModuleList;
	LIST_ENTRY InInitializationOrderModuleList;
} PEB_LDR_DATA, * PPEB_LDR_DATA;



typedef struct _PEB
{
	UCHAR InheritedAddressSpace;
	UCHAR ReadImageFileExecOptions;
	UCHAR BeingDebugged;
	UCHAR BitField;
	PVOID Mutant;
	PVOID ImageBaseAddress;
	PPEB_LDR_DATA Ldr;
	PVOID ProcessParameters;
	PVOID SubSystemData;
	PVOID ProcessHeap;
	PVOID FastPebLock;
	PVOID AtlThunkSListPtr;
	PVOID IFEOKey;
	PVOID CrossProcessFlags;
	PVOID KernelCallbackTable;
	ULONG SystemReserved;
	ULONG AtlThunkSListPtr32;
	PVOID ApiSetMap;
} PEB, * PPEB;


typedef struct _INFORMATION
{
	int operation;
	uint64_t src_addr;
	uint64_t dst_addr;
	size_t size;
	ULONG64 client_base;
} INFORMATION, * PINFORMATION;


typedef struct _CommunicationDTO
{
	INFORMATION request;
	_int64 mode;	
} CommunicationDTO, *PCommunicationDTO;

typedef struct _HANDLE_TABLE_ENTRY_INFO
{
	ULONG AuditMask;
	ULONG MaxRelativeAccessMask;
} HANDLE_TABLE_ENTRY_INFO, * PHANDLE_TABLE_ENTRY_INFO;


typedef struct _HANDLE_TABLE_ENTRY
{
	union
	{
		INT64 VolatileLowValue;
		INT64 LowValue;
		PHANDLE_TABLE_ENTRY_INFO InfoTable;

		struct
		{
			INT64 Unlocked : 1;
			INT64 RefCnt : 16;
			INT64 Attributes : 3;
			INT64 ObjectPointerBits : 44;
		};

	};

	union
	{
		INT64 HighValue;
		PVOID NextFreeHandleEntry;
		PVOID LeafHandleValue;

		struct
		{
			ULONG GrantedAccessBits : 25;
			ULONG NoRightsUpgrade : 1;
			ULONG Spare : 6;
		};
	};

} HANDLE_TABLE_ENTRY, * PHANDLE_TABLE_ENTRY;

typedef struct _HANDLE_TABLE_FREE_LIST
{
	EX_PUSH_LOCK FreeListLock;
	PHANDLE_TABLE_ENTRY FirstFreeHandleEntry;
	PHANDLE_TABLE_ENTRY LastFreeHandleEntry;
	LONG HandleCount;
	ULONG HighWaterMark;
} HANDLE_TABLE_FREE_LIST, * PHANDLE_TABLE_FREE_LIST;

typedef struct _HANDLE_TABLE
{
	ULONG NextHandleNeedingPool;
	LONG ExtraInfoPages;
	UINT64 TableCode;
	PEPROCESS QuotaProcess;
	LIST_ENTRY HandleTableList;
	ULONG UniqueProcessId;
	ULONG Flags;
	UCHAR StrictFIFO : 1;
	UCHAR EnableHandleExceptions : 1;
	UCHAR Rundown : 1;
	UCHAR Duplicated : 1;
	UCHAR RaiseUMExceptionOnInvalidHandleClose : 4;
	EX_PUSH_LOCK HandleContentionEvent;
	EX_PUSH_LOCK HandleTableLock;
	HANDLE_TABLE_FREE_LIST FreeLists[1];
	UCHAR ActualEntry[32];
	PVOID DebugInfo;
} HANDLE_TABLE, * PHANDLE_TABLE;



//0x20 bytes (sizeof)
typedef struct _POOL_TRACKER_BIG_PAGES
{
	PVOID Va;                                                  //0x0
	ULONG Key;                                                              //0x8
	ULONG Pattern : 8;                                                        //0xc
	ULONG PoolType : 12;                                                      //0xc
	ULONG SlushSize : 12;                                                     //0xc
	ULONGLONG NumberOfBytes;                                                //0x10
	struct _EPROCESS* ProcessBilled;                                        //0x18
} POOL_TRACKER_BIG_PAGES, * PPOOL_TRACKER_BIG_PAGES;


typedef struct _CID_TABLE_HIDDEN_THREAD
{
	HANDLE_TABLE_ENTRY OldEntry;
	void* DummyEThread;
}CID_TABLE_HIDDEN_THREAD, * PCID_TABLE_HIDDEN_THREAD;

typedef PHANDLE_TABLE_ENTRY(*f_ExpLookupHandleTableEntry) (PHANDLE_TABLE HandleTable, HANDLE Handle);

typedef struct _OBJECT_HEADER
{
	__int64 PointerCount;
	__int64 HandleCount;
	EX_PUSH_LOCK Lock;
	char TypeIndex;
	char ___u4;
	char InfoMask;
	char ___u6;
	unsigned int Reserved;
	__int64 ___u8;
	void* SecurityDescriptor;
}OBJECT_HEADER, * POBJECT_HEADER;

extern "C" {
	NTSTATUS ZwQuerySystemInformation(ULONG InfoClass, PVOID Buffer, ULONG Length, PULONG ReturnLength);
	__declspec(dllimport) PPEB PsGetProcessPeb(PEPROCESS);
	NTSYSAPI PIMAGE_NT_HEADERS	NTAPI RtlImageNtHeader(PVOID);
};