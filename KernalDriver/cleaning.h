
#include "mem.h"


namespace Cleaning
{
	inline PHANDLE_TABLE* pPspCidTable = nullptr;
	inline f_ExpLookupHandleTableEntry ExpLookupHandleTableEntry = nullptr;

	NTSTATUS NullPageFrameNumbers(uint64_t start, uint32_t size);
	NTSTATUS CleanFromBigPools(uint64_t start);
	HANDLE CreateThreadSpoofed(PVOID StartRoutine);

	template <typename t>
	inline bool valid_ptr(t addr)
	{
		return uintptr_t(addr) && uintptr_t(addr) > 0x1000 && MmIsAddressValid((void*)addr);
	}

	template <typename t = void*>
	inline t resolve_rip(ULONG64 addr, ULONG32 offset)
	{
		return reinterpret_cast<t>(addr + *(UINT32*)(addr + offset) + sizeof(ULONG32) + offset);
	}

	inline UCHAR GetMiscFlagsOffset()
	{
		static UCHAR offset = 0;

		if (!offset)
		{
			auto addr = PUCHAR(&PsIsSystemThread);

			offset = *reinterpret_cast<PUCHAR>(addr + 2);
		}
		return offset;
	}

	inline bool HideThreadPspCidTable(HANDLE Handle, PCID_TABLE_HIDDEN_THREAD Data)
	{
		if (!pPspCidTable || !ExpLookupHandleTableEntry || !Data)
			return false;

		auto Entry = ExpLookupHandleTableEntry(*pPspCidTable, Handle);

		if (!Entry)
			return false;

		PETHREAD dummyThread = nullptr;
		HANDLE DummyThreadId = nullptr;

		for (uintptr_t i = 0x100; i < 0x3000; i += 4)
		{
			if (NT_SUCCESS(PsLookupThreadByThreadId(reinterpret_cast<HANDLE>(i), &dummyThread)))
			{
				ObDereferenceObject(dummyThread);

				if (reinterpret_cast<HANDLE>(i) != reinterpret_cast<HANDLE>(Handle) && PsIsSystemThread(dummyThread))
				{
					DummyThreadId = reinterpret_cast<HANDLE>(i);
					break;
				}
			}

		}

		if (!DummyThreadId)
			return false;

		auto pobject_header = reinterpret_cast<POBJECT_HEADER>(reinterpret_cast<uintptr_t>(dummyThread) - sizeof(OBJECT_HEADER));

		auto pdummy_thread = reinterpret_cast<POBJECT_HEADER>(ExAllocatePoolWithTag(NonPagedPoolNx, 0x1000, 0x65726854));

		if (!pdummy_thread)
			return false;

		memcpy(pdummy_thread, pobject_header, 0x1000);

		pdummy_thread->HandleCount = 6334;
		pdummy_thread->PointerCount = 6334;

		auto Entry2 = ExpLookupHandleTableEntry(*pPspCidTable, DummyThreadId);

		if (!Entry2)
		{
			ExFreePoolWithTag(pdummy_thread, 0x65726854);
			return false;
		}

		HANDLE_TABLE_ENTRY entry = { 0 };

		memcpy(&Data->OldEntry, Entry, sizeof(HANDLE_TABLE_ENTRY));
		memcpy(&entry, Entry2, sizeof(HANDLE_TABLE_ENTRY));

		entry.ObjectPointerBits = (reinterpret_cast<INT64>(pdummy_thread) + sizeof(OBJECT_HEADER)) >> 4;

		// PsIsSystemThread will fail
		{
			auto BitFlag = reinterpret_cast<PDWORD>(PUCHAR(PsGetCurrentThread()) + GetMiscFlagsOffset());
			*BitFlag &= ~(1 << 10);
		}

		memcpy(Entry, &entry, sizeof(HANDLE_TABLE_ENTRY));

		Data->DummyEThread = pdummy_thread;

		return true;
	}
}