#include "cleaning.h"
#include "skCrypter.h"
#include "ntddk.h";


NTSTATUS NullPageFrameNumbersFromMdl(PMDL mdl)
{
	PPFN_NUMBER mdl_pages = MmGetMdlPfnArray(mdl);
	if (!mdl_pages) { return STATUS_UNSUCCESSFUL; }

	ULONG mdl_page_count = ADDRESS_AND_SIZE_TO_SPAN_PAGES(MmGetMdlVirtualAddress(mdl), MmGetMdlByteCount(mdl));

	ULONG null_pfn = 0x0;
	MM_COPY_ADDRESS source_address = { 0 };
	source_address.VirtualAddress = &null_pfn;

	for (ULONG i = 0; i < mdl_page_count; i++)
	{
		size_t bytes = 0;
		MmCopyMemory(&mdl_pages[i], source_address, sizeof(ULONG), MM_COPY_MEMORY_VIRTUAL, &bytes);
	}
	return STATUS_SUCCESS;
}

NTSTATUS Cleaning::NullPageFrameNumbers(uint64_t start, uint32_t size)
{
	NTSTATUS status = STATUS_UNSUCCESSFUL;
	PMDL mdl = IoAllocateMdl((PVOID)start, (ULONG)size, FALSE, FALSE, NULL);

	if (!mdl)
	{
		Printf("[mapper] Failed to allocate Mdl\n");
		return status;
	}

	status = NullPageFrameNumbersFromMdl(mdl);

	IoFreeMdl(mdl);

	return status;
}

PVOID resolve_relative_address(PVOID Instruction, ULONG OffsetOffset, ULONG InstructionSize)
//lol paste you got me. IDK the pointers were fucked up somewhere and I'm too lazy to go and manually reread it.
{
	ULONG_PTR Instr = (ULONG_PTR)Instruction;
	LONG RipOffset = *(PLONG)(Instr + OffsetOffset);
	PVOID ResolvedAddr = (PVOID)(Instr + InstructionSize + RipOffset);

	return ResolvedAddr;
}

NTSTATUS Cleaning::CleanFromBigPools(uint64_t start)
{
	u64 ntoskrnl = mem::get_kernel_module(skCrypt("\\SystemRoot\\system32\\ntoskrnl.exe"));

	if (!ntoskrnl)
	{
		Printf("[mapper] Failed to get ntoskrnl.exe base Address!\n");
		return STATUS_UNSUCCESSFUL;
	}
	Printf("[mapper] ntoskrnl.exe -> 0x%p\n", ntoskrnl);

	u64 size = 0;
	auto BigPoolTable_ptr = mem::FindPattern((PVOID)ntoskrnl, size,
		skCrypt("\x48\x8B\x15\x00\x00\x00\x00\x4C\x8B\x0D\x00\x00\x00\x00"),
		skCrypt("xxx????xxx????")
	);
	auto BigPoolTableSize_ptr = mem::FindPattern((PVOID)ntoskrnl, size,
		skCrypt("\x4C\x8B\x0D\x00\x00\x00\x00\x48\x85\xD2"),
		skCrypt("xxx????xxx")
	);


	Printf("BigPoolTable_ptr, %p\n", BigPoolTable_ptr);
	Printf("BigPoolTableSize_ptr, %p\n", BigPoolTableSize_ptr);

	if (!valid_ptr(BigPoolTable_ptr) || !valid_ptr(BigPoolTableSize_ptr)) {
		Printf("Failed to clean BigPoolTable (2).\n");
		return false;
	}

	auto BigPoolTable_size = *resolve_rip<size_t*>((u64)BigPoolTableSize_ptr, 3);

	Printf("BigPoolTable length: 0x%d\n", BigPoolTable_size);

	auto BigPoolTable = *resolve_rip<_POOL_TRACKER_BIG_PAGES**>((u64)BigPoolTable_ptr, 3);

	if (!valid_ptr(BigPoolTable)) {
		Printf("BigPoolTable invalid\n");
		return STATUS_UNSUCCESSFUL;
	}

	bool found_at_least_one = false;

	for (size_t i = 0; i < BigPoolTable_size; i++) {
		_POOL_TRACKER_BIG_PAGES* entry = &BigPoolTable[i];

		if (entry->Va == reinterpret_cast<void*>(start) || entry->Va == reinterpret_cast<void*>(start + 0x1))
		{
			entry->Va = reinterpret_cast<void*>(0x1);
			entry->NumberOfBytes = 0x0;

			found_at_least_one = true;
		}
	}

	if (found_at_least_one) {
		Printf("Cleaned BigPoolTable.\n");

	}
	else
		Printf("Failed to clean BigPoolTable (4).\n");


	return STATUS_SUCCESS;
}

SIZE_T StartAddress = NULL;

HANDLE Cleaning::CreateThreadSpoofed(PVOID StartRoutine)
{
	if (!StartRoutine) return NULL;

	if (!StartAddress)
	{
		LARGE_INTEGER li{ };
		KeQueryTickCount(&li);
		const auto val = 1 + (RtlRandomEx(&li.LowPart) % INT_MAX);

		if (val % 2)
			StartAddress = mem::FindPattern(skCrypt("\\SystemRoot\\system32\\ntoskrnl.exe"), skCrypt("PAGE"), PBYTE("\xFF\xE1"), skCrypt("xx"));
		else
			StartAddress = mem::FindPattern(skCrypt("\\SystemRoot\\system32\\ntoskrnl.exe"), skCrypt(".text"), PBYTE("\xFF\xE1"), skCrypt("xx"));
	}

	if (!StartAddress)
	{
		Printf("Failed to find a address to spoof thread!\n");
		return NULL;
	}

	HANDLE hThread = nullptr;
	auto status = PsCreateSystemThread(&hThread, GENERIC_ALL, nullptr, nullptr, nullptr, PKSTART_ROUTINE(StartAddress), StartRoutine);
	return status ? hThread : NULL;
}