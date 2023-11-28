#pragma once
#include "imports.h"

namespace globals
{
	uintptr_t hook_pointer = 0;
	uintptr_t hook_address = 0;
}

struct _requests
{
	//rw
	uint32_t    src_pid;
	uint64_t    src_addr;
	uint64_t    dst_addr;
	size_t        size;

	//function requests
	int request_key;

	ULONG64 client_base;
};