#include <ntifs.h>
#include <windef.h>
#include <ntimage.h>

extern "C" {

	NTKERNELAPI PVOID NTAPI 
		PsGetProcessSectionBaseAddress(
			__in PEPROCESS Process
		);

	NTKERNELAPI NTSTATUS NTAPI
		MmCopyVirtualMemory(
			_In_ PEPROCESS FromProcess,
			_In_ CONST VOID* FromAddress,
			_In_ PEPROCESS ToProcess,
			_Out_ PVOID ToAddress,
			_In_ SIZE_T BufferSize,
			_In_ KPROCESSOR_MODE PreviousMode,
			_Out_ PSIZE_T NumberOfBytesCopied
		);

	NTKERNELAPI NTSTATUS NTAPI 
		PsLookupProcessByProcessId(
			_In_ HANDLE    ProcessId,
			_Out_ PEPROCESS* Process
		);

	NTKERNELAPI PLIST_ENTRY NTKERNELAPI 
		PsLoadedModuleList;
}

typedef unsigned int       uint32_t;
typedef unsigned long long uint64_t;

typedef struct _MMPTE_HARDWARE
{
	/* 0x0000 */ unsigned __int64 Valid : 1; /* bit position: 0 */
	/* 0x0000 */ unsigned __int64 Dirty1 : 1; /* bit position: 1 */
	/* 0x0000 */ unsigned __int64 Owner : 1; /* bit position: 2 */
	/* 0x0000 */ unsigned __int64 WriteThrough : 1; /* bit position: 3 */
	/* 0x0000 */ unsigned __int64 CacheDisable : 1; /* bit position: 4 */
	/* 0x0000 */ unsigned __int64 Accessed : 1; /* bit position: 5 */
	/* 0x0000 */ unsigned __int64 Dirty : 1; /* bit position: 6 */
	/* 0x0000 */ unsigned __int64 LargePage : 1; /* bit position: 7 */
	/* 0x0000 */ unsigned __int64 Global : 1; /* bit position: 8 */
	/* 0x0000 */ unsigned __int64 CopyOnWrite : 1; /* bit position: 9 */
	/* 0x0000 */ unsigned __int64 Unused : 1; /* bit position: 10 */
	/* 0x0000 */ unsigned __int64 Write : 1; /* bit position: 11 */
	/* 0x0000 */ unsigned __int64 PageFrameNumber : 36; /* bit position: 12 */
	/* 0x0000 */ unsigned __int64 ReservedForHardware : 4; /* bit position: 48 */
	/* 0x0000 */ unsigned __int64 ReservedForSoftware : 4; /* bit position: 52 */
	/* 0x0000 */ unsigned __int64 WsleAge : 4; /* bit position: 56 */
	/* 0x0000 */ unsigned __int64 WsleProtection : 3; /* bit position: 60 */
	/* 0x0000 */ unsigned __int64 NoExecute : 1; /* bit position: 63 */
} MMPTE_HARDWARE, * PMMPTE_HARDWARE; /* size: 0x0008 */
typedef struct _MMPTE
{
	union
	{
		/* 0x0000 */ unsigned __int64 Long;
		/* 0x0000 */ volatile unsigned __int64 VolatileLong;
		/* 0x0000 */ struct _MMPTE_HARDWARE Hard;
		/* 0x0000 */ typedef struct _MMPTE_PROTOTYPE Proto;
		/* 0x0000 */ typedef struct _MMPTE_SOFTWARE Soft;
		/* 0x0000 */ typedef struct _MMPTE_TIMESTAMP TimeStamp;
		/* 0x0000 */ typedef struct _MMPTE_TRANSITION Trans;
		/* 0x0000 */ typedef struct _MMPTE_SUBSECTION Subsect;
		/* 0x0000 */ typedef struct _MMPTE_LIST List;
	} /* size: 0x0008 */ u;
} MMPTE, * PMMPTE; /* size: 0x0008 */

typedef struct _LDR_SERVICE_TAG_RECORD
{
	struct _LDR_SERVICE_TAG_RECORD* Next;
	ULONG ServiceTag;
} LDR_SERVICE_TAG_RECORD, * PLDR_SERVICE_TAG_RECORD;

typedef struct _LDRP_CSLIST
{
	PSINGLE_LIST_ENTRY Tail;
} LDRP_CSLIST, * PLDRP_CSLIST;

typedef enum _LDR_DDAG_STATE {
	LdrModulesMerged = -5,
	LdrModulesInitError = -4,
	LdrModulesSnapError = -3,
	LdrModulesUnloaded = -2,
	LdrModulesUnloading = -1,
	LdrModulesPlaceHolder = 0,
	LdrModulesMapping = 1,
	LdrModulesMapped = 2,
	LdrModulesWaitingForDependencies = 3,
	LdrModulesSnapping = 4,
	LdrModulesSnapped = 5,
	LdrModulesCondensed = 6,
	LdrModulesReadyToInit = 7,
	LdrModulesInitializing = 8,
	LdrModulesReadyToRun = 9
} LDR_DDAG_STATE;

typedef struct _LDR_DDAG_NODE
{
	LIST_ENTRY Modules;
	PLDR_SERVICE_TAG_RECORD ServiceTagList;
	ULONG LoadCount;
	ULONG LoadWhileUnloadingCount;
	ULONG LowestLink;
	union {
		LDRP_CSLIST Dependencies;
		SINGLE_LIST_ENTRY RemovalLink;
	};
	LDRP_CSLIST IncomingDependencies;
	LDR_DDAG_STATE State;
	SINGLE_LIST_ENTRY CondenseLink;
	ULONG PreorderNumber;
} LDR_DDAG_NODE, * PLDR_DDAG_NODE;

typedef struct _LDR_DEPENDENCY_RECORD
{
	SINGLE_LIST_ENTRY DependencyLink;
	PLDR_DDAG_NODE DependencyNode;
	SINGLE_LIST_ENTRY IncomingDependencyLink;
	PLDR_DDAG_NODE IncomingDependencyNode;
} LDR_DEPENDENCY_RECORD, * PLDR_DEPENDENCY_RECORD;

typedef enum _LDR_DLL_LOAD_REASON {
	LoadReasonStaticDependency,
	LoadReasonStaticForwarderDependency,
	LoadReasonDynamicForwarderDependency,
	LoadReasonDelayloadDependency,
	LoadReasonDynamicLoad,
	LoadReasonAsImageLoad,
	LoadReasonAsDataLoad,
	LoadReasonUnknown = -1
} LDR_DLL_LOAD_REASON,
* PLDR_DLL_LOAD_REASON;

typedef struct _LDR_DATA_TABLE_ENTRY
{
	LIST_ENTRY InLoadOrderLinks;
	LIST_ENTRY InMemoryOrderLinks;
	union {
		LIST_ENTRY InInitializationOrderLinks;
		LIST_ENTRY InProgressLinks;
	};
	PVOID DllBase;
	PVOID EntryPoint;
	ULONG SizeOfImage;
	UNICODE_STRING FullDllName;
	UNICODE_STRING BaseDllName;
	union {
		UCHAR FlagGroup[4];
		ULONG Flags;
		struct
		{
			ULONG PackagedBinary : 1;
			ULONG MarkedForRemoval : 1;
			ULONG ImageDll : 1;
			ULONG LoadNotificationsSent : 1;
			ULONG TelemetryEntryProcessed : 1;
			ULONG ProcessStaticImport : 1;
			ULONG InLegacyLists : 1;
			ULONG InIndexes : 1;
			ULONG ShimDll : 1;
			ULONG InExceptionTable : 1;
			ULONG ReservedFlags1 : 2;
			ULONG LoadInProgress : 1;
			ULONG LoadConfigProcessed : 1;
			ULONG EntryProcessed : 1;
			ULONG ProtectDelayLoad : 1;
			ULONG ReservedFlags3 : 2;
			ULONG DontCallForThreads : 1;
			ULONG ProcessAttachCalled : 1;
			ULONG ProcessAttachFailed : 1;
			ULONG CorDeferredValidate : 1;
			ULONG CorImage : 1;
			ULONG DontRelocate : 1;
			ULONG CorILOnly : 1;
			ULONG ReservedFlags5 : 3;
			ULONG Redirected : 1;
			ULONG ReservedFlags6 : 2;
			ULONG CompatDatabaseProcessed : 1;
		};
	};
	USHORT ObsoleteLoadCount;
	USHORT TlsIndex;
	LIST_ENTRY HashLinks;
	ULONG TimeDateStamp;
	struct _ACTIVATION_CONTEXT* EntryPointActivationContext;
	PVOID Lock;
	PLDR_DDAG_NODE DdagNode;
	LIST_ENTRY NodeModuleLink;
	struct _LDRP_LOAD_CONTEXT* LoadContext;
	PVOID ParentDllBase;
	PVOID SwitchBackContext;
	RTL_BALANCED_NODE BaseAddressIndexNode;
	RTL_BALANCED_NODE MappingInfoIndexNode;
	ULONG_PTR OriginalBase;
	LARGE_INTEGER LoadTime;
	ULONG BaseNameHashValue;
	LDR_DLL_LOAD_REASON LoadReason;
	ULONG ImplicitPathOptions;
	ULONG ReferenceCount;
	ULONG DependentLoadFlags;
} LDR_DATA_TABLE_ENTRY, * PLDR_DATA_TABLE_ENTRY;

typedef INT64(_fastcall* Khg_Function_t)(PVOID, PVOID, PVOID, PVOID, PVOID);

#define MAGICNUMBER 0xDEADC0DE66660000ull
#define COMMUNICATION_KEY (0xDEADBEEF)

enum Request {
	GETBASE = 0,
	READPROCESSMEMORY = 1,
	WRITEPROCESSMEMORY = 2,
	OPENHANDLE = 3,
};

struct Communication {

	Request Request;
	DWORD processID;
	DWORD Reason; // must be 0xDEADBEEF....
	PVOID Outbase; // output image base for process.

	/*
	* READ/WRITE PROCESS MEMORY.
	*/
	PVOID Address;
	PVOID result;
	size_t size;
};

typedef struct
{
	decltype(&ExGetPreviousMode)(ExGetPreviousMode);
	decltype(&DbgPrintEx)(DbgPrintEx);
	decltype(&PsGetProcessSectionBaseAddress)(PsGetProcessSectionBaseAddress);
	decltype(&PsLookupProcessByProcessId)(PsLookupProcessByProcessId);
	decltype(&MmCopyVirtualMemory)(MmCopyVirtualMemory);
	decltype(&IoGetCurrentProcess)(IoGetCurrentProcess);

	Khg_Function_t FunctionOriginal;
	Khg_Function_t FunctionHook;

} ImportsList;

ImportsList* g_Code;
ImportsList* g_Imports = (ImportsList*)MAGICNUMBER;

ULONG64 g_KernelBase = 0;

BOOL CheckMask(PCHAR base, PCHAR pattern, PCHAR mask)
{
	for (; *mask; ++base, ++pattern, ++mask)
	{
		if ('x' == *mask && *base != *pattern)
		{
			return FALSE;
		}
	}

	return TRUE;
}

UINT_PTR FindPattern(PCHAR base, DWORD length, PCHAR pattern, PCHAR mask)
{
	length -= (DWORD)strlen(mask);
	for (DWORD i = 0; i <= length; ++i)
	{
		UINT_PTR addr = UINT_PTR(&base[i]);

		if (CheckMask((PCHAR)addr, pattern, mask))
		{
			return addr;
		}
	}

	return 0;
}

UINT_PTR FindPatternImage(PCHAR base, PCHAR pattern, PCHAR mask)
{
	UINT_PTR match = 0;

	PIMAGE_NT_HEADERS headers = (PIMAGE_NT_HEADERS)(base + ((PIMAGE_DOS_HEADER)base)->e_lfanew);
	PIMAGE_SECTION_HEADER sections = IMAGE_FIRST_SECTION(headers);
	for (DWORD i = 0; i < headers->FileHeader.NumberOfSections; ++i)
	{
		PIMAGE_SECTION_HEADER section = &sections[i];
		if ('EGAP' == *(int*)section->Name || memcmp(section->Name, ".text", 5) == 0)
		{
			match = FindPattern(base + section->VirtualAddress, section->Misc.VirtualSize, pattern, mask);
			if (match)
			{
				break;
			}
		}
	}

	return match;
}

PMMPTE GetPteAddress(PVOID Address)
{
	typedef PMMPTE
	(*MiGetPteAddress_t)(
		PVOID Address
		);

	static auto MiGetPteAddress = reinterpret_cast<MiGetPteAddress_t>(
		FindPatternImage((PCHAR)g_KernelBase,
			(PCHAR)"\x48\xC1\xE9\x09\x48\xB8\x00\x00\x00\x00\x00\x00\x00\x00\x48\x23\xC8\x48\xB8\x00\x00\x00\x00\x00\x00\x00\x00\x48\x03\xC1\xC3",
			(PCHAR)"xxxxxx????????xxxxx????????xxxx"));

	return MiGetPteAddress(Address);
}

PMMPTE GetPdeAddress(PVOID Address)
{
	typedef PMMPTE
	(*MiGetPdeAddress_t)(
		PVOID Address
		);

	static auto MiGetPdeAddress = reinterpret_cast<MiGetPdeAddress_t>(
		FindPatternImage((PCHAR)g_KernelBase,
			(PCHAR)"\x48\xC1\xE9\x12\x81\xE1\x00\x00\x00\x00\x48\xB8\x00\x00\x00\x00\x00\x00\x00\x00\x48\x03\xC1\xC3",
			(PCHAR)"xxxxxx????xx????????xxxx"));

	return MiGetPdeAddress(Address);
}

void MiMakePageValid(PMMPTE PTE)
{
	PTE->u.Hard.Dirty = 1;
	PTE->u.Hard.Accessed = 1;
	PTE->u.Hard.Owner = 0;
	PTE->u.Hard.Write = 1;
	PTE->u.Hard.NoExecute = 0;
	PTE->u.Hard.Valid = 1;
}

PVOID GetModuleBase(LPCWSTR moduleName) {

	UNICODE_STRING pmoduleName{ };
	RtlInitUnicodeString(&pmoduleName, moduleName);

	for (auto entry = PsLoadedModuleList; entry != PsLoadedModuleList->Blink; entry = entry->Flink)
	{
		PLDR_DATA_TABLE_ENTRY Datatable = CONTAINING_RECORD(entry, LDR_DATA_TABLE_ENTRY, InLoadOrderLinks);

		if (Datatable->BaseDllName.Length == pmoduleName.Length && RtlEqualUnicodeString(&Datatable->BaseDllName, &pmoduleName, TRUE)) {
			return Datatable->DllBase;
		}
	}

	return NULL;
}