#include        <windows.h>
#include        <stdio.h>

typedef struct _IMAGE_LOAD_CONFIG_DIRECTORY_NEW {
    DWORD   Size;
    DWORD   TimeDateStamp;
    WORD    MajorVersion;
    WORD    MinorVersion;
    DWORD   GlobalFlagsClear;
    DWORD   GlobalFlagsSet;
    DWORD   CriticalSectionDefaultTimeout;
    DWORD   DeCommitFreeBlockThreshold;
    DWORD   DeCommitTotalFreeThreshold;
    DWORD   LockPrefixTable;                // VA
    DWORD   MaximumAllocationSize;
    DWORD   VirtualMemoryThreshold;
    DWORD   ProcessHeapFlags;
    DWORD   ProcessAffinityMask;
    WORD    CSDVersion;
    WORD    Reserved1;
    DWORD   EditList;                       // VA
    DWORD   SecurityCookie;                 // VA
    DWORD   SEHandlerTable;                 // VA
    DWORD   SEHandlerCount;
    DWORD   GuardCFCheckFunctionPointer;    // VA
    DWORD   Reserved2;
    DWORD   GuardCFFunctionTable;           // VA
    DWORD   GuardCFFunctionCount;
    DWORD   GuardFlags;
} IMAGE_LOAD_CONFIG_DIRECTORY_NEW, *PIMAGE_LOAD_CONFIG_DIRECTORY_NEW;