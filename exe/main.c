#include        "defs.h"

BOOL    inject(__in DWORD       dwPid, __in WCHAR *wsDllPath){
        HANDLE  hProcess;
        PVOID   fnLoadLibrary;
        PVOID   lpDllPath;
        HANDLE  hThread;
        
        hProcess = OpenProcess(PROCESS_ALL_ACCESS, 0, dwPid);
        if (hProcess == NULL) return FALSE;
        fnLoadLibrary = (PVOID)GetProcAddress(GetModuleHandle(L"kernel32.dll"), "LoadLibraryW");
        lpDllPath = VirtualAllocEx(hProcess, 0, 0x1000, MEM_COMMIT, PAGE_READWRITE);
        WriteProcessMemory(hProcess, lpDllPath, wsDllPath, MAX_PATH * sizeof(WCHAR), 0);
        
        hThread = CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)fnLoadLibrary, lpDllPath, 0, NULL);
        WaitForSingleObject(hThread, 200);
        CloseHandle(hThread);
        return TRUE;
}

int __cdecl wmain(int argc, wchar_t **argv){
        PSYSTEM_PROCESS_INFORMATION     pspi, pspi_tmp;
        WCHAR   wsDllPath[MAX_PATH];
        ULONG   cbNeeded;
        BOOLEAN enabled;
        
        if (argc != 2){
                printf("Usage: cfghook <process name>\n");
                return 1;
        }        
        
        RtlAdjustPrivilege(20, TRUE, FALSE, &enabled);
        
        pspi = pspi_tmp = GlobalAlloc(GPTR, 0x100000);
        memset(pspi, 0, 0x100000);
        memset(wsDllPath, 0, sizeof(wsDllPath));
        GetFullPathName(L"inject.dll", MAX_PATH, wsDllPath, NULL);
        
        NtQuerySystemInformation(SystemProcessInformation, pspi, 0x100000, &cbNeeded);
        for (;;){
                if (pspi->ImageName.Buffer == 0) goto __next_pid;
                if (_wcsicmp(pspi->ImageName.Buffer, argv[1])) goto __next_pid;
                if (inject((DWORD)(ULONG_PTR)pspi->UniqueProcessId, wsDllPath)){
                        printf("injected into : %d process name : %S\n", pspi->UniqueProcessId, pspi->ImageName.Buffer);
                }else{
                        printf("failed to inject into : %d process name : %S\n", pspi->UniqueProcessId, pspi->ImageName.Buffer);
                }
                        
__next_pid:
                if (pspi->NextEntryOffset == 0) break;
                pspi = (PSYSTEM_PROCESS_INFORMATION)((ULONG_PTR)pspi + pspi->NextEntryOffset);                
        }
}