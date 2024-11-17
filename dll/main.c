#include        "defs.h"


VOID    __fastcall cfg_hook(__in PVOID lpAddress){
        MEMORY_BASIC_INFORMATION        mbi;
        VirtualQuery(lpAddress, &mbi, sizeof(mbi));
        if (mbi.Type == MEM_IMAGE) return;
        __debugbreak();
        return;
}

VOID    __declspec(naked) cfg_save_regs(){
        __asm{
                push    ecx
                push    edx
                push    eax
                call    cfg_hook
                pop     eax
                pop     edx
                pop     ecx
                ret        
        }
}

VOID    HookCfg(__in WCHAR *wsDllName){
        PIMAGE_DOS_HEADER       pmz;
        PIMAGE_NT_HEADERS       pnt;
        PIMAGE_LOAD_CONFIG_DIRECTORY_NEW        pload;        
        ULONG_PTR               imagebase;
        DWORD                   dwOldProt;
        PVOID                   GuardCFCheckFunctionPointer;
        PUCHAR                  pbuff;
        
        imagebase = (ULONG_PTR)GetModuleHandle(wsDllName);
        if (imagebase == 0) return;
        pmz = (PIMAGE_DOS_HEADER)imagebase;
        pnt = (PIMAGE_NT_HEADERS)(imagebase + pmz->e_lfanew);
        if (pnt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG].VirtualAddress == 0) return;
        pload = (PIMAGE_LOAD_CONFIG_DIRECTORY_NEW)(imagebase + pnt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG].VirtualAddress);
        if (pload->Size < sizeof(IMAGE_LOAD_CONFIG_DIRECTORY_NEW)) return;
        
        GuardCFCheckFunctionPointer = (PVOID)*(ULONG_PTR *)pload->GuardCFCheckFunctionPointer;
        VirtualProtect(GuardCFCheckFunctionPointer, 5, PAGE_EXECUTE_READWRITE, &dwOldProt);
        pbuff = GuardCFCheckFunctionPointer;
        pbuff[0] = 0x68;
        *(DWORD *)&pbuff[1] = (ULONG_PTR)cfg_save_regs;
        pbuff[5] = 0xC3;
        
        VirtualProtect(GuardCFCheckFunctionPointer, 5, dwOldProt, &dwOldProt);                
}

BOOL WINAPI DllMain(
  HINSTANCE hinstDLL,
  DWORD fdwReason,
  LPVOID lpvReserved
){
        if (fdwReason == DLL_PROCESS_ATTACH){
                HookCfg(L"kernel32.dll");
        }
        return TRUE;
}      
        