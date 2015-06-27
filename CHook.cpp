#include "CHook.h"



DWORD CProcessUtils::GetProcessIdFromProcName(char* procname){
	PROCESSENTRY32 pe;
	HANDLE thSnapshot;
	BOOL retval, ProcFound = false;

	thSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

	if(thSnapshot == INVALID_HANDLE_VALUE) throw std::exception("CreateToolhelp32Snapshot failed");

	pe.dwSize = sizeof(PROCESSENTRY32);

    retval = Process32First(thSnapshot, &pe);

	while(retval)
	{
		
		std::string p = pe.szExeFile;
		if(p.find(procname) != p.npos )
		{
			return pe.th32ProcessID;
		}

		retval    = Process32Next(thSnapshot,&pe);
		pe.dwSize = sizeof(PROCESSENTRY32);
    }

	return 0;
}

HMODULE CProcessUtils::GetRemoteModuleHandle(DWORD processid, char* module){
	int pId = 0;
	if (!processid) pId = GetCurrentProcessId();
	else pId = processid;
	MODULEENTRY32 modEntry;
    HANDLE tlh = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pId);

    modEntry.dwSize = sizeof(MODULEENTRY32);
    Module32First(tlh, &modEntry);

    do
    {
        if(!_stricmp(modEntry.szModule, module))	{
            return modEntry.hModule;
			}
        modEntry.dwSize = sizeof(MODULEENTRY32);
    }
    while(Module32Next(tlh, &modEntry));

    return NULL;
}

MODULEENTRY32 CProcessUtils::GetRemoteModule(DWORD processid, char* module){
	MODULEENTRY32 modEntry;
	int pId = 0;
	if (!processid) pId = GetCurrentProcessId();
	else pId = processid;
    HANDLE tlh = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pId);

    modEntry.dwSize = sizeof(MODULEENTRY32);
    Module32First(tlh, &modEntry);

    do
    {
        if(!_stricmp(modEntry.szModule, module))	{
            return modEntry;
			}
        modEntry.dwSize = sizeof(MODULEENTRY32);
    }
    while(Module32Next(tlh, &modEntry));

	throw std::exception("Module not found");
}

/*CIATHook::CIATHook(PVOID rep){
	this->moduleimporting = 0;
	
	this->replacer = rep;
	this->szimportsfrom = 0;
	this->szoldfuncname = 0;
	this->loadModuleProperties(szmodulename);
}*/

CIATHook::CIATHook(char *szmodulename, PVOID rep){
	
	this->moduleimporting = 0;
	
	this->target = 0;
	this->replacer = rep;
	this->loadModuleProperties(szmodulename);
	this->szimportsfrom = 0;
	this->szoldfuncname = 0;
}



bool CIATHook::loadModuleProperties(char* szmodule){
	try{
		this->modstruct = this->utils.GetRemoteModule(0, szmodule);
	}catch(std::exception e){
		loaded = false;
		return false;
	}
	
	this->moduleimporting = this->modstruct.hModule;
	loaded = true;
	return loaded;
}


DWORD* CIATHook::IATHook( /*HMODULE hDllWhichImports,*/ char *DllImportsFrom, char *OldFunctionName ){
	if (!this->loaded) return 0;
	DWORD dwIndex;
    DWORD dwOffset;
    HMODULE hDllWhichImports = this->moduleimporting;
    PIMAGE_DATA_DIRECTORY pDataDirectory;
    PIMAGE_DOS_HEADER pDosHeader;
    PDWORD pdwIAT;
    PDWORD pdwINT;
    PIMAGE_IMPORT_DESCRIPTOR pImportDescriptor;
    PIMAGE_IMPORT_BY_NAME pImportName;
    PIMAGE_OPTIONAL_HEADER pOptionalHeader;
    PIMAGE_NT_HEADERS pPeHeader;
    PSTR strCurrent;
    //hDllWhichImports = GetModuleHandleA(DllWhichImports);

    if(!hDllWhichImports) return NULL;
          
    pDosHeader = PIMAGE_DOS_HEADER(hDllWhichImports);
    dwOffset = pDosHeader->e_lfanew;
    pPeHeader = PIMAGE_NT_HEADERS(long(hDllWhichImports) + dwOffset);
    pOptionalHeader = &pPeHeader->OptionalHeader;
    pDataDirectory = pOptionalHeader->DataDirectory;
    dwOffset = pDataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
    pImportDescriptor = PIMAGE_IMPORT_DESCRIPTOR(long(hDllWhichImports) + dwOffset);
    for(dwIndex = 0; true; dwIndex++)
    {
        dwOffset = pImportDescriptor[dwIndex].Name;
        if (!dwOffset) return NULL;
        strCurrent = PSTR(long(hDllWhichImports) + dwOffset);

		if(_stricmp( strCurrent, DllImportsFrom) == 0 )
		{
			break;
		}
    }
    dwOffset = pImportDescriptor[dwIndex].FirstThunk;
    pdwIAT = PDWORD(long(hDllWhichImports) + dwOffset);
    dwOffset = pImportDescriptor[dwIndex].OriginalFirstThunk;
    pdwINT = PDWORD(long(hDllWhichImports) + dwOffset);

	for(dwIndex = 0; true; dwIndex++)
    {
        dwOffset = pdwINT[dwIndex];
        if (!dwOffset) return NULL;
        pImportName = PIMAGE_IMPORT_BY_NAME(long(hDllWhichImports) + dwOffset);
        strCurrent = PSTR(pImportName->Name);

		if(_stricmp(strCurrent, OldFunctionName) == 0)
        {
            return &pdwIAT[dwIndex];
        }
    }
    return NULL;
}

PVOID CIATHook::hook(PVOID szimportsfrom, PVOID oldfuncname){
	this->szimportsfrom = (char*) szimportsfrom;
	this->szoldfuncname = (char*) oldfuncname;
	PVOID oldfun = (PVOID) this->IATHook((char*)szimportsfrom, (char*)oldfuncname);
	if (!oldfun) return 0;
	// type(oldfun = void**)
	target = *(PVOID*)oldfun;
	DWORD repfun = (DWORD) replacer;

	
	DWORD oldprotect = 0;
	VirtualProtect(oldfun, sizeof(DWORD), PAGE_EXECUTE_READWRITE, &oldprotect);
	*(DWORD*)oldfun = repfun;
	VirtualProtect(oldfun, sizeof(DWORD), oldprotect, 0);

	return target;

}

PVOID CIATHook::unhook(){
	PVOID tmp;
	tmp = target;
	target = replacer;
	replacer = tmp;
	return hook(this->szimportsfrom, this->szoldfuncname);
}

PVOID DetourHook::hook(PVOID tgt, PVOID rep){
	this->target = tgt;
	this->replacer = rep;
	PVOID detoured = tgt;
	DetourTransactionBegin();
    DetourUpdateThread(GetCurrentThread());
    DetourAttach(&(PVOID&)target, replacer);
	DetourTransactionCommit();

	return target;
}

PVOID DetourHook::unhook(){
	PVOID detoured = target;
	DetourTransactionBegin();
    DetourUpdateThread(GetCurrentThread());
    DetourDetach(&(PVOID&)target, replacer);
    DetourTransactionCommit();
	return replacer;
}

JMPHook::JMPHook(){
	size = 0;
}

JMPHook::JMPHook(int funlen){
	size = funlen;
}


PVOID JMPHook::hook(PVOID tgt, PVOID rep){
	this->target = tgt;
	this->replacer = rep;
	PVOID orig_fn = tgt;
	PVOID dest_fn = rep;
	
	
	newregion = (byte*) VirtualAlloc(0, size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	memcpy(newregion, orig_fn, size);
	int p = memcmp(newregion, orig_fn, size);
	//printf("%d\n", p);

	
	unsigned long oldprotect = 0;
	VirtualProtect(orig_fn, size, PAGE_EXECUTE_READWRITE, &oldprotect);
	__asm{
		mov eax, dword ptr [orig_fn];	//	eax = orig_fn address
		mov ecx, 0xe9;	// ecx = jmp relative
		mov [eax], ecx; // *orig_fn = jmp relative
		mov ecx, dword ptr [dest_fn];	// ecx = dest_fn address
		sub ecx, dword ptr [orig_fn];	// ecx = address(dest_fn) - address(orig_fn)
		sub ecx, 5;
		inc eax;	// eax = orig_fn address + 1
		mov dword ptr [eax], ecx;	// *orig_fn = jmp relative to [dest_fn]
	}
	VirtualProtect(orig_fn, size, oldprotect, &oldprotect);
	VirtualProtect(newregion, size, PAGE_EXECUTE_READ, 0);
	
	FlushInstructionCache(0, orig_fn, size);
	FlushInstructionCache(0, newregion, size);
	
	return (PVOID) newregion;	// address of the copied function

}

PVOID JMPHook::unhook(){
	unsigned long oldprotect = 0;
	VirtualProtect(target, size, PAGE_EXECUTE_READWRITE, &oldprotect);
	memcpy(target, newregion, 5);	// restore the old 5 bytes
	VirtualProtect(target, size, oldprotect, &oldprotect);

	VirtualProtect(newregion, size, PAGE_READWRITE, &oldprotect);
	memset(newregion, 0 , size);	// restore the old 5 bytes
	VirtualProtect(target, size, oldprotect, &oldprotect);

	VirtualFree(newregion, 0, MEM_RELEASE);

	return target;
}