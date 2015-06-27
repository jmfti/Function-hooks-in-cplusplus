#include "iathook.h"



// credits to osGB writers / temp2 for highlighting the func 
DWORD *IATHook( HMODULE hDllWhichImports, char *DllImportsFrom, char *OldFunctionName )
{
	DWORD dwIndex;
    DWORD dwOffset;
    //HMODULE hDllWhichImports;
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