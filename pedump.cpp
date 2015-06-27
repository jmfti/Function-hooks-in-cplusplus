#include "pedump.h"

PEDump::PEDump(HMODULE hmod){
	hmodule = hmod;
	dosheader = PIMAGE_DOS_HEADER(hmod);
	ntheaders = PIMAGE_NT_HEADERS( DWORD(hmod) + dosheader->e_lfanew );
	opthdr = &ntheaders->OptionalHeader;
	datadirectory = opthdr->DataDirectory;

}

PEDump::~PEDump(){

}

PIMAGE_IMPORT_DESCRIPTOR PEDump::getImportDescriptorFor(char* dll){
	PIMAGE_IMPORT_DESCRIPTOR pidesc;
	pidesc = PIMAGE_IMPORT_DESCRIPTOR( DWORD(hmodule) + datadirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress );
	for (int i = 0; ; i++){
		if (!pidesc[i].Name)	// a null structure defines the end of the array
			return 0;
		PSTR strname = PSTR( DWORD(hmodule) + pidesc[i].Name );
		if (_stricmp(strname, dll) == 0)	// if strname == dll case insensitive return reference
			return &pidesc[i];
	}
	return 0;
}

PDWORD PEDump::getReferencePointer(char* functionname, char* dll){
	PIMAGE_IMPORT_DESCRIPTOR pidesc = 0 ;
	pidesc = getImportDescriptorFor(dll);
	if (!pidesc) return 0;	// if null then we didn't locate the dll 

	PIMAGE_IMPORT_BY_NAME* imbyname = 0;
	PIMAGE_THUNK_DATA thunkdata = 0;
	imbyname = ( PIMAGE_IMPORT_BY_NAME* )( DWORD(hmodule) + pidesc->OriginalFirstThunk );	// array of pointers of type IMAGE_IMPORT_BY_NAME
	thunkdata = PIMAGE_THUNK_DATA( DWORD(hmodule) + pidesc->FirstThunk );	// array of IMAGE_THUNK_DATA structures
	

	for (int i = 0; ; i++){
		PIMAGE_IMPORT_BY_NAME p = PIMAGE_IMPORT_BY_NAME( DWORD(hmodule) + DWORD(imbyname[i]) ) ;
		PSTR name = PSTR(p->Name);
		
		if (_stricmp(name, functionname) == 0){		// if name == functionname return the address of that pointer
			return &thunkdata[i].u1.AddressOfData;
		}
	}
	return 0;
}