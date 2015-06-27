#include "stdafx.h"

#ifndef PEDUMP_H
#define PEDUMP_H

using std::string;

class PEDump{
protected:
	
	PIMAGE_DOS_HEADER dosheader;
	PIMAGE_NT_HEADERS ntheaders;
	
	PIMAGE_DATA_DIRECTORY datadirectory;
	HMODULE hmodule;
	PIMAGE_IMPORT_DESCRIPTOR idesc;
	PIMAGE_OPTIONAL_HEADER opthdr;

public:

	PEDump(HMODULE mod);
	~PEDump();

	PIMAGE_IMPORT_DESCRIPTOR getImportDescriptorFor(char* impdll);
	PDWORD getReferencePointer(char* functionname, char* impdll);
};


#endif