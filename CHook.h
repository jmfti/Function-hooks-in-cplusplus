#include "stdafx.h"


#ifndef CHOOK_H
#define CHOOK_H

class CProcessUtils{
public:
	HMODULE GetRemoteModuleHandle(DWORD processid, char* szmodulename);
	DWORD GetProcessIdFromProcName(char* procname);
	MODULEENTRY32 GetRemoteModule(DWORD processid, char* module);
};

class CHook{
protected:
	PVOID target, replacer;

public:
	
	virtual PVOID hook(PVOID tgt, PVOID rep) = 0;
	virtual PVOID unhook() = 0;
	void* getTarget() { return target; };
	void* getReplacer() { return replacer; };
	void setTarget(PVOID tgt) { this->target = tgt; };
	void setReplacer(PVOID rep) { this->replacer = rep; };

};

class CIATHook : public CHook {
private:
	HMODULE moduleimporting;
	MODULEENTRY32 modstruct;
	CProcessUtils utils;
	bool loaded;
	char* szimportsfrom;
	char* szoldfuncname;
public:
	//CIATHook(PVOID rep);
	CIATHook(char* szmodule, PVOID ret);
	CIATHook(char* szmodule, PVOID tgt, PVOID ret);
	//~CIATHook();
	DWORD *IATHook( /*HMODULE hDllWhichImports, */char *DllImportsFrom, char *OldFunctionName );
	bool loadModuleProperties(char* szmodule);
	PVOID hook(PVOID importsfrom, PVOID oldfuncname);
	PVOID unhook();
};

class DetourHook : public CHook {
public:
	
	PVOID hook(PVOID tgt, PVOID rep);
	PVOID unhook();
};

class JMPHook : public CHook {
private:
	int size;
	byte* newregion;
public:
	void setSize(int len) { size = len; };
	JMPHook();
	JMPHook(int funlen);

	PVOID hook(PVOID tgt, PVOID rep);
	PVOID unhook();
};
#endif