#include "stdafx.h";

void doHook();
void doHook2();
void testClasses();
int __fastcall callTest(int a, int b, int c, int d);

using std::cout;
using std::endl;

class ReplaceClass{

public:
	ReplaceClass(){
		int b = 0;
	}

	virtual void hkprocessPhase1(int a, char b, int c, int d){
		cout << "ReplaceClass->phase1()" << endl;
	}
};


DWORD jumpfunction;
DWORD origfunction;
DWORD hookfn;

typedef int (*funproto)(DWORD, char*, char*, DWORD);
funproto funhooked;

struct stjmp{
	byte jmp;
	DWORD addr;
};

int funcionprueba(int a, int b){
	for (int i = 0; i < a; i++)
		b += a - i;
	printf("functionprueba called\n");
	return b;
}
void p(){
}

static void __declspec(naked) jump(){
	__asm jmp hookfn;
}

static __declspec(naked) void jumpf(){
}

int __stdcall funcionhook(DWORD a, char* st1, char* st2, DWORD q){
	
	int p = funhooked(0, "testing hook", "testing hook", 0);
	return p;
}

HMODULE GetRemoteModuleHandle(ULONG pId, char* module);

void* __stdcall hookfunction3(PVOID orig_fn, PVOID dest_fn){
	int size = (DWORD)&p - (DWORD) &funcionprueba;
	byte* newregion = (byte*) VirtualAlloc(0, size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	memcpy(newregion, orig_fn, size);
	int p = memcmp(newregion, orig_fn, size);
	printf("%d\n", p);

	
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

void* __stdcall hookfunction2(PVOID orig_fn, PVOID dest_fn){
	/*int size = (DWORD)&p - (DWORD) &funcionprueba;
	byte* newregion = new byte[size];
	memcpy(newregion, orig_fn, size);
	int p = memcmp(newregion, orig_fn, size);
	printf("%d\n", p);*/
	int size = 10; //(DWORD)&p - (DWORD) &funcionprueba;
	unsigned long oldprotect = 0;
	VirtualProtect(orig_fn, size, PAGE_EXECUTE_READWRITE, &oldprotect);
	__asm{
		mov eax, dword ptr [orig_fn];
		mov ecx, 0xe9;
		mov [eax], ecx;
		inc eax;
		mov ecx, dword ptr [dest_fn];
		mov dword ptr [eax], ecx;
	}
	VirtualProtect(orig_fn, size, oldprotect, &oldprotect);
	//FlushInstructionCache(0, orig_fn, size);
	/*p = memcmp(newregion, orig_fn, size);
	printf("%d\n", p);
	byte w = *(byte*) orig_fn;
	DWORD* q = (DWORD*) orig_fn + 1;
	DWORD address = *q;
	int b = 0;*/
	return (PVOID) ((DWORD) orig_fn + 5);
}

void* __stdcall hookfunction(PVOID orig_fn, PVOID dest_fn){
	int size = (DWORD)&p - (DWORD) &funcionprueba;
	
	
	byte* buffer = (byte*) orig_fn;
	unsigned long oldprotect = 0;
	VirtualProtect(buffer, size, PAGE_EXECUTE_READWRITE, &oldprotect);
	*buffer = 0xe9;	// jmp
	buffer++;
	*((DWORD*)buffer) = (int) dest_fn - (int) orig_fn - 5;	// jmp dest_fn
	printf(" orig_fn : %x\tdest_fn : %x", (int) orig_fn, (int) dest_fn);
	VirtualProtect(buffer, size, oldprotect, 0);
	
	FlushInstructionCache(0, orig_fn, size);
	return (PVOID) ((DWORD) orig_fn + 5);
	/*
	


	byte* tbytes = (PBYTE)&funcionprueba;
	
	printf("funcionprueba : %x\t orig_fn : %x\n", &funcionprueba, (DWORD) orig_fn);
	
	printf("funcionhook : %x\t dest_fn : %x\n", &funcionhook, (DWORD) dest_fn);
	jumpfunction = (DWORD) jump; // address of jump
	origfunction = (DWORD) orig_fn; // address of original function (funcionprueba)
	hookfn = (DWORD) dest_fn; // address of destination function (funcionhook)

	printf("size of jumpfunction : %d\n", (DWORD) &jumpf - (DWORD) &jump);
	byte prologue[5];
	memcpy(prologue, orig_fn, 5);	// copy function prologue

	// unprotect region
	DWORD oldprotect = 0;
	DWORD newprotect = PAGE_EXECUTE_READWRITE;
	VirtualProtect(orig_fn, 5, newprotect, &oldprotect);
	memcpy((PVOID)origfunction, (PVOID) jumpfunction, 5); // replace orig_fn prologue with the jump
	VirtualProtect(orig_fn, 5, oldprotect, &newprotect);*/
	
	
}

typedef int (*dllfuncionpruebaproto)(void);
typedef PVOID (*memsetproto)(PVOID, int, int);

memsetproto orig_memset;

void* mymemset(PVOID address, int val, int size){
	printf("memset called\n");
	return orig_memset(address, val, size);
}

void testhooks();


int main (){


	testClasses();

	return 0;

	LoadLibrary("dllprueba.dll");

	dllfuncionpruebaproto exp;
	exp = (dllfuncionpruebaproto) GetProcAddress(GetModuleHandle("dllprueba.dll"), "pruebaFuncionExportada");
	
	PEDump pe = PEDump(GetModuleHandle("dllprueba.dll"));
	DWORD* address = pe.getReferencePointer("memset", "msvcr100.dll");

	
	orig_memset = (memsetproto)*address;
	DWORD oldprotect = 0;
	VirtualProtect(address, sizeof(DWORD), PAGE_EXECUTE_READWRITE, &oldprotect);
	*address = (DWORD)&mymemset;
	VirtualProtect(address, sizeof(DWORD), oldprotect, 0);


	exp();

	/*DWORD* address2 = IATHook(GetModuleHandle("dllprueba.dll"), "msvcr100.dll", "memset");
	printf("%x\t%x\n", *address, *address2);*/

	return 0;

	MessageBox(0, "testing", "testing", MB_OK);
	doHook2();
	MessageBox(0, "testing", "testing", MB_OK);

	return 0;

	testhooks();

	int x = funcionprueba(2,3);
	printf("x : %x\n", x);
	/*byte* region = (byte*) VirtualAlloc(0, (DWORD) &p - (DWORD) &funcionprueba, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	printf("last error : %d", GetLastError());
	memcpy(region, &funcionprueba, (DWORD) &p - (DWORD) &funcionprueba);
	VirtualProtect(region, (DWORD) &p - (DWORD) &funcionprueba, PAGE_EXECUTE_READ, 0);
	funproto funcionprueba2 = (funproto) region;
	funcionprueba2(2, 3);*/
	//DisableThreadLibraryCalls(hDLL);
	/*funhooked = (funproto) &funcionprueba;
    DetourTransactionBegin();
    DetourUpdateThread(GetCurrentThread());
    DetourAttach(&(PVOID&)funhooked, funcionhook);
	DetourTransactionCommit();
	FlushInstructionCache(0, (PVOID) &funcionprueba, (DWORD) &p - (DWORD) &funcionprueba);
	funcionprueba(2,3);

	DetourTransactionBegin();
    DetourUpdateThread(GetCurrentThread());
    DetourDetach(&(PVOID&)funhooked, funcionhook);
	DetourTransactionCommit();*/
	/*funhooked = (funproto) hookfunction3((PVOID) &funcionprueba, (PVOID) &funcionhook);
	funcionprueba(2,3);
	int b = 0;
	HMODULE user32 = GetModuleHandle("user32.dll");


	HMODULE libreria = LoadLibrary("dllprueba.dll");
	dllfuncionpruebaproto exp;
	exp = (dllfuncionpruebaproto) GetProcAddress(libreria, "pruebaFuncionExportada");
	x = GetLastError();
	printf("x : %i\n", x);
	exp();
	
	DWORD* address = IATHook(libreria, "msvcr100.dll", "memset");

	HMODULE msvcr100 = GetModuleHandle("msvcr100.dll");
	HMODULE msvcrt = GetRemoteModuleHandle(GetCurrentProcessId(), "msvcr100.dll");
	memsetproto ormemset = (memsetproto) GetProcAddress(msvcrt, "memset");
	orig_memset = (memsetproto)*address;
	DWORD oldprotect = 0;
	VirtualProtect(address, sizeof(DWORD), PAGE_EXECUTE_READWRITE, &oldprotect);
	*address = (DWORD)&mymemset;
	VirtualProtect(address, sizeof(DWORD), oldprotect, 0);

	exp();

	x = funcionprueba(2,3);
	printf("x : %x\n", x);
	system("pause");
	return 0;*/
}



HMODULE GetRemoteModuleHandle(ULONG pId, char* module)
{

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


void testhooks(){
	JMPHook jmp = JMPHook((DWORD) &p - (DWORD) &funcionprueba);
	
	funcionprueba(2,3);
	funhooked = (funproto) jmp.hook((PVOID) &funcionprueba, (PVOID) &funcionhook);
	funcionprueba(2,3);
	jmp.unhook();
	funcionprueba(2,3);

	int b = 0;

	// suppose that we have library dllprueba.dll loaded into memory
	HMODULE libreria = LoadLibrary("dllprueba.dll");

	// and that this module imports from another DLL the function memset
	// let's get the function for test
	dllfuncionpruebaproto exp = (dllfuncionpruebaproto) GetProcAddress(libreria, "pruebaFuncionExportada");
	// we test, it should work fine
	exp();

	// our memset
	PVOID my_memset = (PVOID) &mymemset;

	CIATHook iat = CIATHook("dllprueba.dll", my_memset);
	orig_memset = (memsetproto) iat.hook("msvcr100.dll", "memset");

	// now it should run our hook
	exp();
	iat.unhook();
	exp();
	b = 0;


	DetourHook detour = DetourHook();
	funcionprueba(2,3);
	funhooked = (funproto) detour.hook(&funcionprueba, &funcionhook);
	funcionprueba(2,3);
	printf("desactivado hook\n");
	detour.unhook();
	funcionprueba(2,3);
	b = 0;


}

__declspec(naked) void jumpMessageBox(){
	__asm{
		mov eax, MessageBoxA;
		add eax, 5;
		jmp [eax];
	}
}


void doHook2(){
	PVOID addrmsgbox = GetProcAddress(GetModuleHandle("user32.dll"), "MessageBoxA");	// get functions address
	DWORD oldprotect = 0;
	byte* newregion = (byte*) VirtualAlloc(0, 10, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);	// alloc new space for the trampoline
	VirtualProtect(addrmsgbox, 5, PAGE_EXECUTE_READWRITE, &oldprotect);	// unprotect prologue
	memcpy( newregion, addrmsgbox, 5);	// copy messagebox's prologue
	// modify MessageBox's prologue
	byte* t = (byte*)addrmsgbox;
	*t = 0xe9; // jmp
	t++;
	*(DWORD*) t = ( (DWORD) funcionhook - (DWORD) t - 4);	//jmp relative to our function

	VirtualProtect(addrmsgbox, 5, oldprotect, &oldprotect); // restore prologues protection

	t = newregion + 5;
	// after the prologue we have to jump to MessageBox address + 5 to skip our jmp
	*t = 0xe9;
	t++;
	*(DWORD*) t = ( (DWORD) addrmsgbox - (DWORD) t + 1);

	VirtualProtect(newregion, 10, PAGE_EXECUTE_READ, 0);	// we have to set protection to PAGE_EXECUTE_READ
	funhooked = (funproto) newregion;		// this is the pointer to function that we will call from hookfunction
}


	/*VirtualProtect( (PVOID) addrmsgbox, 5, PAGE_EXECUTE_READWRITE, &oldprotect);
	byte* t = (byte*) addrmsgbox;*/
	

void doHook(){
	//DWORD address = (DWORD) &MessageBox;
	//byte jmpabsolute = 0xe9;
	
	DWORD addrmsgbox = (DWORD) GetProcAddress(GetModuleHandle("user32.dll"), "MessageBoxA");
	// set a new executable region with enough space to have the prolog and the jmp back, so 5 bytes + jump + 4 bytes = 10 bytes
	byte* newregion = (byte*) VirtualAlloc(0, 100, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	VirtualProtect(newregion, 100, PAGE_READWRITE, 0);
	//printf("getlasterror : %d \n", GetLastError());
	// copy the first 5 bytes, push ebp, mov esp, ebp,...
	memcpy(newregion, &MessageBox, 5);
	// unprotect memory region
	DWORD oldprotection = 0;
	VirtualProtect(&MessageBox, 5, PAGE_EXECUTE_READWRITE, &oldprotection);
	// set the jmp and the address of our hook function
	byte* t = (byte*)&MessageBox;
	*t = 0xe9;	// jmp relative
	t++;
	*(DWORD*) t = ((DWORD) &funcionhook - (DWORD) t - 4 );
	// now we must reprotect 
	VirtualProtect(&MessageBox, 5, oldprotection, &oldprotection);

	// now we must set the jmp into newregion
	t = newregion+5;
	// mov eax, messagebox; add eax, 5; jmp eax
	*t = 0xa1; 
	t++;
	*(DWORD*) t = addrmsgbox; // mov eax, addrmsgbox
	t += 4;
	*t = 0x83;	
	t++;
	*t = 0xc0;	
	t++;
	*t = 0x05;	// add eax, 5
	t++;
	*t = 0xff;	
	t++;
	*t = 0x20;	// jmp dword ptr [eax] 	
	//byte instructions[] = { 0xA1, 0x24, 0x51, 0x19, 0x01, 0x83, 0xC0, 0x05, 0xFF, 0xE0 }; 
	//memcpy(t, instructions, sizeof(instructions));
	printf("%x\t%x\n", (int) t - (int) &MessageBox, (DWORD) &MessageBox);
	printf("%x\t%x\n", (int) &MessageBox - (int) t, (DWORD) &MessageBox);
	printf("%x\t%x\n", (DWORD) &doHook - (DWORD) &jumpMessageBox, (DWORD) &MessageBox);
	//*(DWORD*) t = ( (DWORD) t - (DWORD) &MessageBox );

	funhooked = (funproto) newregion;	// add 5 bytes to original address so we skip the jmp, this will be called from the hook function
	VirtualProtect(newregion, 100, PAGE_EXECUTE_READ, 0);
}


void testClasses(){
	CrappyClass* cc = new CrappyClass();
	CrappyClass* cc2 = new CrappyClass();
	DerivedCrappyClass* dcc = new DerivedCrappyClass();
	callTest(1,2,3,4);

	cc->processIt(1, 2);
	dcc->processIt(1, 2);

	

	ReplaceClass rc = ReplaceClass();
	PDWORD* vtable = (PDWORD*)(cc);
	PDWORD* vtable_replace = (PDWORD*)(&rc);

	cout << std::hex << vtable_replace[0][0] << endl;
	cout << std::hex << vtable[0][1] << endl;
	DWORD oldprotect = 0;
	VirtualProtect(vtable[0], 12, PAGE_READWRITE, &oldprotect);
	vtable[0][1] = vtable_replace[0][0];
	VirtualProtect(vtable[0], 12, oldprotect, 0);
	cout << std::hex << vtable[0][1] << endl;
	cc->processIt(1,2);

	int b = 0;
}

int __fastcall callTest(int a, int b, int c, int d){
	return a+b+c+d;
}