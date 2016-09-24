// PETest.cpp : 定义控制台应用程序的入口点。
//

#include "stdafx.h"
#include<Windows.h>
#include"detours.h"
typedef int(WINAPI*FUNCMESS)(HWND, LPCSTR, LPCSTR, UINT);
FUNCMESS OLD_MessageBoxA = MessageBoxA;


int __stdcall NEW_MessageBoxA(HWND, LPCSTR, LPCSTR, UINT)
{
	return OLD_MessageBoxA(NULL, "it is func.", "PETest", MB_OK);

}
int _tmain(int argc, _TCHAR* argv[])
{
	DetourRestoreAfterWith();
	DetourTransactionBegin();
	DetourUpdateThread(GetCurrentThread());
	DetourAttach(&(PVOID&)OLD_MessageBoxA, NEW_MessageBoxA);
	DetourTransactionCommit();

	MessageBoxA(NULL,"it is test.","PETest",MB_OK);

	return 0;
}

