// PELoader.cpp : 定义控制台应用程序的入口点。
//

#include "stdafx.h"
#include<Windows.h>
#include "Shlwapi.h"
#include<DbgHelp.h>
#include"detours.h"
#include<muiload.h>

#define NOTEPAD
#ifdef NOTEPAD
#define EXE_FILE_PATH "C:\\Windows\\SysWOW64\\notepad.exe"
#define EXE_FILE_NAME "notepad.exe"
#define MUI_FILE_PATH "C:\\Windows\\SysWOW64\\zh-CN\\notepad.exe.mui"
#define MUI_FILE_NAME "C:\Windows\SysWOW64\zh-CN\notepad.exe.mui"
#endif // NOTEPAD

#ifndef NOTEPAD
//#define EXE_FILE_PATH "d:\\PEview.exe"
//#define EXE_FILE_PATH "C:\\Windows\\SysWOW64\\cmd.exe"
#define EXE_FILE_PATH "C:\\Users\\AVATAR\\Documents\\Visual Studio 2013\\Projects\\PELoader\\Debug\\PETest.exe"
#endif // !NOTEPAD


typedef int (WINAPI *MAIN)(HINSTANCE, HINSTANCE, LPSTR, int);
MAIN ptrMain = NULL;
typedef DWORD(WINAPI *pfnFormatMessageA)(
	__in          DWORD dwFlags,
	__in          LPCVOID lpSource,
	__in          DWORD dwMessageId,
	__in          DWORD dwLanguageId,
	__out         LPSTR lpBuffer,
	__in          DWORD nSize,
	__in          va_list* Arguments
	);

typedef DWORD(WINAPI *pfnFormatMessageW)(
	__in          DWORD dwFlags,
	__in          LPCVOID lpSource,
	__in          DWORD dwMessageId,
	__in          DWORD dwLanguageId,
	__out         LPWSTR lpBuffer,
	__in          DWORD nSize,
	__in          va_list* Arguments
	);
typedef int (WINAPI *pfnLoadStringA)(
	__in_opt HINSTANCE hInstance,
	__in UINT uID,
	__out_ecount(cchBufferMax) LPSTR lpBuffer,
	__in int nBufferMax);
typedef int (WINAPI *pfnLoadStringW)(
	__in_opt HINSTANCE hInstance,
	__in UINT uID,
	__out_ecount(cchBufferMax) LPTSTR lpBuffer,
	__in int nBufferMax);

static HINSTANCE ghMuiLoad = NULL;
pfnFormatMessageA OldFormatMessageA = NULL;
pfnFormatMessageW OldFormatMessageW = NULL;
pfnLoadStringA OldLoadStringA = NULL;
pfnLoadStringW OldLoadStringW = NULL;
DWORD WINAPI RunPE(LPVOID lpParam)
{
	DWORD dwError = 0x8691 + (DWORD)lpParam;
	if (ptrMain!=NULL)
	{
		ptrMain((HINSTANCE)lpParam, NULL, "", 0xa);
	}
	return 0;
} 

LPVOID InitPE(LPSTR szPEPath)
{
	LPVOID lpDsk;
	FILE *fp = fopen(szPEPath,"rb");
	if (fp == NULL)
	{
		return NULL;
	}
	fseek(fp,0,SEEK_END);
	DWORD dwPESize = ftell(fp); 
	fseek(fp, 0, SEEK_SET);
	lpDsk = malloc(dwPESize);
	fread(lpDsk, dwPESize, 1, fp);
	fclose(fp);
	return lpDsk;
}


DWORD
WINAPI
FakeFormatMessageA(
__in          DWORD dwFlags,
__in          LPCVOID lpSource,
__in          DWORD dwMessageId,
__in          DWORD dwLanguageId,
__out         LPSTR lpBuffer,
__in          DWORD nSize,
__in          va_list* Arguments
)
{
	LPCVOID lpNewSource = lpSource;

	if (lpSource == NULL && dwFlags & FORMAT_MESSAGE_FROM_HMODULE && ghMuiLoad)
	{
		lpNewSource = ghMuiLoad;
	}

	return OldFormatMessageA(dwFlags,
		lpNewSource,
		dwMessageId,
		dwLanguageId,
		lpBuffer,
		nSize,
		Arguments
		);

}
DWORD
WINAPI
FakeFormatMessageW(
__in          DWORD dwFlags,
__in          LPCVOID lpSource,
__in          DWORD dwMessageId,
__in          DWORD dwLanguageId,
__out         LPWSTR lpBuffer,
__in          DWORD nSize,
__in          va_list* Arguments
)
{
	LPCVOID lpNewSource = lpSource;

	if (lpSource == NULL && dwFlags & FORMAT_MESSAGE_FROM_HMODULE && ghMuiLoad)
	{
		lpNewSource = ghMuiLoad;
	}

	return OldFormatMessageW(dwFlags,
		lpNewSource,
		dwMessageId,
		dwLanguageId,
		lpBuffer,
		nSize,
		Arguments
		);
}


int WINAPI FakeLoadStringA(
	__in_opt HINSTANCE hInstance,
	__in UINT uID,
	__out_ecount(cchBufferMax) LPSTR lpBuffer,
	__in int nBufferMax)
{
	DWORD dwNum = OldLoadStringA(hInstance, uID, lpBuffer, nBufferMax);
	if (dwNum == 0)
	{
		if (ghMuiLoad != NULL)
		{
			dwNum = OldLoadStringA(ghMuiLoad, uID, lpBuffer, nBufferMax);
		}		
	}
	return dwNum;
}

int WINAPI FakeLoadStringW(
	__in_opt HINSTANCE hInstance,
	__in UINT uID,
	__out_ecount(cchBufferMax) LPTSTR lpBuffer,
	__in int nBufferMax)
{
	DWORD dwNum = OldLoadStringW(hInstance, uID, lpBuffer, nBufferMax);
	if (dwNum == 0)
	{
		if (ghMuiLoad != NULL)
		{

			dwNum = OldLoadStringW(LoadMUILibraryW(_T(MUI_FILE_PATH), MUI_LANGUAGE_NAME, LOCALE_SYSTEM_DEFAULT), uID, lpBuffer, nBufferMax);
		}
	}
	return dwNum;
}

void APIHook()
{
	OldFormatMessageA = FormatMessageA;
	OldFormatMessageW = FormatMessageW;
	DetourRestoreAfterWith();
	DetourTransactionBegin();
	DetourUpdateThread(GetCurrentThread());


	DetourAttach(&(PVOID&)OldFormatMessageA, FakeFormatMessageA);
	DetourAttach(&(PVOID&)OldFormatMessageW, FakeFormatMessageW);
	//DetourAttach(&(PVOID&)OldLoadStringA, FakeLoadStringA);
	//DetourAttach(&(PVOID&)OldLoadStringW, FakeLoadStringW);

	DetourTransactionCommit();
}

BOOL cal_import(DWORD  dwImpRVA, BYTE* pMemMap)
{
	IMAGE_IMPORT_DESCRIPTOR * pIMP = (IMAGE_IMPORT_DESCRIPTOR *)(pMemMap + dwImpRVA);

	while (true)
	{
		if (pIMP->Name == NULL)
		{
			break;
		}
		DWORD dwINTRVA = pIMP->OriginalFirstThunk;
		DWORD dwNameRVA = pIMP->Name;
		DWORD dwIATRVA = pIMP->FirstThunk;
		LPSTR szDllName = (LPSTR)(pMemMap + dwNameRVA);
		HMODULE hmDll = LoadLibraryA(szDllName);
		DWORD * pIAT = (DWORD*)(pMemMap + dwIATRVA);
		while (true)
		{
			if (*pIAT == 0)
			{
				break;
			}
			DWORD dwIATMARK = (DWORD)(*pIAT + pMemMap + 2);

			if ((dwIATMARK & IMAGE_ORDINAL_FLAG) != 0)
			{
				dwIATMARK = dwIATMARK & 0xffff;
				*pIAT = (DWORD)GetProcAddress(hmDll, (LPSTR)dwIATMARK);
			}
			else
			{
				LPSTR szFuncName = (LPSTR)dwIATMARK;
				*pIAT = (DWORD)GetProcAddress(hmDll, szFuncName);
				if (strcmp(szFuncName, "FormatMessageA") == 0)
				{
					OldFormatMessageA = FormatMessageA;
					*pIAT = (DWORD)FakeFormatMessageA;
				}
				if (strcmp(szFuncName, "FormatMessageW") == 0)
				{
					OldFormatMessageW = FormatMessageW;
					*pIAT = (DWORD)FakeFormatMessageW;
				}
				if (strcmp(szFuncName,"LoadStringA") == 0)
				{
					OldLoadStringA = LoadStringA;
					*pIAT = (DWORD)FakeLoadStringA;
				}
				if (strcmp(szFuncName, "LoadStringW") == 0)
				{
					OldLoadStringW = LoadStringW;
					*pIAT = (DWORD)FakeLoadStringW;
				}
			}
			pIAT++;
		}
		pIMP++;
	}
	return TRUE;
}

BOOL cal_reloc(IMAGE_NT_HEADERS * pImgNtHdr,BYTE* pMemMap)
{
	int i = 0;
	if (pMemMap != (LPVOID)pImgNtHdr->OptionalHeader.ImageBase)
	{
		BYTE * RelocMem = NULL;
		RelocMem = pMemMap + pImgNtHdr->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress;
		if (RelocMem == NULL)
		{
			return FALSE;
		}
		DWORD  dwRelocValue = (DWORD)pMemMap - pImgNtHdr->OptionalHeader.ImageBase;
		DWORD dwRelocIndex = 0;
		while (true)
		{
			DWORD RvaOfBlock = *(DWORD*)&RelocMem[dwRelocIndex];
			if (RvaOfBlock == 0)
			{
				break;
			}
			dwRelocIndex += 4;
			DWORD SizeOfBlock = *(DWORD*)&RelocMem[dwRelocIndex] / 2 - 4;
			dwRelocIndex += 4;
			for (i = 0; i<SizeOfBlock; i++)
			{
				short TypeRVA = *(short*)&RelocMem[dwRelocIndex];
				dwRelocIndex += 2;
				TypeRVA = TypeRVA & 0xfff;
				if (TypeRVA != 0)
				{
					*(DWORD*)(pMemMap + TypeRVA + RvaOfBlock) += dwRelocValue;
				}
			}
		}
	}

}

BOOL MemoryLoader(LPVOID lpBuff)
{
	BYTE * pMem = (BYTE*)lpBuff;
	if (pMem == NULL)
	{
		return FALSE;
	}
	DWORD dwIgnore;
	
	IMAGE_DOS_HEADER ImgDosHdr = { 0 };
	IMAGE_NT_HEADERS ImgNtHdr = { 0 };
	IMAGE_SECTION_HEADER * ImgSecHdrList = NULL;
	memcpy(&ImgDosHdr, pMem, sizeof(IMAGE_DOS_HEADER));
	memcpy(&ImgNtHdr, pMem + ImgDosHdr.e_lfanew, sizeof(IMAGE_NT_HEADERS));
	if (ImgDosHdr.e_magic != 0x5a4d)
	{
		return FALSE;
	}
	if (ImgNtHdr.Signature != 0x4550)
	{
		return FALSE;
	}
	BYTE* pMemMap = NULL;
	pMemMap = (BYTE*)VirtualAlloc((LPVOID)ImgNtHdr.OptionalHeader.ImageBase, ImgNtHdr.OptionalHeader.SizeOfImage, MEM_COMMIT, PAGE_READWRITE);
	if (pMemMap == NULL)
	{
		pMemMap = (BYTE*)VirtualAlloc(NULL, ImgNtHdr.OptionalHeader.SizeOfImage, MEM_COMMIT, PAGE_READWRITE);
	}
	VirtualProtect(pMemMap, ImgNtHdr.OptionalHeader.SizeOfImage, PAGE_EXECUTE_READWRITE, &dwIgnore);

	memcpy(pMemMap, pMem, ImgNtHdr.OptionalHeader.SizeOfHeaders);
	DWORD dwSecHdrsSize = ImgNtHdr.FileHeader.NumberOfSections*sizeof(IMAGE_SECTION_HEADER);
	ImgSecHdrList = (IMAGE_SECTION_HEADER*)VirtualAlloc(NULL, dwSecHdrsSize, MEM_COMMIT, PAGE_READWRITE);
	if (ImgSecHdrList == NULL)
	{
		return FALSE;
	}
	memcpy(ImgSecHdrList, pMem + ImgDosHdr.e_lfanew + sizeof(IMAGE_NT_HEADERS), dwSecHdrsSize);
	DWORD dwRelocIndex = -1;
	int i = 0,j = 0;
	for (i = 0; i < ImgNtHdr.FileHeader.NumberOfSections; i++)
	{
		IMAGE_SECTION_HEADER sec = ImgSecHdrList[i];
		DWORD rva = sec.VirtualAddress;
		
		if (sec.PointerToRawData == NULL)
		{
			
		}
		else
		{
			memcpy(pMemMap + rva, pMem + sec.PointerToRawData,sec.SizeOfRawData);

		}
	}
	
	//reloc
	cal_reloc(&ImgNtHdr,pMemMap);
	
	//import table
	DWORD dwImpRVA = ImgNtHdr.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
	if (dwImpRVA!=0)
	{
		cal_import(dwImpRVA, pMemMap);
	}

	DWORD dwLoadConfigDirRVA = ImgNtHdr.OptionalHeader.DataDirectory[10].VirtualAddress;
	IMAGE_LOAD_CONFIG_DIRECTORY * ilcd = (IMAGE_LOAD_CONFIG_DIRECTORY *)(pMemMap + dwLoadConfigDirRVA);
	ilcd->SecurityCookie = (DWORD)(ilcd->SecurityCookie - ImgNtHdr.OptionalHeader.ImageBase + pMemMap);
	
#ifdef NOTEPAD
	FILE *fp = fopen(MUI_FILE_PATH, "rb");
	HANDLE hMuiFile = NULL;
	HANDLE hMuiFileMap = NULL;
	DWORD dwMuiFileSize = 0;
	LPVOID lpMuiMapView;
	if (fp != NULL)
	{
		fclose(fp);
		ghMuiLoad = LoadMUILibraryW(_T(MUI_FILE_PATH), MUI_LANGUAGE_NAME, LOCALE_SYSTEM_DEFAULT);
		
	}
	
#endif // NOTEPAD

	
	ptrMain = (MAIN)(pMemMap + ImgNtHdr.OptionalHeader.AddressOfEntryPoint);
	APIHook();
	RunPE(pMemMap);


#ifdef NOTEPAD
	if (hMuiFileMap!=NULL)
	{
		CloseHandle(hMuiFileMap);
	}
#endif // NOTEPAD

	
	return TRUE;
}




int _tmain(int argc, _TCHAR* argv[])
{
	LPVOID lpPEBuf;
	lpPEBuf = InitPE(EXE_FILE_PATH);
	MemoryLoader(lpPEBuf);
	 
	free(lpPEBuf);
	return 0;
}

