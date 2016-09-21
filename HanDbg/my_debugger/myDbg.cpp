// my_debugger.cpp : �������̨Ӧ�ó������ڵ㡣
//

#include "stdafx.h"

#define _CRT_SECURE_NO_WARNINGS
#define STRICT
#define MAINPROG  

#include<malloc.h>
#include<Windows.h>
#include<DbgHelp.h>
#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <vector>
//#include <dir.h>
#include <math.h>
#include <float.h>
#include<string.h>
#pragma hdrstop
#include "disasm.h"

#define MEM_BLOCK_SIZE			128
#define REALLINE				0x3
#define UNREALLINE				0x4







//������ģʽ
#define SINGLE_STEP_MODE_NUM		2
#define SINGLE_STEP_MODE_STEPIN     0x10
#define SINGLE_STEP_MODE_STEPOVER	0x20

//POINT_TYPE_
#define POINT_TYPE_INT3_BREAKPOINT				0x10
#define POINT_TYPE_INT3_SINGLE_STEP				0x20
#define POINT_TYPE_HARDWARE_BREAKPOINT			0x30
#define POINT_TYPE_HARDWARE_SINGLE_STEP			0x40

//DEBUG_EVENT�ж��Ƿ�ִ����һ��ָ��
#define DEBUG_EVENT_ERROR_INPUT					0x10
#define DEBUG_EVENT_NEXT_STEP					0x20
#define DEBUG_EVENT_THIS_STEP					0x30

//��ʾ��һ����ָ������
#define DEBUG_EVENT_INIT_COMMAND				0X00
#define DEBUG_EVENT_GO_COMMAND					0X10
#define DEBUG_EVENT_STEPIN_COMMAND				0X20
#define DEBUG_EVENT_STEPOVER_COMMAND			0X30


//DEBUG_EVENT_FUNC_
#define DEBUG_EVENT_FUNC_ON_CREATE_THREAD		0X10
#define DEBUG_EVENT_FUNC_ON_CREATE_PROCESS		0X20 
#define DEBUG_EVENT_FUNC_ON_EXIT_THREAD 		0X30
#define DEBUG_EVENT_FUNC_ON_EXIT_PROCESS 		0X40
#define DEBUG_EVENT_FUNC_ON_LOAD_DLL 			0X50
#define DEBUG_EVENT_FUNC_ON_UNLOAD_DLL 			0X60
#define DEBUG_EVENT_FUNC_ON_OUTPUT_STRING 		0X70
#define DEBUG_EVENT_FUNC_ON_RIP 				0X80



typedef struct Int3BPointInfo
{
	int				ptType;			//�ϵ�����
	int				ptNum;			//�ϵ����
	LPVOID			ptAddr;			//�ϵ��ַ
	//POINT_ACCESS    ptAccess;		//�ϵ�Ȩ��
	BOOL			isOnlyOne;		//�Ƿ���һ�ζϵ�
	char			oldByte;		//ԭ�����ֽ�����

}INT3BPT,*PINT3BPT;


typedef struct Int3BPointNode
{
	int				ptNum;			//�ϵ����
	INT3BPT			ptSelf;			//�Լ�����Ϣ
	Int3BPointNode  *ptSelfAddr;    //�Լ��ĵ�ַ
	Int3BPointNode	*ptPro;			//��һ��ָ��
	Int3BPointNode	*ptNext;		//��һ��ָ��


}INT3BPTNODE, *PINT3BPTNODE;

typedef struct Int3BPLManager
{
	int					count;		//����ڵ���
	PINT3BPTNODE		mHead;		//����ͷָ��
	PINT3BPTNODE		mTail;		//����βָ��
}INT3BPTMG;


typedef struct GlobalContext
{
	DEBUG_EVENT			dbgEvent;	//�����¼�
	DWORD				dwProcessId;//�������
	DWORD				dwThreadId;	//�߳����
	HANDLE				hProcess;	//���̾��
	HANDLE				hThread;    //�߳̾��
	LPVOID              lpStartAddress;//������ʼ��ַ
	EXCEPTION_DEBUG_INFO dbgInfo;	//�쳣��Ϣ
	LPVOID				currentAddr;//��ǰִ�е�ַ
	CONTEXT				currentContext;//Reg....
	char				strFileName[MAX_PATH];//�ļ���
	/*EXCEPTION_DEBUG_INFO        m_exception;
	CREATE_THREAD_DEBUG_INFO    mc_thdDbgInfo;
	CREATE_PROCESS_DEBUG_INFO   mc_proDbgInfo;
	EXIT_THREAD_DEBUG_INFO      me_thdDbgInfo;
	EXIT_PROCESS_DEBUG_INFO     me_proDbgInfo;
	LOAD_DLL_DEBUG_INFO         ml_dllDbgInfo;
	UNLOAD_DLL_DEBUG_INFO       mu_dllDbgInfo;
	OUTPUT_DEBUG_STRING_INFO    m_dbgString;
	RIP_INFO                    m_ripInfo;*/
}GContext;

typedef struct Command{
	char strData[10][50];
	int  strNum;
}DBG_Command, *PDBG_Command;


BOOL PtFind(LPVOID lpAddr, int ptType, PINT3BPTNODE goal);


CONTEXT GetRegInfo();
BOOL SetRegInfo(CONTEXT context);
BOOL ShowRegInfo();
BOOL GetMemData(LPVOID lpStartAddress, LPVOID Dsk,int size);
BOOL ShowMemData(LPVOID lpStartAddress);
DWORD GetEntryPointAddress();
DWORD GetSourceLineInfo(DWORD dwLineNumber, PIMAGEHLP_LINE64 lineInfo);
BOOL ShowSourceLineInfo(IMAGEHLP_LINE64 lineInfo, DWORD isRealLine); 
BOOL GetSourceInfo(PIMAGEHLP_LINE64 lineInfo);
DWORD ShowSourceInfo();
DWORD  DisplayAsmCode(LPVOID src, int srcSize, int addr);
DWORD BackEipOneStep();
DWORD  GetAsmCode(LPVOID src, int srcSize, int addr, t_disasm* pda);
DWORD ShowAsmCode(t_disasm da, LPVOID lpAddr);
DWORD RecoverInt3FirstByte(LPVOID lpAddr);


BOOL SetInt3BreakPoint(LPVOID lpAddr, int ptType);


DWORD OnCreateThreadDebugEvent(const LPDEBUG_EVENT);
DWORD OnCreateProcessDebugEvent(const LPDEBUG_EVENT);
DWORD OnExitThreadDebugEvent(const LPDEBUG_EVENT);
DWORD OnExitProcessDebugEvent(const LPDEBUG_EVENT);
DWORD OnLoadDllDebugEvent(const LPDEBUG_EVENT);
DWORD OnUnloadDllDebugEvent(const LPDEBUG_EVENT);
DWORD OnOutputDebugStringEvent(const LPDEBUG_EVENT);
DWORD OnRipEvent(const LPDEBUG_EVENT);


DWORD LPSTRToInt(LPSTR data);
void myDbgUsage();





HANDLE hProcess = NULL;
int ptCount = 0;
GContext mCon = {0};
INT3BPTMG mMg = {0};
CONTEXT con;
BOOL isFirst = TRUE;
LPVOID lpAddrSingleStep = NULL;
DWORD lastCommand = DEBUG_EVENT_INIT_COMMAND;

//*********************************************************************
//�ϵ�����Ĳ���
BOOL PtInit(PINT3BPT ptDsk, int ptType,LPVOID lpAddr,BOOL isOnlyOne,char oldChar)
{
	ptDsk->ptType = ptType;
	ptDsk->ptNum = ptCount;
	ptCount++;
	ptDsk->ptAddr = lpAddr;
	ptDsk->isOnlyOne = isOnlyOne;
	ptDsk->oldByte = oldChar;

	return TRUE;
}
//��Ӷϵ�
BOOL PtPush(INT3BPT ptInfo)
{
	mMg.count++;
	PINT3BPTNODE ptNode = (PINT3BPTNODE)malloc(sizeof(INT3BPTNODE));
	ptNode->ptNum = ptInfo.ptNum;
	ptNode->ptSelf = ptInfo;
	ptNode->ptSelfAddr = ptNode;
	if (mMg.mHead == NULL)
	{
		mMg.mHead = ptNode;
		mMg.mTail = ptNode;
		ptNode->ptNext = NULL;
		ptNode->ptPro = NULL;
		return TRUE;
	}
	else
	{
		mMg.mTail->ptNext = ptNode;
		ptNode->ptPro = mMg.mTail;
		ptNode->ptNext = NULL;
		mMg.mTail = ptNode;
		return TRUE;
	}

}

//Ѱ�Ҷϵ�,��goalΪ��ʱ��������lp�Ƿ����
BOOL PtFind(LPVOID lpAddr,int ptType, PINT3BPTNODE goal)
{
	PINT3BPTNODE head = mMg.mHead;
	INT3BPT ptInfo;
	if (head == NULL)
		return FALSE;
	if (ptType == NULL)
	{
		while (lpAddr != head->ptSelf.ptAddr)
		{

			head = head->ptNext;
			if (head == NULL)
				return FALSE;
		}
	}	
	else
	{
		while (lpAddr != head->ptSelf.ptAddr || ptType != head->ptSelf.ptType)
		{

			head = head->ptNext;
			if (head == NULL)
				return FALSE;
		}
	}	
	if (lpAddr == head->ptSelf.ptAddr)
	{
		if (goal != NULL)
		{
			goal->ptSelf = head->ptSelf;
			goal->ptSelfAddr = head;
			goal->ptNext = head->ptNext;
			goal->ptNum = head->ptNum;
		}
		return TRUE;
	}

	return FALSE;
}

BOOL PtShow(INT3BPTNODE point)
{
	printf("BREAKPOINT:\t0X%X\n", point.ptSelfAddr);
	return TRUE;
}

//ɾ���ϵ㣬�������Ҫɾ���Ķϵ�ĵ�ַ
BOOL PtDelete(PINT3BPTNODE ptNode)
{
	if (ptNode == NULL)
	{
		return FALSE;
	}
	if (mMg.mHead == ptNode)
	{
		mMg.mHead = ptNode->ptNext;
		mMg.mHead->ptPro = NULL;
	}
	else if (mMg.mTail == ptNode)
	{
		mMg.mTail = ptNode->ptPro;
		mMg.mTail->ptNext = NULL;
	}
	else
	{
		ptNode->ptNext->ptPro = ptNode->ptPro;
		ptNode->ptPro->ptNext = ptNode->ptNext;
	}
	free(ptNode);
	return TRUE;
}
//*********************************************************************

CONTEXT GetRegInfo()
{
	
	CONTEXT context;
	context.ContextFlags = CONTEXT_FULL;
	if(GetThreadContext(mCon.hThread,&context)==FALSE)
		printf("GetRegInfo  failed\n");	
	return context;
}
BOOL SetRegInfo(CONTEXT context)
{
	 return SetThreadContext(mCon.hThread,&context);
}
BOOL ShowRegInfo()
{
	CONTEXT context = GetRegInfo();
	printf("\
Reg:===============================================\r\n\
EAX = 0X%.8X\t\tEBX = 0X%.8X\r\n\ECX = 0X%.8X\t\tEDX = 0X%.8X\r\n\
EBP = 0X%.8X\t\tESI = 0X%.8X\r\n\EDI = 0X%.8X\t\tESP = 0X%.8X\r\n\
EIP = 0X%.8X\t\tEFLAGS = 0X%.8X\r\n", context.Eax, context.Ebx, context.Ecx, context.Edx,
		   context.Ebp, context.Esi, context.Edi, context.Esp,
		   context.Eip, context.EFlags);
	return TRUE;
}

BOOL GetMemData(LPVOID lpStartAddress,LPVOID Dsk ,int size)
{
	DWORD dwOldProtect;
	BOOL bRet = TRUE;
	VirtualProtectEx(mCon.hProcess, lpStartAddress, 1, PAGE_READWRITE, &dwOldProtect);
	
	bRet = ReadProcessMemory(mCon.hProcess, lpStartAddress, Dsk, size, NULL);
	
	VirtualProtectEx(mCon.hProcess, lpStartAddress, 1, dwOldProtect, &dwOldProtect);
	return bRet;
}

BOOL ShowMemData(LPVOID lpStartAddress)
{
	LPVOID memBlock = malloc(MEM_BLOCK_SIZE);
	GetMemData(lpStartAddress,memBlock,MEM_BLOCK_SIZE);
	char * pcm = (char *)memBlock;
	printf("MemData:=======================================================\n");
	printf("��ַ\t\t�ڴ�����\r\n");
	for (int i = 0; i<MEM_BLOCK_SIZE/16; i++)
	{
		printf("%.8X\t", (int)lpStartAddress + 16*i);
		for (int j = 0;j<16;j++)
		{
			printf("%.2x ", pcm[j + 8 * i] & 0x000000ff);
		}
		printf("\r\n");
	}
	return TRUE;
}

//��ó�����ڵ�ַ
DWORD GetEntryPointAddress() 
{

	static LPCTSTR entryPointNames[] = {
		TEXT("main"),
		TEXT("wmain"),
		TEXT("WinMain"),
		TEXT("wWinMain"),
	};

	SYMBOL_INFO symbolInfo = { 0 };
	symbolInfo.SizeOfStruct = sizeof(SYMBOL_INFO);

	for (int index = 0; index != sizeof(entryPointNames) / sizeof(LPCTSTR); ++index) {

		if (SymFromName(mCon.hProcess, entryPointNames[index], &symbolInfo) == TRUE) {

			return (DWORD)symbolInfo.Address;
		}
	}

	return 0;
}
//��Ϊ��Ч�У���Ϊ��Ч��
DWORD GetSourceLineInfo(DWORD dwLineNumber, PIMAGEHLP_LINE64 lineInfo)
{
	LONG displacement = 0;
	if (lineInfo != NULL)
	{		
		if(SymGetLineFromName64(mCon.hProcess,
			NULL,
			mCon.strFileName, 
			dwLineNumber, 
			&displacement, 
			lineInfo)==FALSE)
			return FALSE;
		if (displacement != 0)
		{
			return REALLINE;
		}
		else
		{
			return UNREALLINE;
		}

	}	
	return FALSE;
}

BOOL ShowSourceLineInfo(IMAGEHLP_LINE64 lineInfo, DWORD isRealLine)
{
	if (isRealLine == REALLINE)
	{
		printf("%d\t%.8X\n",lineInfo.LineNumber,lineInfo.Address);
	}
	else if (isRealLine == UNREALLINE)
	{

	}
	else
	{
		return FALSE;
	}
	return TRUE;
}

BOOL GetSourceInfo(PIMAGEHLP_LINE64 lineInfo)
{
	//IMAGEHLP_LINE64 lineInfo = { 0 };
	lineInfo->SizeOfStruct = sizeof(lineInfo);
	CONTEXT context = GetRegInfo();
	DWORD displacement = 0;

	if (SymGetLineFromAddr64(
		mCon.hProcess,
		context.Eip,
		&displacement,
		lineInfo) == FALSE)
	{
		printf("SymGetLineFromAddr64 failed.\n");
	}
	return TRUE;
}

DWORD ShowSourceInfo()
{
	IMAGEHLP_LINE64 lineInfo;
	if(GetSourceInfo(&lineInfo)==FALSE)
		return FALSE;
	int isAccessLine = 1;
	while (TRUE)
	{
		isAccessLine = GetSourceLineInfo(lineInfo.LineNumber + 1,&lineInfo);
		if (isAccessLine == FALSE)
		{
			break;
		}
		ShowSourceLineInfo(lineInfo,isAccessLine);
	}

	return TRUE;
}
DWORD UpdateGContext(const LPDEBUG_EVENT DebugEv)
{
	EXCEPTION_DEBUG_INFO exDbg = DebugEv->u.Exception;
	mCon.currentContext = GetRegInfo();
	mCon.currentAddr = (LPVOID)mCon.currentContext.Eip;
	
	return TRUE;
}

DWORD SetTrapFlag(CONTEXT reg)
{
	reg.EFlags |= 0x100;
	SetRegInfo(reg);
	return TRUE;
}


//д��int3�ϵ�ĵ�һ���ֽ�
DWORD WriteInt3FirstByte(LPVOID lpAddr,char *oldchar)
{
	char oldc = 0;
	char int3 = 0;
	int3 = 0xcc;
	DWORD dwOldProtect;
	BOOL bRet;
	HANDLE hPro;
	hPro = mCon.hProcess;
	//VirtualProtectEx �������Ըı����ض��������ڴ�����ı������ԡ�
	bRet = VirtualProtectEx(hPro, lpAddr, 1, PAGE_READWRITE, &dwOldProtect);
	bRet = ReadProcessMemory(hPro, lpAddr, &oldc, 1, NULL);
	if (bRet == FALSE)
	{
		printf("ReadProcessMemory error.\n");
		return FALSE;
	}
	bRet = WriteProcessMemory(hPro, lpAddr, &int3, 1, NULL);
	if (bRet == FALSE)
	{
		printf("WriteProcessMemory error.\n");
		return FALSE;
	}
	VirtualProtectEx(hPro, lpAddr, 1, dwOldProtect, &dwOldProtect);
	*oldchar = oldc;
	return  TRUE;

}
//�ָ�int3�ϵ�ĵ�һ���ֽ�
DWORD RecoverInt3FirstByte(LPVOID lpAddr)
{
	INT3BPTNODE goal;
	if (PtFind(lpAddr, NULL,&goal) == FALSE)
		return FALSE;
	char int3 = 0;
	char oldc = goal.ptSelf.oldByte;
	DWORD dwOldProtect;
	BOOL bRet;
	HANDLE hPro = mCon.hProcess;
	//hPro = hProcess;
	//VirtualProtectEx �������Ըı����ض��������ڴ�����ı������ԡ�
	bRet = VirtualProtectEx(hPro, lpAddr, 1, PAGE_READWRITE, &dwOldProtect);
	bRet = ReadProcessMemory(hPro, lpAddr, &int3, 1, NULL);
	if (bRet == FALSE)
	{
		printf("ReadProcessMemory error.\n");//����
		return FALSE;
	}
	if (int3 != (char)0xcc)
	{
		printf("this is not old break point.\n");
		return FALSE;
	}
	bRet = WriteProcessMemory(hPro, lpAddr, &oldc, 1, NULL);
	if (bRet == FALSE)
	{
		printf("WriteProcessMemory error.\n");
		return FALSE;
	}
	VirtualProtectEx(hPro, lpAddr, 1, dwOldProtect, &dwOldProtect);
}

DWORD BackEipOneStep()
{
	con = GetRegInfo();
	con.Eip--;
	if (SetRegInfo(con) == FALSE)
	{
		printf("eip - 1 error\n");
		return FALSE;
	}
	return TRUE;
}
LPVOID GetAddrFromStack()
{
	LPVOID lpAddr,data;
	DWORD dwOldProtect;
	HANDLE hPro = mCon.hProcess;
	con = GetRegInfo();
	lpAddr = (LPVOID)con.Esp;
	GetMemData(lpAddr,&data,4);
	return data;
}

//ʹ����od�ķ��������
//��������һ������src�Ǵ����Ļ�����ĵ�ַ���ڶ�������srcSize���������ݵĳ���
//����ֵΪ����ָ�������
//ʹ�ú�����Disasm����������������ݣ�ֻ������һ������
//ulong Disasm(char *src,ulong srcsize,ulong srcip,t_disasm *disasm, int disasmmode)
//��һ��������src���������������ַ��
//�ڶ����������������ݵĳ���
//����������Ϊ����ַ
//���ĸ�����������Ľ��
//����������Ƿ����ģʽ
//����ֵΪ��������һ��������ָ��ĳ���
//da.dump�ǻ��������ݣ�da.result�ǻ�����ķ������

//�����뿽�����ڴ�ĵ�ַ����������ռ�õ����ݵĴ�С����һ���������ڽ����еĵ�ַ
DWORD  DisplayAsmCode(LPVOID src, int srcSize, int addr)
{
	int i, j, n;
	ulong l;
	char *pasm = (char *)src;
	t_disasm da;
	int accLen = 0;
	int lpAddr = addr;
	// Demonstration of Disassembler.
	printf("Disassembler:\n");
	ideal = 0; lowercase = 0; putdefseg = 1;
	while (accLen<srcSize)
	{
		l = Disasm(pasm, srcSize, 0x000000, &da, DISASM_CODE);//0x400000
		pasm = pasm + l;
		printf("0X%.8X  %-24s  %-24s\n", lpAddr, da.dump, da.result);
		accLen = accLen + l;
		lpAddr = lpAddr + l;
		if (accLen>srcSize)
		{
			break;
		}
	}
	return accLen;

}

DWORD  GetAsmCode(LPVOID src, int srcSize, int addr, t_disasm* pda)
{
	int i, j, n;
	ulong len = 0;
	char *pasm = (char *)src;
	int accLen = 0;
	int lpAddr = addr;
	ideal = 0; lowercase = 0; putdefseg = 1;
	if (accLen < srcSize)
	{
		len = Disasm(pasm, srcSize, 0x000000, pda, DISASM_CODE);//0x400000
	}
	return len;
}

DWORD ShowAsmCode(t_disasm da,LPVOID lpAddr)
{
	printf("0X%.8X  %-24s  %-24s\n", lpAddr, da.dump, da.result);
	return TRUE;
}

//*********************************************************************
//����Int3�ϵ�
BOOL SetInt3BreakPoint(LPVOID lpAddr,int ptType)
{
	char oldchar = 0;
	if (WriteInt3FirstByte(lpAddr,&oldchar)==FALSE)
	{
		return FALSE;
	}

	INT3BPT  pt;
	PtInit(&pt,ptType,lpAddr,TRUE,oldchar);

	if (PtPush(pt) == FALSE)
		return FALSE;

	return TRUE;
}

//ɾ��Int3�ϵ�
BOOL DelInt3BreakPoint(LPVOID lpAddr, int ptType)
{
	INT3BPTNODE goal;
	if (PtFind(lpAddr,ptType, &goal) == FALSE)
		return FALSE;
	if (PtDelete(goal.ptSelfAddr) == FALSE)
		return FALSE;
	return TRUE;
}

//���üĴ���
DWORD SetEflags()
{
	con = GetRegInfo();
	if (SetTrapFlag(con) == FALSE)
		return FALSE;
	return TRUE;
}



DWORD StepIn(const LPDEBUG_EVENT DebugEv)
{
	SetEflags();
	return TRUE;
}

DWORD StepOver(const LPDEBUG_EVENT DebugEv)
{
	LPVOID data = malloc(20);
	LPVOID lpAddr;
	int len;

	t_disasm da = { 0 };
	GetMemData(mCon.currentAddr, data, 20);
	len = GetAsmCode(data, 20, (int)mCon.currentAddr, &da);
	lpAddr = mCon.currentAddr;

	if (da.cmdtype<0)
	{
		da.cmdtype = da.cmdtype & 0xff;
	}
	int type = da.cmdtype / 16 * 16;
	switch (type)
	{
	case C_CAL:
		lpAddr = (LPVOID)((int)lpAddr+len);
		SetInt3BreakPoint(lpAddr, POINT_TYPE_INT3_SINGLE_STEP);
		break;
	default:
		SetEflags();
		break;
	}
	free(data);
	return TRUE;
}




DWORD RecoverBreakPoint(const LPDEBUG_EVENT DebugEv)
{
	EXCEPTION_DEBUG_INFO exDbg = DebugEv->u.Exception;
	BOOL bRet = TRUE;
	LPVOID lpAddr;
	INT3BPTNODE goal;
	lpAddr = exDbg.ExceptionRecord.ExceptionAddress;
	if (PtFind(lpAddr,NULL ,&goal) == FALSE)
	{
		return FALSE;
	}
	//int3�ϵ�
	switch (goal.ptSelf.ptType)
	{
	case POINT_TYPE_INT3_BREAKPOINT:
		if (RecoverInt3FirstByte(lpAddr) == FALSE)
		{
			return FALSE;
		}
		if (BackEipOneStep() == FALSE)
		{
			return FALSE;
		}
		break;
	case  POINT_TYPE_INT3_SINGLE_STEP:
		if (RecoverInt3FirstByte(lpAddr) == FALSE)
		{
			return FALSE;
		}
		DelInt3BreakPoint(lpAddrSingleStep, POINT_TYPE_INT3_SINGLE_STEP);
		if (BackEipOneStep() == FALSE)
		{
			return FALSE;
		}
		break;
	case POINT_TYPE_HARDWARE_BREAKPOINT:
		//Ӳ���ϵ�
		break;
	case POINT_TYPE_HARDWARE_SINGLE_STEP:
		break;
	default:
		break;
	}
	return TRUE;
}
//********************************************************************
//int3��������
DWORD T_COMMAND(const LPDEBUG_EVENT DebugEv, DBG_Command command)
{
	StepIn(DebugEv);	
	return DEBUG_EVENT_NEXT_STEP;
}

//int3��������
DWORD P_COMMAND(const LPDEBUG_EVENT DebugEv, DBG_Command command)
{
	StepOver(DebugEv);
	return DEBUG_EVENT_NEXT_STEP;
}


DWORD H_COMMAND(const LPDEBUG_EVENT DebugEv, DBG_Command command)
{
	myDbgUsage();
	return DEBUG_EVENT_THIS_STEP;
}

//int3����ִ��
DWORD G_COMMAND(const LPDEBUG_EVENT DebugEv, DBG_Command command)
{
	LPVOID lpAddr;
	lpAddr = (LPVOID)((int)mCon.currentAddr);
	LPVOID data = malloc(20);
	if (lastCommand != DEBUG_EVENT_GO_COMMAND)
	{
		lastCommand = DEBUG_EVENT_GO_COMMAND;		
		//SetInt3BreakPoint(lpAddr, POINT_TYPE_INT3_SINGLE_STEP);		
	}
	else
	{
		lastCommand = DEBUG_EVENT_INIT_COMMAND;

	}
	free(data);
	return DEBUG_EVENT_NEXT_STEP;
}


//����࣬�ڶ�������Ϊ��ַ
DWORD U_COMMAND(const LPDEBUG_EVENT DebugEv, DBG_Command command)
{
	LPVOID lpAddr;
	EXCEPTION_DEBUG_INFO exDbg = DebugEv->u.Exception;	
	char data[100];
	t_disasm da = { 0 };
	if (command.strNum == 1)
	{
		lpAddr = exDbg.ExceptionRecord.ExceptionAddress;
	}
	else if (command.strNum == 2)
	{
		//������ַ
		lpAddr = (LPVOID)LPSTRToInt(command.strData[1]);
	}
	else
		return DEBUG_EVENT_ERROR_INPUT;
	if (GetMemData(lpAddr, data, 100) == FALSE)
	{
		return DEBUG_EVENT_ERROR_INPUT;
	}
	DisplayAsmCode(data,100,(int)lpAddr);

	return DEBUG_EVENT_THIS_STEP;
}

//�ڴ�
DWORD D_COMMAND(const LPDEBUG_EVENT DebugEv, DBG_Command command)
{
	LPVOID lpAddr = NULL;
	EXCEPTION_DEBUG_INFO exDbg = DebugEv->u.Exception;
	if (command.strNum == 1)
	{
		lpAddr = exDbg.ExceptionRecord.ExceptionAddress;
	}
	else if (command.strNum == 2)
	{
		//������ַ
		lpAddr = (LPVOID)LPSTRToInt(command.strData[1]);
	}
	else
		return DEBUG_EVENT_ERROR_INPUT;

	ShowMemData(lpAddr);
	return DEBUG_EVENT_THIS_STEP;
}

//��ʾ�Ĵ���
DWORD R_COMMAND(const LPDEBUG_EVENT DebugEv, DBG_Command command)
{
	return ShowRegInfo();
}

//���öϵ�
DWORD B_COMMAND(const LPDEBUG_EVENT DebugEv, DBG_Command command)
{
	LPVOID lpAddr;
	EXCEPTION_DEBUG_INFO exDbg = DebugEv->u.Exception;	
	if (command.strNum == 2)
	{        
		//������ַ
		lpAddr = (LPVOID)LPSTRToInt(command.strData[1]);
	}
	else
		return DEBUG_EVENT_ERROR_INPUT;
	SetInt3BreakPoint(lpAddr, POINT_TYPE_INT3_BREAKPOINT);


	return DEBUG_EVENT_THIS_STEP;
}

//��ʾ�ϵ��б�
DWORD L_COMMAND(const LPDEBUG_EVENT DebugEv, DBG_Command command)
{
	PINT3BPTNODE p = mMg.mHead;
	while (p!=NULL)
	{
		if (p->ptSelf.ptType==POINT_TYPE_INT3_BREAKPOINT||
			p->ptSelf.ptType==POINT_TYPE_HARDWARE_BREAKPOINT)
		{
			PtShow(*p);
		}		
		p = p->ptNext;		
	}
	return DEBUG_EVENT_THIS_STEP;
}

//ɾ���ϵ�
DWORD C_COMMAND(const LPDEBUG_EVENT DebugEv, DBG_Command command)
{
	LPVOID lpAddr;
	EXCEPTION_DEBUG_INFO exDbg = DebugEv->u.Exception;
	if (command.strNum == 2)
	{
		//������ַ
		lpAddr = (LPVOID)LPSTRToInt(command.strData[1]);
	}
	else
		return DEBUG_EVENT_ERROR_INPUT;
	//SetInt3BreakPoint(lpAddr, POINT_TYPE_INT3_BREAKPOINT);
	//ɾ���ϵ�

	return DEBUG_EVENT_THIS_STEP;
}

BOOL InitCommand(PDBG_Command command)
{
	if (command!=NULL)
	{
		memset(command,0,sizeof(DBG_Command));
		return TRUE;
	}
	else
	{
		return FALSE;
	}
}


//16�����ַ���תint
DWORD LPSTRToInt(LPSTR data)
{
	char * str;
	int i = (int)strtol(data, &str, 16);
	return i;
}


BOOL GetInputCommand(PDBG_Command command)
{
	char data[20];
	char * p = data;
	int len;
	fflush(stdin);
	scanf("%[0-9a-zA-Z ]s", data);
	fflush(stdin);
	while (*p != 0)
	{
		len = 0;
		while (*p == ' ')
		{
			p = p + 1;
		}
		while (*p != ' '&&*p != 0)
		{
			p = p + 1;
			len++;
		}
		memcpy(command->strData[command->strNum], p - len, len);
		command->strNum++;
	}
	return TRUE;
}

void PrintCommand()
{
	printf("COMMAND:");
}


BOOL WaitForInput(const LPDEBUG_EVENT DebugEv)
{
	EXCEPTION_DEBUG_INFO exDbg = DebugEv->u.Exception;
	char inc = 'G';
	DBG_Command command = { 0 };
	DWORD bRet = DEBUG_EVENT_THIS_STEP;

	while (bRet != DEBUG_EVENT_NEXT_STEP)
	{
		PrintCommand();
		InitCommand(&command);
		GetInputCommand(&command);
		inc = *command.strData[0];

		//inc = 't';

		switch (inc)
		{
		case 't':
			bRet = T_COMMAND(DebugEv, command);
			break;
		case 'T':
			bRet = T_COMMAND(DebugEv, command);
			break;

		case 'g':
			bRet = G_COMMAND(DebugEv, command);
			break;
		case 'G':
			bRet = G_COMMAND(DebugEv, command);
			break;

		case 'p':
			bRet = P_COMMAND(DebugEv, command);
			break;
		case 'P':
			bRet = P_COMMAND(DebugEv, command);
			break;

		case 'h':
			bRet = H_COMMAND(DebugEv, command);
			break;
		case 'H':
			bRet = H_COMMAND(DebugEv, command);
			break;

		case 'u':
			bRet = U_COMMAND(DebugEv, command);
			break;
		case 'U':
			bRet = U_COMMAND(DebugEv, command);
			break;

		case 'd':
			bRet = D_COMMAND(DebugEv, command);
			break;
		case 'D':
			bRet = D_COMMAND(DebugEv, command);
			break;

		case 'r':
			bRet = R_COMMAND(DebugEv, command);
			break;
		case 'R':
			bRet = R_COMMAND(DebugEv, command);
			break;

		case 'b':
			bRet = B_COMMAND(DebugEv, command);
			break;
		case 'B':
			bRet = B_COMMAND(DebugEv, command);
			break;

		case 'l':
			bRet = L_COMMAND(DebugEv, command);
			break;
		case 'L':
			bRet = L_COMMAND(DebugEv, command);
			break;

		case 'c':
			bRet = C_COMMAND(DebugEv, command);
			break;
		case 'C':
			bRet = C_COMMAND(DebugEv, command);
			break;
		default:
			break;
		}
	}

	return TRUE;
}


//*********************************************************************
DWORD OnShowDebugEventInfo(int index)
{
	switch (index)
	{
	case DEBUG_EVENT_FUNC_ON_CREATE_THREAD:
		printf("OnCreateThreadDebugEvent\n");
		break;
	case DEBUG_EVENT_FUNC_ON_CREATE_PROCESS:
		printf("OnCreateProcessDebugEvent\n");
		break;
	case DEBUG_EVENT_FUNC_ON_EXIT_THREAD:
		printf("OnExitThreadDebugEvent\n");
		break;
	case DEBUG_EVENT_FUNC_ON_EXIT_PROCESS:
		printf("OnExitProcessDebugEvent\n");
		break;
	case DEBUG_EVENT_FUNC_ON_LOAD_DLL:
		printf("OnLoadDllDebugEvent\n");
		break;
	case DEBUG_EVENT_FUNC_ON_UNLOAD_DLL:
		printf("OnUnloadDllDebugEvent\n");
		break;
	case DEBUG_EVENT_FUNC_ON_OUTPUT_STRING:
		printf("OnOutputDebugStringEvent\n");
		break;
	case DEBUG_EVENT_FUNC_ON_RIP:
		printf("OnRipEvent\n");
		break;
	default:
		break;
	}
	return TRUE;
}


DWORD OnExceptionDebugEvent(const LPDEBUG_EVENT DebugEv)
{
	EXCEPTION_DEBUG_INFO exDbg = DebugEv->u.Exception;
	BOOL bRet = TRUE;
	LPVOID data = malloc(20);
	t_disasm da = { 0 };	
	UpdateGContext(DebugEv);
	LPVOID lpAddr = exDbg.ExceptionRecord.ExceptionAddress;
	switch (exDbg.ExceptionRecord.ExceptionCode)
	{
	case EXCEPTION_ACCESS_VIOLATION:
	break;

	case EXCEPTION_BREAKPOINT:
		bRet = PtFind(lpAddr, NULL, NULL);
		if (bRet == TRUE)
		{
			RecoverBreakPoint(DebugEv);
			con = GetRegInfo();
			con.Eip = (DWORD)exDbg.ExceptionRecord.ExceptionAddress;
			SetRegInfo(con);

			mCon.currentAddr = (LPVOID)con.Eip;
			GetMemData(mCon.currentAddr, data, 20);
			GetAsmCode(data, 20, (int)mCon.currentAddr, &da);
			ShowAsmCode(da, mCon.currentAddr);
			WaitForInput(DebugEv);
		}
	break;

	case EXCEPTION_DATATYPE_MISALIGNMENT:
	break;

	case EXCEPTION_SINGLE_STEP:				
		mCon.currentAddr = (LPVOID)con.Eip;
		lpAddr = mCon.currentAddr;
		GetMemData(mCon.currentAddr, data, 20);
		GetAsmCode(data, 20, (int)mCon.currentAddr, &da);
		ShowAsmCode(da, mCon.currentAddr);
		WaitForInput(DebugEv);
	break;
	case DBG_CONTROL_C:
	break;

	default:
	break;
	}	
	free(data);
	
	//getchar();
	return TRUE;
}


DWORD OnCreateThreadDebugEvent(const LPDEBUG_EVENT DebugEv)
{
	OnShowDebugEventInfo(DEBUG_EVENT_FUNC_ON_CREATE_THREAD);
	CREATE_THREAD_DEBUG_INFO cThdDbg = DebugEv->u.CreateThread;
	
	return TRUE;
}


DWORD OnCreateProcessDebugEvent(const LPDEBUG_EVENT DebugEv)
{
	OnShowDebugEventInfo(DEBUG_EVENT_FUNC_ON_CREATE_PROCESS);
	CREATE_PROCESS_DEBUG_INFO cProDbg = DebugEv->u.CreateProcessInfo;
	
	mCon.dwProcessId = DebugEv->dwProcessId;
	mCon.lpStartAddress = DebugEv->u.CreateProcessInfo.lpStartAddress;
	mCon.hProcess = DebugEv->u.CreateProcessInfo.hProcess;
	
	
	HANDLE hPro = mCon.hProcess;
	LPVOID lpAddr = (LPVOID)con.Eip;
	con = GetRegInfo();
	//LPVOID lpAddr = (LPVOID)mCon.lpStartAddress;

	SetInt3BreakPoint((LPVOID)((int)lpAddr + 4), POINT_TYPE_INT3_BREAKPOINT);
	
	
	CloseHandle(cProDbg.hFile);
	CloseHandle(cProDbg.hThread);
	CloseHandle(cProDbg.hProcess);
	
	return TRUE;
}


DWORD OnExitThreadDebugEvent(const LPDEBUG_EVENT DebugEv)
{
	OnShowDebugEventInfo(DEBUG_EVENT_FUNC_ON_EXIT_THREAD);
	EXIT_THREAD_DEBUG_INFO exitThdDbg = DebugEv->u.ExitThread;
	
	return TRUE;
}

DWORD OnExitProcessDebugEvent(const LPDEBUG_EVENT DebugEv)
{
	OnShowDebugEventInfo(DEBUG_EVENT_FUNC_ON_EXIT_PROCESS);
	EXIT_PROCESS_DEBUG_INFO exitProDbg = DebugEv->u.ExitProcess;
	
	SymCleanup(mCon.hProcess);
	
	return FALSE;
}

DWORD OnLoadDllDebugEvent(const LPDEBUG_EVENT DebugEv)
{
	OnShowDebugEventInfo(DEBUG_EVENT_FUNC_ON_LOAD_DLL);
	LOAD_DLL_DEBUG_INFO loadDllDbg = DebugEv->u.LoadDll;
	
	return TRUE;
}

DWORD OnUnloadDllDebugEvent(const LPDEBUG_EVENT DebugEv)
{
	OnShowDebugEventInfo(DEBUG_EVENT_FUNC_ON_UNLOAD_DLL);
	UNLOAD_DLL_DEBUG_INFO unloadDllDbg = DebugEv->u.UnloadDll;
	
	return TRUE;
}

DWORD OnOutputDebugStringEvent(const LPDEBUG_EVENT DebugEv)
{
	OnShowDebugEventInfo(DEBUG_EVENT_FUNC_ON_OUTPUT_STRING);
	OUTPUT_DEBUG_STRING_INFO outDbgStr = DebugEv->u.DebugString;
	
	return TRUE;
}

DWORD OnRipEvent(const LPDEBUG_EVENT DebugEv)
{
	OnShowDebugEventInfo(DEBUG_EVENT_FUNC_ON_RIP);
	RIP_INFO ripInfo = DebugEv->u.RipInfo;
	
	return TRUE;
}

void myDbgUsage()
{
	printf("   ============================ usage menu ==================================\r\n");
    printf("   **************************************************************************\r\n");
    printf("\
   * ��� ������      ������ Ӣ��˵��        ����1    ����2    ����3        *\r\n\
   * 1    ��������      T    step into                                      *\r\n\
   * 2    ��������      P    step over                                      *\r\n\
   * 3    ����          G    run             ��ַ����                       *\r\n\
   *------------------------------------------------------------------------*\r\n\
   * 4    �����        U    assemble        ��ַ����                       *\r\n\
   * 5    �ڴ�          D    data            ��ַ����                       *\r\n\
   * 6    �Ĵ���        R    register                                       *\r\n\
   *------------------------------------------------------------------------*\r\n\
   * 7    int3�ϵ�      B   breakpoint      ��ַ				            *\r\n\
   * 8    int3�ϵ��б�  L   bp list                                         *\r\n\
   * 9    ɾ��int3�ϵ�  C   clear bp        ��ַ                            *\r\n\
   *------------------------------------------------------------------------*\r\n\
   * 10   ����          h    help                                           *\r\n");
    printf("   **************************************************************************\r\n");
}

//***********************************************************************************
DEBUG_EVENT myDbgEvent = { 0 };
int _tmain(int argc, _TCHAR* argv[])
{	
	CHAR          szFileName[MAX_PATH] = "";
	OPENFILENAME    ofn;
	ZeroMemory(&ofn, sizeof(OPENFILENAME));
	ofn.lStructSize = sizeof(OPENFILENAME);
	ofn.lpstrFile = szFileName;
	ofn.nMaxFile = MAX_PATH;
	ofn.lpstrFilter = "Exe Files(*.exe)\0*.exe\0All Files(*.*)\0*.*\0\0";
	ofn.nFilterIndex = 1;
	if (GetOpenFileName(&ofn) == FALSE)
	{
		return -1;
	}
	
	//PCSTR path = "F:\\test.exe";

	STARTUPINFO si = { 0 };
	PROCESS_INFORMATION pi = { 0 };
	si.cb = sizeof(si);
	DWORD dwStatus;
	GetStartupInfo(&si);
	BOOL bRet = CreateProcess(
		szFileName,//ָ����ִ���ļ����ļ���
		NULL,//�����в���
		NULL,//Ĭ�Ͻ��̰�ȫ��
		NULL,//Ĭ�Ͻ��̰�ȫ��
		FALSE,//ָ����ǰ�����ھ�����Ա��ӽ��̼̳�
		DEBUG_ONLY_THIS_PROCESS | CREATE_NEW_CONSOLE,//Ч����ͬ��ʹ��DebugActiveProcess
		NULL,//ʹ�ñ����̵Ļ�������
		NULL,//ʹ�ñ����̵���������Ŀ¼
		&si,
		&pi);
	
	if (bRet)
	{
		printf("start debugging...\n");
		myDbgUsage();
		BOOL waitEvent = TRUE;
		BOOL bRet = TRUE;
		mCon.hThread = pi.hThread;
		hProcess = pi.hProcess;
		while (waitEvent == TRUE && WaitForDebugEvent(&myDbgEvent, INFINITE))
		{
			dwStatus = DBG_CONTINUE;
			con = GetRegInfo();
			switch (myDbgEvent.dwDebugEventCode)
			{
			case EXCEPTION_DEBUG_EVENT:			
				mCon.hThread = pi.hThread;
				mCon.hProcess = pi.hProcess;
				bRet = OnExceptionDebugEvent(&myDbgEvent);								
				if (bRet == FALSE)
				{
					dwStatus = DBG_EXCEPTION_NOT_HANDLED;
				}
				break;

			case CREATE_THREAD_DEBUG_EVENT:			
				OnCreateThreadDebugEvent(&myDbgEvent);
				break;
			case CREATE_PROCESS_DEBUG_EVENT:
				OnCreateProcessDebugEvent(&myDbgEvent);
				break;
			case EXIT_THREAD_DEBUG_EVENT:
				OnExitThreadDebugEvent(&myDbgEvent);
				break;
			case EXIT_PROCESS_DEBUG_EVENT:
				OnExitProcessDebugEvent(&myDbgEvent);
				waitEvent = FALSE;
				break;
			case LOAD_DLL_DEBUG_EVENT:
				//OnLoadDllDebugEvent(&myDbgEvent);
				break;
			case UNLOAD_DLL_DEBUG_EVENT:
				//OnUnloadDllDebugEvent(&myDbgEvent);
				break;
			case OUTPUT_DEBUG_STRING_EVENT:
				OnOutputDebugStringEvent(&myDbgEvent);
				break;
			case RIP_EVENT:
				OnRipEvent(&myDbgEvent);
				break;
			}if (waitEvent == TRUE) {
				ContinueDebugEvent(myDbgEvent.dwProcessId, myDbgEvent.dwThreadId, DBG_CONTINUE);
			}
			else {
				break;
			}
		}
	}
	else
	{
		printf("create debug process failed");
	}
	getchar();
	return 0;
}




