#include<Windows.h>
#include<malloc.h>
enum POINT_ACCESS
{
	ACCESS = 1,
	WRITE = 2,
	EXECUTE = 3
};
enum POINT_TYPE
{
	BREAKPOINT = 1,
	STEPIN = 2
};

typedef struct Int3BPointInfo
{
	POINT_TYPE		ptType;			//断点类型
	int				ptNum;			//断点序号
	LPVOID			ptAddr;			//断点地址
	POINT_ACCESS    ptAccess;		//断点权限
	BOOL			isOnlyOne;		//是否是一次断点
	char			oldByte;		//原来的字节内容

}INT3BPT, *PINT3BPT;

typedef struct Int3BPointNode
{
	int				ptNum;			//断点序号
	INT3BPT			ptSelf;			//自己的信息
	Int3BPointNode  *ptSelfAddr;    //自己的地址
	Int3BPointNode	*ptPro;			//上一个指针
	Int3BPointNode	*ptNext;		//下一个指针


}INT3BPTNODE, *PINT3BPTNODE;


typedef struct Int3BPLManager
{
	int					count;		//链表节点数
	PINT3BPTNODE		mHead;		//链表头指针
	PINT3BPTNODE		mTail;		//链表尾指针
}INT3BPTMG;


typedef struct GlobalContext
{
	DEBUG_EVENT			dbgEvent;	//调试事件
	DWORD				dwProcessId;//进程序号
	DWORD				dwThreadId;	//线程序号
	HANDLE				hProcess;	//进程句柄
	HANDLE				hThread;    //线程句柄
	LPVOID              lpStartAddress;//进程起始地址
	EXCEPTION_DEBUG_INFO dbgInfo;	//异常信息
	LPVOID				currentAddr;//当前执行地址
	CONTEXT				currentContext;//Reg....
	char				strFileName[MAX_PATH];//文件名
}GContext;
BOOL PtPush(INT3BPT ptInfo);
BOOL PtFind(LPVOID lpAddr, PINT3BPTNODE goal);
BOOL PtDelete(PINT3BPTNODE ptNode);