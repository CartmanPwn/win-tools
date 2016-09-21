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
	POINT_TYPE		ptType;			//�ϵ�����
	int				ptNum;			//�ϵ����
	LPVOID			ptAddr;			//�ϵ��ַ
	POINT_ACCESS    ptAccess;		//�ϵ�Ȩ��
	BOOL			isOnlyOne;		//�Ƿ���һ�ζϵ�
	char			oldByte;		//ԭ�����ֽ�����

}INT3BPT, *PINT3BPT;

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
}GContext;
BOOL PtPush(INT3BPT ptInfo);
BOOL PtFind(LPVOID lpAddr, PINT3BPTNODE goal);
BOOL PtDelete(PINT3BPTNODE ptNode);