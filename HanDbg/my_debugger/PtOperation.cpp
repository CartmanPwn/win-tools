#include"stdafx.h"
#include"PtOperation.h"



int ptCount = 0;

INT3BPTMG mMg = { 0 };

//断点链表的操作
//添加断点
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
//寻找断点,当goal为空时，即查找lp是否存在
BOOL PtFind(LPVOID lpAddr, PINT3BPTNODE goal)
{
	PINT3BPTNODE head = mMg.mHead;
	INT3BPT ptInfo;
	if (head == NULL)
		return FALSE;
	while (lpAddr != head->ptSelf.ptAddr)
	{
		head = head->ptNext;
		if (head == NULL)
			return FALSE;
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