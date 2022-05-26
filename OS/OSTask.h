// OSTask.h: interface for the CTask class.
//
//////////////////////////////////////////////////////////////////////

#if !defined(AFX_TASK_H__F27E82B5_5296_46CE_906F_0DE2F8805068__INCLUDED_)
#define AFX_TASK_H__F27E82B5_5296_46CE_906F_0DE2F8805068__INCLUDED_

#include "OS.h"
#include "OSCond.h"
#include "OSMutex.h"

#if _MSC_VER > 1000
#pragma once
#endif // _MSC_VER > 1000

#define DEL_SELF  0
#define DEL_MANUL 1

class OSTask  
{
public:	
	int32 SetDetroyMode(int32 mode);
	int32 Active();
	uint32   m_SessionID;//进程编号

	uint32   m_subsession;//ClientSession
	char     m_objectName[128];
	int32    m_bExit;

	int32	SetObjectName(char *pObjectName);
	int32	SetSessionID(uint32 SessionID);
	virtual int32 SetFD(int32 fd);
	
	int		Start();
	virtual int		Stop();	
	virtual int32 Run();

	OSTask();
	virtual ~OSTask();

private:

	int32           m_DestroyMode;//0 自动销毁,1 手动销毁

	OSCond 			m_Cond_Run;	
	OSMutex 		m_Mutex_Run;
	bool            m_IsTaskRun;
	bool            m_IsTaskWating;

#ifdef WIN32
	HANDLE			m_hRecvThread;
	static uint32 WINAPI ThreadFunc(void* pVoid);
#else
	pthread_t		m_hRecvThread;
	pthread_attr_t	m_ThreadAttr;
	static void* ThreadFunc(void *pVoid);
#endif

};

#endif // !defined(AFX_TASK_H__F27E82B5_5296_46CE_906F_0DE2F8805068__INCLUDED_)
