// Task.cpp: implementation of the OSTask class.
//
//////////////////////////////////////////////////////////////////////

#include "OSTask.h"
#include "OSMutex.h"

//////////////////////////////////////////////////////////////////////
// Construction/Destruction
//////////////////////////////////////////////////////////////////////

OSTask::OSTask()
{
	memset(m_objectName,0,128);
	m_SessionID = 0;
	m_bExit		= 0;
	m_DestroyMode	= 0;
	m_IsTaskRun		= false;
	m_IsTaskWating	= false;
	m_subsession	= 0;
}

OSTask::~OSTask()
{
#ifdef WIN32
	if(m_hRecvThread != NULL)
	{
		CloseHandle(m_hRecvThread);
		m_hRecvThread = NULL;
	}

#else
#endif
}

int OSTask::Run()
{
	while(!this->m_bExit)
	{
		OS_Sleep(100);
	}

	return 1;
}

int OSTask::Stop()
{
	m_Mutex_Run.Lock();
	m_bExit = 1;
	if(m_IsTaskWating)
	{
		m_Cond_Run.Signal();		
	}
	m_IsTaskRun = false;
	m_Mutex_Run.Unlock();
	return 1;
}

int32 OSTask::Active()
{	
	m_Mutex_Run.Lock();
	m_IsTaskRun = 1;
	if(m_IsTaskWating)
	{		
		m_Cond_Run.Signal();		
	}

	m_Mutex_Run.Unlock();

	return 1;
}


int OSTask::Start()
{
	m_IsTaskRun = true;

#ifdef WIN32
	m_hRecvThread = CreateThread(NULL,128*1024,(LPTHREAD_START_ROUTINE)ThreadFunc,this,0,0);
	if(m_hRecvThread == 0)
	{
		m_IsTaskRun = false;
		return 0;
	}
#else
	pthread_attr_init(&m_ThreadAttr);
	pthread_attr_setstacksize(&m_ThreadAttr,64*1024);

	int32 ret = pthread_create(&m_hRecvThread,&m_ThreadAttr,ThreadFunc,this);
	if(ret!=0)
	{
		m_IsTaskRun =false;
		return 0;
	}
	pthread_attr_destroy(&m_ThreadAttr); 
#endif

	return 1;
}


#ifdef WIN32
uint32 WINAPI OSTask::ThreadFunc(void *pVoid)
#else
void* OSTask::ThreadFunc(void *pVoid)
#endif
{
#ifndef WIN32
	pthread_detach(pthread_self());
#endif
	if(pVoid == 0) return 0;
	
	OSTask *pThis = (OSTask*) pVoid;
/*  用于线程池
	while(!pThis->m_bExit)
	{
			pThis->m_Mutex_Run.Lock();
			if(!pThis->m_IsTaskRun)
			{
				m_IsTaskWating = true;
				pThis->m_Cond_Run.Wait(&pThis->m_Mutex_Run);
				m_IsTaskWating = false;				
			}
			pThis->m_Mutex_Run.Unlock();		
			
		

		
		pThis->Run();

		pThis->m_IsTaskRun = false;

		LOG("[proxy_3gs XXX]task is over=%u;\n",pThis->m_SessionID);

		ClientMgr::GetInstance()->DestroyClient(pThis->m_SessionID);	

		if(pThis->m_DestroyMode == DEL_SELF)
			pThis->Stop();
	}
*/
		pThis->Run();

	//	pThis->m_IsTaskRun = false;

		//Trace("[proxy_3gs XXX]task is over thread=%u;subsession=%u;\n",pThis->m_SessionID,pThis->m_subsession);

	//	ClientMgr::GetInstance()->DestroyClient(pThis->m_SessionID);	
	
	//	delete pThis;
	
		return 0;
}


int32 OSTask::SetSessionID(uint32 SessionID)
{
	m_SessionID = SessionID;
	return 1;
}

int32 OSTask::SetObjectName(char *pObjectName)
{
	if(pObjectName == NULL) return 0;

	strncpy(m_objectName,pObjectName,127);
	return 1;
}

int32 OSTask::SetFD(int32 fd)
{
	return 1;
}


int32 OSTask::SetDetroyMode(int32 mode)
{
	m_DestroyMode = mode;
	return 1;
}
