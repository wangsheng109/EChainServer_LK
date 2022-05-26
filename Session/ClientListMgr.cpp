#include "ClientListMgr.h"
#include "ClientSession.h"

#include <fstream>
#include <time.h>
//#include "ReadConfig.h"
#include "Global.h"
#include "api_echain_func.h"

CClientListMgr* g_ClientListMgr;

CClientListMgr* CClientListMgr::m_CClientListMgr = NULL;
UInt32 CClientListMgr::m_curSessionID = 0;
OSMutex CClientListMgr::m_Mutex_ClientList;
OSMutex CClientListMgr::m_Mutex_UnusedList;
UInt32 CClientListMgr::m_ClientNum = 0;
UInt32 CClientListMgr::m_unClientNum = 0;


CClientListMgr::CClientListMgr()
{
	m_iTaskFlag = 0;
	m_curSessionID = 0;
	m_ClientNum = 0;
	m_ClientList.clear();
}

CClientListMgr::~CClientListMgr()
{
	for(map<UInt32,CClientSession*>::iterator it = m_ClientList.begin(); it != m_ClientList.end(); ++it)
	{
		delete (it->second);
	}

	//stop all ClientSessions
	while(!m_ClientList.empty()) usleep(1000);

	//release all clientsessions
	while(!m_UnusedList.empty())
	{
		delete m_UnusedList.front();
		m_UnusedList.pop();
	}
	
}

//取得全局实例
CClientListMgr* CClientListMgr::GetInstance()
{
	if (m_CClientListMgr == NULL)
	{
		m_CClientListMgr = new CClientListMgr();
		
		m_CClientListMgr->m_iTaskFlag = 1;
		m_CClientListMgr->Start();
	}
	return m_CClientListMgr;
}

//销毁全局实例
bool CClientListMgr::DelInstance()
{
	if (m_CClientListMgr != NULL)
	{
		m_CClientListMgr->Stop();
	//	delete this;
	}

	return TRUE;
}

//统一创建Client
CClientSession * CClientListMgr::CreateClient(Int32 v_inputFD)
{
	OSMutexLocker ClientListLocker(&m_Mutex_ClientList);
	m_curSessionID++;
	CClientSession* pClient = new CClientSession(m_curSessionID);
	if (pClient != NULL)
	{
		int Ret = pClient->Initialize(v_inputFD);
		if (Ret == TRUE)
		{
			pClient->m_iTaskFlag = 1;
			if(pClient->Start())
			{
				m_ClientList[m_curSessionID] = pClient;
				
				m_ClientNum++; //用户数加1				
				LOG("===========CreateClient, Cur User Num is %u\n", m_ClientNum); 
				printf("===========CreateClient, Cur User Num is %u\n", m_ClientNum); 
				return pClient;
			}
			else
			{
				LOG("ClientSession::RunTask failed!\n");
				m_ClientList.erase(m_curSessionID);
			}
		}
		else
		{
			LOG("ClientSession initialize failed!\n");
		}
		delete pClient;
	}
	else
	{
		LOG("ClientSession create failed!\n");
	}
	
	return NULL;
}


//统一析构Client
bool CClientListMgr::DestroyClient(UInt32 v_SessionID)
{

	OSMutexLocker ClientListLocker(&m_Mutex_ClientList);
	map<UInt32,CClientSession*>::iterator it = m_ClientList.find(v_SessionID);
	if (it != m_ClientList.end())
	{
		m_Mutex_UnusedList.Lock();
		m_UnusedList.push(it->second);
		m_unClientNum = m_UnusedList.size();
		m_Mutex_UnusedList.Unlock();
		
		m_ClientList.erase(it);

		m_ClientNum--; //用户数减1

		LOG("DestroyClient, Cur User Num is %u\n", m_ClientNum);
		printf("DestroyClient, Cur User Num is %u\n", m_ClientNum);
		return TRUE;
	}
	return FALSE;
}

int CClientListMgr::Stop()
{
//	LOG("================Task Stop!==============\n");
	m_iTaskFlag = 0;
	
	return 1;
}

int CClientListMgr::Run()
{
	CClientSession *pClient;
	time_t cur_time = 0;
	time_t old_time = 0;
	time_t check_time = 0;
	time_t record_time = 0;
	time_t account_time = 0;
	time_t count_time = 0;
	
	while(TRUE)
	{
 		m_Mutex_UnusedList.Lock();
 		while(!m_UnusedList.empty())
 		{
			/*
			if the clientsession block, it will caused others clientsession can't be release in time.
			*/
			pClient = m_UnusedList.front();
 			m_UnusedList.pop();			
			m_unClientNum = m_UnusedList.size();
	 		m_Mutex_UnusedList.Unlock();
 			if(pClient) pClient->Stop();
 			delete pClient;
 		//	LOG("pClient->DeleteTask end\n\n");
			
			m_Mutex_UnusedList.Lock();
 		}
 		m_Mutex_UnusedList.Unlock();

		//sleep
		usleep(1000*500);
		if(old_time == 0)
		{
			old_time = time(NULL);
			check_time = time(NULL);
			record_time = time(NULL);
			account_time = time(NULL);
		}
		cur_time = time(NULL);
		
		//每隔180秒钟检测是否需要更换文件
		if((cur_time - check_time) >= 180)
		{
			check_time = cur_time;
			if(CheckLogFileName() == 2)
			{
				version();
			}
		}
		
		//每隔30秒钟检测是否需要写新纪录
		if((cur_time - account_time) >= 10)
		{
			account_time = cur_time;
			if(EChain_AccountPrepare() < 0)
			{
				LOG("EChain_AccountPrepare failed!\n");
			}
		}
		
	}

	return 1;
}

UInt32 CClientListMgr::GetClientNum()
{
	return m_ClientNum;
}


