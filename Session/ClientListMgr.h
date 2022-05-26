#ifndef __CLIENT__MGR__
#define  __CLIENT__MGR__
#ifdef __Win32__
#pragma warning(disable:4786)
#endif


#include <map>
#include <queue>
#include "OSMutex.h"
#include "OSType.h"
#include "OSTask.h"
#include "ClientSession.h"

using namespace std;


class CClientSession;

class CClientListMgr :public OSTask
{
private:
	CClientListMgr();
	virtual ~CClientListMgr();
public:

	//hash表锁
	static OSMutex m_Mutex_ClientList;
	static OSMutex m_Mutex_UnusedList;
	//hash表，维护Client
	map<UInt32,CClientSession*>	m_ClientList;

	//release list
	std::queue<CClientSession *> m_UnusedList;
	//取得全局实例
	static CClientListMgr* GetInstance();
	//销毁全局实例
	static bool DelInstance();
public:
	//统一创建Client
	CClientSession *  CreateClient(Int32 v_inputFD);

	//统一析构Client
	bool DestroyClient(UInt32 v_SessionID);

	int 		Stop();
	int		Run();
	
	UInt32 GetClientNum(); 
	
	UInt32 m_iTaskFlag;
	
private:
	//全局ClientMgr对象
	static CClientListMgr* m_CClientListMgr;

	//session id
	static UInt32 m_curSessionID;
	//session id 锁
//	static OSMutex m_Mutex_SessionID;

	//用户数
	static UInt32 m_ClientNum;
public:
	static UInt32 m_unClientNum;		
};

extern CClientListMgr* g_ClientListMgr;



#endif

