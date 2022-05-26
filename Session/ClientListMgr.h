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

	//hash����
	static OSMutex m_Mutex_ClientList;
	static OSMutex m_Mutex_UnusedList;
	//hash��ά��Client
	map<UInt32,CClientSession*>	m_ClientList;

	//release list
	std::queue<CClientSession *> m_UnusedList;
	//ȡ��ȫ��ʵ��
	static CClientListMgr* GetInstance();
	//����ȫ��ʵ��
	static bool DelInstance();
public:
	//ͳһ����Client
	CClientSession *  CreateClient(Int32 v_inputFD);

	//ͳһ����Client
	bool DestroyClient(UInt32 v_SessionID);

	int 		Stop();
	int		Run();
	
	UInt32 GetClientNum(); 
	
	UInt32 m_iTaskFlag;
	
private:
	//ȫ��ClientMgr����
	static CClientListMgr* m_CClientListMgr;

	//session id
	static UInt32 m_curSessionID;
	//session id ��
//	static OSMutex m_Mutex_SessionID;

	//�û���
	static UInt32 m_ClientNum;
public:
	static UInt32 m_unClientNum;		
};

extern CClientListMgr* g_ClientListMgr;



#endif

