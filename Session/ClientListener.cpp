// ClientListener.cpp : implementation file
#include "ClientListener.h"
#include "ClientListMgr.h"
#include "ClientSession.h"
#include "Global.h"

CClientListener::CClientListener(Int32 v_ListenPort)
{
	
	if(v_ListenPort == 0)
	{
		m_ListenPort = 9999;
	}
	else
	{
		m_ListenPort = v_ListenPort;
	}
	
	m_ListenSocket = NULL;
	m_iTaskFlag = 0;
	
}

CClientListener::~CClientListener()
{
	Int32 i;
	LOG("Client listen socket Release...\n");
	
	if(m_ListenSocket)  
	{
		delete m_ListenSocket;
		m_ListenSocket = NULL;
		LOG("m_ListenSocket deleted\n");
	}
}

int CClientListener::Stop()
{
	m_iTaskFlag = 0;	
	return 1;
}

int CClientListener::Run()
{
	Int32 i, error;
	fd_set rfd; 
	struct timeval timeout;
	Int32	result;
	Int32 maxSocket;
	
loop:	
	m_ListenSocket = new TCPSocket;
	if(!m_ListenSocket)
	{
		LOG("Can't alloc m_ListenSocket\n");
		return -1;      
	}
	m_ListenSocket->SetLocalAddr("127.0.0.1",m_ListenPort);
	m_ListenSocket->ReuseAddr();
	error = m_ListenSocket->Bind();
	if(error < 0)
	{
		perror("Port bind error");
		LOG("m_ListenSocket bind error\n");
		delete m_ListenSocket;
		m_ListenSocket = NULL;
		return -1;
	}
	error = m_ListenSocket->Listen(32/*LISTENQ*/);
	if(error < 0)
	{
		perror("Listen error"); 
		LOG("m_ListenSocket listen error\n");
		delete m_ListenSocket;
		m_ListenSocket = NULL;
		return -1;
	}
//	m_ListenSocket->SetBlock(TRUE);
	
#if 1
	while(m_iTaskFlag)
	{
		FD_ZERO(&rfd); 
		FD_SET(m_ListenSocket->GetFD(),&rfd); 
		timeout.tv_sec=1; 
		timeout.tv_usec=0;
		maxSocket = m_ListenSocket->GetFD() + 1;
		result = select(maxSocket,&rfd,0, 0, &timeout);
		if(result == 0) 
		{
			continue;      
		}
		else if(result < 0)
		{
			perror("main listener");
			LOG("liseten socket select() gets error.\n");
			delete m_ListenSocket;
			m_ListenSocket = NULL;
			usleep(1000 * 1000);
			goto loop;
		}
		if(FD_ISSET(m_ListenSocket->GetFD(), &rfd))
		{
			Int32 iFD = (m_ListenSocket->Accept());
			if (iFD > 0)
			{
			//	LOG("m_ListenSocket->Accept() success, fd = %d\n", iFD);
				CClientSession* pClient = g_ClientListMgr->CreateClient(iFD);
				//创建成功返回 TRUE，否则返回 FALSE
				if (pClient== NULL)
				{
					LOG("ClientMgr create ClientSession failed!\n");
					shutdown(iFD,SHUT_RDWR);
					::close(iFD);
					return -1;
				}
			}
			else
			{
				LOG("m_ListenSocket accept() an illegal fd, continue looping\n");
			}
		}
	}
#else
	
#endif
	return 1;
}

