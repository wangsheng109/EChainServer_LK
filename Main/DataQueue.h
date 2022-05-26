#ifndef __UDP_DATA_QUEUE_H__
#define __UDP_DATA_QUEUE_H__

//#include "pub_stdafx.h"
#include "OSType.h"
#include "Global.h"
#define LINUX_PLATFORM

template<class T>
class TDataQueue  
{
public:
	TDataQueue()
	{
#ifndef LINUX_PLATFORM
	InitializeCriticalSection(&m_csLockSyn);
#else
	pthread_mutexattr_init(&m_lockattr);
	pthread_mutexattr_settype(&m_lockattr,PTHREAD_MUTEX_RECURSIVE);
	pthread_mutex_init(&m_csLockSyn,&m_lockattr);
#endif

		m_nQueueSize	= 0;
		m_pHead			= 0;
		m_pTail			= 0;
	}
	virtual ~TDataQueue()
	{
#ifndef LINUX_PLATFORM
	DeleteCriticalSection(&m_csLockSyn);
#else
	pthread_mutex_destroy(&m_csLockSyn);
	pthread_mutexattr_destroy(&m_lockattr);
#endif
	}
private:
#ifdef WIN32
	CRITICAL_SECTION    m_csLockSyn;
#else
	pthread_mutex_t		m_csLockSyn;
	pthread_mutexattr_t m_lockattr;
#endif

public:
	Int32			size()
	{
		return m_nQueueSize;
	}
	void		Clear();
private:
	T 			m_pHead;
	T 			m_pTail;

	Int32			m_nQueueSize;
public:
	Int32				push_front(T	pNode)
	{
#ifndef LINUX_PLATFORM
		EnterCriticalSection(&m_csLockSyn);
#else
		pthread_mutex_lock(&m_csLockSyn);
#endif
		pNode->pFirst	= 0;
		pNode->pNext	= 0;
		if ( m_pHead == 0 )
		{
			m_pHead			= pNode;
			m_pTail			= pNode;
			m_nQueueSize	= 1;
		}
		else
		{
			pNode->pFirst = 0;
			pNode->pNext  = m_pHead;

			m_pHead = pNode;
			m_nQueueSize ++;
		}
#ifndef LINUX_PLATFORM
		LeaveCriticalSection(&m_csLockSyn);
#else
		pthread_mutex_unlock(&m_csLockSyn);
#endif
		return 1;
	}
	Int32			push_back(T 	 pNode)
	{
#ifndef LINUX_PLATFORM
		EnterCriticalSection(&m_csLockSyn);
#else
		pthread_mutex_lock(&m_csLockSyn);
#endif
		
		pNode->pFirst	= 0;
		pNode->pNext	= 0;
		
		if ( m_pHead == 0 )
		{
			m_pHead			= pNode;
			m_pTail			= pNode;
			m_nQueueSize	= 1;
		}
		else
		{
			m_pTail->pNext = pNode;
			pNode->pFirst	= m_pTail;
			m_pTail = pNode;
			m_nQueueSize ++;
		}
#ifndef LINUX_PLATFORM
		LeaveCriticalSection(&m_csLockSyn);
#else
		pthread_mutex_unlock(&m_csLockSyn);
#endif
		return m_nQueueSize;
	}
	T 			pop_front()
	{
		T	pNode = 0;
		
#ifndef LINUX_PLATFORM
		EnterCriticalSection(&m_csLockSyn);
#else
		pthread_mutex_lock(&m_csLockSyn);
#endif
		
		if(m_pHead == 0 )
		{
			m_nQueueSize	= 0;
			m_pTail			= 0;
			
#ifndef LINUX_PLATFORM
			LeaveCriticalSection(&m_csLockSyn);
#else
			pthread_mutex_unlock(&m_csLockSyn);
#endif
			return  0;
		}
		
		pNode			= m_pHead;
		m_pHead			= m_pHead->pNext;
		if (m_pHead != 0 )
			m_pHead->pFirst	= 0;
		else	m_pTail	 =0 ;		
		
		m_nQueueSize --;
		if (m_nQueueSize < 0 )
			m_nQueueSize= 0;
		
		pNode->pFirst	= 0;
		pNode->pNext	= 0;
		
#ifndef LINUX_PLATFORM
		LeaveCriticalSection(&m_csLockSyn);
#else
		pthread_mutex_unlock(&m_csLockSyn);
#endif
		return pNode;
	}

};

#endif
