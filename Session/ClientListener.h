#ifndef CLIENT_LISTENER_H
#define CLIENT_LISTENER_H

#include "OSType.h"
#include "OSTask.h"
#include "TCPSocket.h"


class CClientListener : public OSTask
{
public:
	
	CClientListener(Int32 v_ListenPort);           
	virtual ~CClientListener();

public:

	int		m_iTaskFlag;
	Int32		m_ListenPort;
	TCPSocket*	m_ListenSocket;
	
protected:
	int 		Stop();
	int		Run();
	
};

#endif  //CLIENT_LISTENER_H

