#ifndef __OS_TCP_SOCKET__
#define  __OS_TCP_SOCKET__

#include "Socket.h"

class TCPSocket:public Socket
{
public:
	TCPSocket();
	TCPSocket(Int32 v_fd);
	virtual ~TCPSocket();
public:
	virtual bool Connect();
	bool CloseSocket();
	virtual bool Listen(UInt32 acceptcount);
	virtual Int32 Accept();
        
        
public:
	virtual socklen_t SendData(const char* v_senddata,const UInt32 v_len);
	virtual socklen_t RecvData(char* v_Buffer,socklen_t v_len);
  public:
    virtual bool Bind();
  public:

    virtual bool SetBlock(bool v_Block);

    virtual bool ReuseAddr();
    
    virtual Int32 SetSendTimeOut(Int32 seconds);
    
    virtual UInt32 GetFD();
};

#endif

