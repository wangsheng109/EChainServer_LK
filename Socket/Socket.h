#ifndef __OS__SOCKET__
#define  __OS__SOCKET__

#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <netdb.h>

#include <string.h>
#include <assert.h>
#include "OSType.h"


class Socket
{
public:
	Socket();
	Socket(Int32 v_fd);
	virtual ~Socket();
public:

	sockaddr_in GetLocalAddr();

	sockaddr_in GetRemoteAddr();
        
        UInt32 GetLocalPort();
        UInt32 GetRemotePort();
                
        const Int8* GetLocalAddrByString();
        const Int8* GetRemoteAddrByString();
        

	bool SetLocalAddr(const Int8* v_ipaddr,UInt32  v_port);

	bool SetRemoteAddr(const Int8* v_ipaddr,UInt32 v_port);
        

        
        Int8 local_addr_string[20];
        Int8 remote_addr_string[20];
            
  public:
    virtual bool Bind() = 0;
  public:

    virtual bool SetBlock(bool v_Block) = 0;

    virtual bool ReuseAddr() = 0;

    virtual UInt32 GetFD() = 0;
public:

	virtual socklen_t SendData(const char* v_senddata,const UInt32 v_len) = 0;	

	virtual socklen_t RecvData(char* v_Buffer,socklen_t v_len) = 0;
        
        virtual bool Connect() = 0;
        
        virtual bool Listen(UInt32 acceptcount) = 0;
        
        virtual Int32 Accept() = 0;

protected:
	sockaddr_in m_Local_Addr;
	sockaddr_in m_Remote_Addr;
protected:
	UInt32 m_fd;
};

#endif

