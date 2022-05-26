#include "TCPSocket.h"
#include "Global.h"
//#include <stropts.h>



TCPSocket::TCPSocket()
{
	m_fd = socket(AF_INET,SOCK_STREAM,0);
}


TCPSocket::TCPSocket(Int32 v_fd)
{
	UInt32 ret = 0;
	socklen_t len = 0;
	sockaddr_in ftempaddr;
	
	m_fd = v_fd;
	
	//get local addr
	bzero(&ftempaddr, sizeof(ftempaddr));
	len = sizeof(ftempaddr);
	ret = getsockname(m_fd,(struct sockaddr*)&ftempaddr,&len);
	if (ret == 0)
	SetLocalAddr(inet_ntoa(ftempaddr.sin_addr),ntohs(ftempaddr.sin_port));
	
	//get remote addr
	bzero(&ftempaddr, sizeof(ftempaddr));
	len = sizeof(ftempaddr);	
	ret = getpeername(m_fd,(struct sockaddr*)&ftempaddr,&len);
	if (ret == 0)
		SetRemoteAddr(inet_ntoa(ftempaddr.sin_addr),ntohs(ftempaddr.sin_port));
	
}

TCPSocket::~TCPSocket()
{
 	CloseSocket();
}

bool TCPSocket::CloseSocket()
{
	if(m_fd != -1)
	{
		::shutdown(m_fd,SHUT_RDWR);
	  	::close(m_fd);
	  	m_fd = -1;
	}
	return TRUE;
}

bool TCPSocket::Connect()
{
	return connect(m_fd,(struct sockaddr*)&m_Remote_Addr,sizeof(m_Remote_Addr));
}

socklen_t TCPSocket::SendData(const char * v_senddata,const UInt32 v_len)
{
  	UInt32 sended = 0;
  	Int32 ret;

  	while(sended < v_len)
	{
		ret  = ::send(m_fd, v_senddata + sended, v_len - sended, 0);
		if (ret < 0)
		{
			if(errno == EINTR)
			{
				ret = 0;
			}
			else
			{
				LOG("send fun exit, errno = %d, exit info is %s!\n", errno, strerror(errno));
		      		return -1;
		      	}
		}
		sended += ret;
	}
  	return v_len;
}

socklen_t TCPSocket::RecvData(char * v_Buffer, socklen_t v_len)
{
	Int32 ret = 0;
	ret = recv(m_fd,v_Buffer,v_len,0);
	if(ret <= 0)
	{
		if(errno == EINTR)
		{
			LOG("recv fun interrupted by signal!\n");
			return 0;
		}
		else
		{
			LOG("recv fun exit, errno = %d, exit info is %s!\n",  errno, strerror(errno));
			return (-1);
		}
	}
	return ret;
}


bool TCPSocket::Listen(UInt32 acceptcount)
{
	return listen(m_fd,acceptcount);
}


Int32 TCPSocket::Accept()
{
	socklen_t len = sizeof(m_Local_Addr);
        return accept(m_fd, NULL, NULL);//(struct sockaddr*)&m_Local_Addr,&len);
}

bool TCPSocket::Bind()
{
  return ::bind(m_fd,(struct sockaddr*)&m_Local_Addr,sizeof(m_Local_Addr));
}


UInt32 TCPSocket::GetFD()
{
  return m_fd;
}

bool TCPSocket::SetBlock(bool v_Block)
{
  unsigned long temp = 1;
  UInt32 ret = 0;
  if (v_Block == TRUE)
    temp = 0;

//  ret = ::ioctl(m_fd,FIONBIO,&temp);

  return ret;
}

bool TCPSocket::ReuseAddr()
{
  const Int8 temp = 1;	
  return setsockopt(m_fd,SOL_SOCKET,SO_REUSEADDR,&temp,sizeof(Int32));
}

Int32 TCPSocket::SetSendTimeOut(Int32 seconds)
{
	struct timeval timeout; 
	Int32 ret;
	if((seconds > 0) && (seconds < 60))
	{
		timeout.tv_sec = seconds; 
    		timeout.tv_usec =0;
	}
	else
	{
		timeout.tv_sec = 30; 
    		timeout.tv_usec =0;
	}
	ret   =   setsockopt(m_fd, SOL_SOCKET, SO_SNDTIMEO, (Int8 *)&timeout, sizeof(timeout));
	return ret;
}
