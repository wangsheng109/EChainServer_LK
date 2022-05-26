#include "Socket.h"
#include "Global.h"

Socket::Socket()
{
	m_fd = 0;
        bzero(&m_Local_Addr, sizeof(m_Local_Addr));
	bzero(&m_Remote_Addr, sizeof(m_Remote_Addr));
}

Socket:: Socket(Int32 v_fd):m_fd(v_fd)
{

}

Socket::~Socket()
{

}


sockaddr_in Socket::GetLocalAddr()
{
	return m_Local_Addr;
}

sockaddr_in Socket::GetRemoteAddr()
{
	return m_Remote_Addr;
}
const Int8* Socket::GetLocalAddrByString()
{
  inet_ntop(AF_INET, &m_Local_Addr.sin_addr, local_addr_string, sizeof(local_addr_string));
  return local_addr_string;
}

const Int8* Socket::GetRemoteAddrByString()
{
  inet_ntop(AF_INET, &m_Remote_Addr.sin_addr, remote_addr_string, sizeof(remote_addr_string));
  return remote_addr_string;
}

UInt32 Socket::GetLocalPort()
{
  /*
  UInt32 ret = 0;
  socklen_t len = 0;
  sockaddr_in ftempaddr;
	
  bzero(&ftempaddr, sizeof(ftempaddr));
  len = sizeof(ftempaddr);
  ret = getsockname(m_fd,(struct sockaddr*)&ftempaddr,&len);
  */
  return ntohs(m_Local_Addr.sin_port);
  
}
UInt32 Socket::GetRemotePort()
{
  /*
  UInt32 ret = 0;
  socklen_t len = 0;
  sockaddr_in ftempaddr;
	
  bzero(&ftempaddr, sizeof(ftempaddr));
  len = sizeof(ftempaddr);
  ret = getpeername(m_fd,(struct sockaddr*)&ftempaddr,&len);
  */
  return ntohs(m_Remote_Addr.sin_port);
}

bool Socket::SetLocalAddr(const Int8 * v_ipaddr, UInt32  v_port)
{
	//assert(v_ipaddr);
	m_Local_Addr.sin_family = AF_INET;
	m_Local_Addr.sin_port = htons(v_port);
	//m_Local_Addr.sin_addr.s_addr = inet_addr(v_ipaddr);	
	m_Local_Addr.sin_addr.s_addr = INADDR_ANY;
	return TRUE;
}


bool Socket::SetRemoteAddr(const Int8 * v_ipaddr, UInt32 v_port)
{
	assert(v_ipaddr);
	m_Remote_Addr.sin_family = AF_INET;
	m_Remote_Addr.sin_port = htons(v_port);
	m_Remote_Addr.sin_addr.s_addr = inet_addr(v_ipaddr);

	return TRUE;
}



