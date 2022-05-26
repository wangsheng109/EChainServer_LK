#ifndef __OSHEADER_H__
#define __OSHEADER_H__

/******************************************************************************

  windows header & #define

******************************************************************************/
#ifdef WIN32 ////////////////windows/////////////////////////
#include <string.h>
#include <malloc.h>
#include <memory.h>
#include <time.h>
#include <io.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <share.h>
#include <errno.h>
#include <stdlib.h>
#include <stdio.h>
#include "winsock2.h"
#include "windows.h"

#include <mswsock.h>
#include <process.h>

#include <sys/timeb.h> //这句什么意思?? 
#include <time.h> 
#include <direct.h>   
#include "sys/stat.h"

#include <dos.h>   
#include <io.h>   
#include <signal.h>

#include <ws2tcpip.h>


#define STD_API extern "C" __declspec(dllexport)


#define int8    char
#define uint8   unsigned char 
#define int16   short
#define uint16  unsigned short 
#define int32   int
#define uint32  unsigned int 
#define int64   __int64
#define uint64  unsigned __int64


#define  HANDLE_FILE   void *

typedef int32	SOCK_LEN;

#define snprintf  _snprintf
#pragma pack(push,1)
#define PACKED 

#pragma pack(pop)

#define ENOTCONN 1002
#define ECONNRESET 1003
#define EADDRINUSE 1004
#define EINPROGRESS 1007
#define ENOBUFS 1008
#define EADDRNOTAVAIL 1009

#pragma   warning(disable:4786)

/******************************************************************************

  linux header & #define

******************************************************************************/
#else////////////////////linux///////////////////////
#include <string.h>
#include <malloc.h>
#include <memory.h>
#include <time.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <errno.h>
#include <stdlib.h>
#include <stdio.h>
#include <ctype.h>
#include <pthread.h>
#include <semaphore.h>
#include <stdarg.h>

#include  <sys/ioctl.h>
#include  <sys/socket.h>
#include  <net/if.h>
#include  <netinet/in.h>
#include  <net/if_arp.h>
#include  <arpa/inet.h>
//#include  <iostream.h>
#include  <dlfcn.h>

#include <sys/epoll.h>

#include <sys/errno.h>
#include <pthread.h>
#include <signal.h>

#include <vector>
#include <map>
#include <list>

#include <poll.h>
#include <limits.h>
#include <signal.h>
#include <sys/time.h>

#include <sys/resource.h>
#include <sys/wait.h>


#define STD_API extern "C"





#define int8    char
#define uint8   unsigned char 
#define int16   short
#define uint16  unsigned short 
#define int32   int
#define uint32  unsigned int 
#define __int64 long long
#define int64   long long
#define uint64  unsigned long long


#define  HANDLE_FILE   void *

#define SOCKET int32
typedef struct sockaddr_in	SOCKADDR_IN;
typedef  socklen_t			SOCK_LEN;


#define  _O_RDONLY		O_RDONLY       
#define  _O_WRONLY		O_WRONLY       
#define  _O_RDWR		O_RDWR         
#define  _O_APPEND		O_APPEND       
#define  _O_CREAT		O_CREAT        
#define  _O_TRUNC		O_TRUNC        
#define  _O_EXCL		O_EXCL         
#define  _O_TEXT		O_TEXT         
#define  _O_BINARY		0    
#define  _O_TEMPORARY	O_TEMPORARY    
#define  _O_NOINHERIT	O_NOINHERIT
#define  _O_SEQUENTIAL	O_SEQUENTIAL
#define  _O_RANDOM		O_RANDOM       


#define _SH_DENYRW		SH_DENYRW 
#define _SH_DENYWR		SH_DENYWR 
#define _SH_DENYRD		SH_DENYRD 
#define _SH_DENYNO		SH_DENYNO 


#define _S_IFMT			S_IFMT   
#define _S_IFDIR		S_IFDIR  
#define _S_IFCHR		S_IFCHR  
#define _S_IFREG		S_IFREG  
#define _S_IREAD		S_IREAD  
#define _S_IWRITE		S_IWRITE 
#define _S_IEXEC		S_IEXEC  

#define _sopen(a,b,c,d)	open(a,b)
#define _lseeki64		lseek
#define _read			read
#define _write			write
#define _close			close

#define stricmp         strcasecmp
#define _stricmp		strcasecmp 
#define _strnicmp		strncasecmp

#define PACKED __attribute__((__packed__)) 

#endif
#endif //__OSHEADER_H__
