#include "OS.h"
#include "OSMutex.h"

/////////////全局变量////////////////////////////////////

Std_CallBack g_std_CallBack = NULL;

///////////////全局函数//////////////////////////////////

//处理CTRL + C信号
int32  g_system_quit = 0;

int32  OS_InitSystem()
{
#ifdef WIN32

	WORD wVersionRequested;//版本号
	WSADATA wsaData;

	wVersionRequested = MAKEWORD( 1, 1 );//1.1版本的套接字
	int32 err;
	err = WSAStartup( wVersionRequested, &wsaData );
	if ( err != 0 ) 
	{
		return 0;
	}//加载套接字库，加裁失败则返回

#else//////////////////////// __linux__
/*
    //grow our pool of file descriptors to the max!
    struct rlimit rl;
    // set it to the absolute maximum that the operating system allows - have to be superuser to do this
    rl.rlim_cur = 1024*20;
    rl.rlim_max = 1024*20;
    setrlimit(RLIMIT_NOFILE, &rl);

	signal(SIGTERM,SigFunc);	//终止信号
	signal(SIGUSR1,SigFunc);
	signal(SIGUSR2,SigFunc);

	//忽略的信号
	// ignore terminal I/O, stop signals /
	signal(SIGTTOU,SIG_IGN);
	signal(SIGTTIN,SIG_IGN);
	signal(SIGTSTP,SIG_IGN);

	signal(SIGPIPE,SIG_IGN);	//管道出错
	//signal(SIGCHLD,SIG_IGN);	//child发送终止信号给parent, 多进程时不能忽略,否则父进程的wait会失败

	//set env
	if(setenv("LD_LIBRARY_PATH","../../lib:$LD_LIBRARY_PATH",1) != 0) {
		LOG("Set env failed\n");
		return -1;
	}
*/
#endif

	//安装CTRL+C捕捉器
//	signal(SIGINT,SigFunc);


	return 1;
}

void  OS_Sleep(int32 n)
{	
#ifdef WIN32
	Sleep(n);
#else
	usleep(n * 1000);
#endif
}


int32    OS_GetErrno()
{
#ifdef WIN32
	
    int32 winErr = ::GetLastError();
	
    // Convert to a POSIX errorcode. The *major* assumption is that
    // the meaning of these codes is 1-1 and each Winsock, etc, etc
    // function is equivalent in errors to the POSIX standard. This is 
    // a big assumption, but the server only checks for a small subset of
    // the real errors, on only a small number of functions, so this is probably ok.
    switch (winErr)
    {
		
	case ERROR_FILE_NOT_FOUND: return ENOENT;
		
	case ERROR_PATH_NOT_FOUND: return ENOENT; 
		
	case WSAEINTR:      return EINTR;
	case WSAENETRESET:  return EPIPE;
	case WSAENOTCONN:   return ENOTCONN;
	case WSAEWOULDBLOCK:return EAGAIN;
	case WSAECONNRESET: return ECONNRESET;
	case WSAEADDRINUSE: return EADDRINUSE;
	case WSAEMFILE:     return EMFILE;
	case WSAEINPROGRESS:return EINPROGRESS;
	case WSAEADDRNOTAVAIL: return EADDRNOTAVAIL;
	case WSAECONNABORTED: return EPIPE;
	case 0:             return 0;
        
	//default:            return ENOTCONN;
	default:            return winErr;
    }
	
#else
	return errno; 
#endif
}


int32 OS_CloseSocket(int32 fd)
{
	if(fd < 0)
		return 1;
#ifdef WIN32
		shutdown(fd,SD_BOTH);
		closesocket(fd);
#else
		shutdown(fd,SHUT_RDWR);
		close(fd);
#endif

		return 1;
}

unsigned long OS_Gettickcount()
{
#ifdef WIN32 
	return GetTickCount();
#else
	timeval tv;
	gettimeofday(&tv, NULL);
	return tv.tv_sec*1000L+tv.tv_usec/1000L;
#endif
}

int		OS_strupr(char* str)
{
	int len = strlen(str);
	for  (int i=0;i<len;i++)
	{
		if ( str[i] >= 'a' && str[i] <= 'z' )
		{
			str[i] = 'A'+(str[i]-'a');
		}
	}
	return 1;
}

int		OS_strlwr(char* str)
{
	int len = strlen(str);
	for  (int i=0;i<len;i++)
	{
		if ( str[i] >= 'A' && str[i] <= 'Z' )
		{
			str[i] = 'a'+(str[i]-'A');
		}
	}
	return 1;
}
