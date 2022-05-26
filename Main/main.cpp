//#include "ReadConfig.h"
#include "ClientListMgr.h"
#include "ClientListener.h"
//#include "MySQLExecAPI.h"
#include "Global.h"
#include "OSMutex.h"
#include <unistd.h>
#include <sys/types.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <net/if.h>
#include <netinet/in.h>
#include <net/if_arp.h>
#include <arpa/inet.h>
#include <time.h>
#include <sys/resource.h>
#include <stdarg.h>
#include "librockey.h"

#include "api_echain_func.h"


FILE *bLogFile;
char bLogFileName[64] = {0};
time_t bTicks;
OSMutex bLogMutex;

bool bDaemon = TRUE;
bool bFork = TRUE;

bool bBQuit;


void BLOG(const char *fmt, ...)
{
	
	va_list vl;
	va_start(vl, fmt);
	
	bLogMutex.Lock();
	
	bTicks = time(NULL);
	fprintf(bLogFile, "%.24s ", ctime(&bTicks));
	
	vfprintf(bLogFile, fmt, vl);
	
	fflush(bLogFile);
	bLogMutex.Unlock();
	
	va_end(vl);
}

//struct tagDatabase_Param *g_pDataBase = NULL;
//HANDLE g_DBClass = NULL;

extern "C" 
{ 
	static void SigShutdown(int v_sig); 
}

int getFileLength(const char *pathname)
{	
	int	fd;	
	struct  stat    buf;	
	if ((fd = open(pathname, O_RDONLY)) < 0)	
	{		
		printf("open %s failed!\n", pathname);
		return -2;	
	}        
	if (fstat(fd, &buf) < 0)        
	{		
		printf("fstat error!\n");	
		close(fd);		
		return -1;        
	}	
	close(fd);	
	if (S_ISREG(buf.st_mode))		
		return(buf.st_size);		
	return -1;
}

int CheckLogFileName()
{
	char timebuf[64] = {0};
	time_t t;
    	struct tm tm_t;

	bLogMutex.Lock();
	
	t = time(NULL);
	if (localtime_r(&t, &tm_t) != NULL)
	{
		sprintf(timebuf,"%04d-%02d-%02d",tm_t.tm_year+1900,tm_t.tm_mon+1,tm_t.tm_mday);
	}
	
	//只比较形如"2012-07-12"的部分, 如不相同，则需更新日志文件
	if(strncmp(bLogFileName, timebuf, 10) != 0)
	{
		fclose(bLogFile);
		bLogFile = NULL;
		sprintf(bLogFileName, "%s-%02d-%02d.log", timebuf, tm_t.tm_hour, tm_t.tm_min);
		bLogFile = fopen(bLogFileName, "w+");
		if(!bLogFile)
		{
			printf("Can't open log file!\n");
			bLogMutex.Unlock();
			return -1; 
		}
		memset(bLogFileName, 0, 64);
		memcpy(bLogFileName, timebuf, strlen(timebuf));
		bLogMutex.Unlock();
		return 2;
	}
	
	int iSize = getFileLength(bLogFileName);
	if(iSize < 0)
	{
		printf("getFileLength failed!\n");
		bLogMutex.Unlock();
		return -2;
	}
	//文件名超出指定大小，需换文件
	else if(iSize >= 10 * 1024 * 1024)
	{
		fclose(bLogFile);
		bLogFile = NULL;
		sprintf(bLogFileName, "%s-%02d-%02d.log", timebuf, tm_t.tm_hour, tm_t.tm_min);
		bLogFile = fopen(bLogFileName, "w+");
		if(!bLogFile)
		{
			printf("Can't open log file!\n");
			bLogMutex.Unlock();
			return -1; 
		}
		bLogMutex.Unlock();
		return 2;
	}
	bLogMutex.Unlock();
	return 1;
}





void version()
{
	BLOG("************************************************\n");
	BLOG("	    EChainServer\n");
	BLOG("	    Version: %s\n", VERSION);
	BLOG("	    Build:   %s %s \n",__DATE__, __TIME__);
	BLOG("************************************************\n");

	
}

void usage()
{
	BLOG("Usage: EChainServer [-h] [-v] [-s] [-d]\n"
			"	-h  : help information\n"
			"	-v  : version information\n"
			"	-s  : single process\n"
			"	-d  : non-daemon\n"
			);
}



void version_printf()
{
	printf("************************************************\n");
	printf("	    EChainServer\n");
	printf("	    Version: %s\n", VERSION);
	printf("	    Build:   %s %s \n",__DATE__, __TIME__);
	printf("************************************************\n");
}

//设置允许打开的文件描述符个数
int set_ofile_limit(int open_num)
{
#ifdef __linux__
	struct rlimit limit, nlimit;
	
    if(getrlimit(RLIMIT_NOFILE, &limit) != 0)
   {
        BLOG("get limit failed\n");
	
        return -1;
    }
// BLOG("limit.rlim_cur = %d, limit.rlim_max = %d\n", limit.rlim_cur, limit.rlim_max);
    limit.rlim_cur = open_num;
    limit.rlim_max = open_num;
    if(setrlimit(RLIMIT_NOFILE, &limit) != 0)
    {
        BLOG("set limit failed\n");
        return -1;
    }
	char logbuff[256] = {0};
	sprintf(logbuff,"setrlimit %d success!",open_num);
	BLOG("setrlimit %d success!\n", open_num);
 #endif       
	return 1;
}

//初始化客户Mgr
bool InitClientListMgr()
{
//	BLOG("Initialize client list manager ......");
	g_ClientListMgr = CClientListMgr::GetInstance();
	if (g_ClientListMgr == NULL)
		return FALSE;
//	BLOG("\t\t\tdone\n");
	return TRUE;
}

int RunServer()
{
/*	
	if(ReadIni() < 0)
	{
		BLOG("ReadIni failed!\n");
		return -1;
	}
*/
	int iDebugLog = 1;
		
//if(SConfigPara::m_DebugLog == 1)
	if(iDebugLog == 1)
	{
		int year, month, day, hour, minute;
		time_t cur_time;
		struct	tm	ptr;
	//	printf("11111111111111\n");
		cur_time = time(NULL);
		if (localtime_r(&cur_time, &ptr) != NULL)
		{
			sprintf(bLogFileName, "%04d-%02d-%02d-%02d-%02d.log", ptr.tm_year+1900,
				ptr.tm_mon+1, ptr.tm_mday, ptr.tm_hour, ptr.tm_min);
		}
		else
		{
			strcpy(bLogFileName, "XChainServer.log");
		}
	//	printf("22222222222\n");
	//	BLOG("create log file %s!\n", bLogFileName);
		bLogFile = fopen(bLogFileName, "w+");
	//	bLogFile = stderr;//fopen("log.txt", "w");
		if(!bLogFile)
		{
			BLOG("Can't open log file!\n");
			exit(1); 
		}
	//	printf("33333333333333\n");
		
	}
	else
	{
		bLogFile = stderr;
	}
	
#ifdef _LINUX_
	struct rlimit rl;
	rl.rlim_cur = 1024*50;
	rl.rlim_max = 1024*50;
	setrlimit(RLIMIT_NOFILE, &rl);

	//printf("44444444444444\n");
	
	signal(SIGTERM,SigShutdown);	//终止信号
	signal(SIGUSR1,SigShutdown);
	signal(SIGUSR2,SigShutdown);

	//printf("55555555555\n");
	//忽略的信号 ignore terminal I/O, stop signals
	signal(SIGTTOU,SIG_IGN);
	signal(SIGTTIN,SIG_IGN);
	signal(SIGTSTP,SIG_IGN);

	signal(SIGPIPE,SIG_IGN);	//管道出错

	//安装CTRL+C捕捉器
	signal(SIGINT,SigShutdown);
#endif
	//printf("666666666666\n");
	version();
	version_printf();

	//printf("777777777777777\n");

	//初始化客户端Mgr
	if (InitClientListMgr() == FALSE)
	{
		BLOG("Init Client List Manager\t\tfailed!\n");
		printf("Init Client List Manager\t\tfailed!\n");
		return -1;
	}
	BLOG("Init Client List Manager\t\tsuccess!\n");
	printf("Init Client List Manager\t\tsuccess!\n");

/*
	//初始化数据库链接
	if(InitDataBasesConnection() == FALSE)
	{
		BLOG("Init DataBases Connection\t\tfailed!\n");
		printf("Init DataBases Connection\t\tfailed!\n");
		return -1;
	}
	
	BLOG("Init DataBases Connection\t\tsuccess!\n");
	printf("Init DataBases Connection\t\tsuccess!\n");
*/
	//初始化EChain SDK
	if(EChain_InitSDK() < 0)	
	{		
		BLOG("EChain_InitSDK failed!\n");	
		printf("EChain_InitSDK failed!\n");	
		return -1;	
	}
	
//	CClientListener *pClientListener = new CClientListener(SConfigPara::m_ListenPort);
	CClientListener *pClientListener = new CClientListener(8888);
//	CClientListener *pClientListener = new CClientListener(9999);
	pClientListener->m_iTaskFlag = 1;
	pClientListener->Start();
	BLOG("pClientListener Started\t\t\tsuccess!\n");
	printf("pClientListener Started\t\t\tsuccess!\n");
	BLOG("\n************* Block Server Start *************\n");
	
#ifdef _LINUX_
// 	BLOG("setrlimit()\n");
//	struct rlimit rl;
    	rl.rlim_cur = 1024*50;
    	rl.rlim_max = 1024*50;
    	setrlimit(RLIMIT_NOFILE, &rl);
// 	set it to the absolute maximum that the operating system allows - have to be superuser to do this
#endif
	bBQuit = false;
	unsigned int timeJiffer = 0;
	while(!bBQuit)
	{
		OS_Sleep(1000);
	}
	delete pClientListener;
	
	return 0;
}

//信号处理
void SigShutdown(int v_sig)
{
	bBQuit=TRUE;	
	return;
}

int main(int argc, char* argv[])
{
#ifdef _LINUX_
	bool bDaemon = TRUE;
	bool bFork = TRUE;

	//version
	if (argc > 1)
	{
		for (int i = 1; i < argc; i++)
		{
			if (strcasecmp(argv[i],"-h") == 0)
			{
				usage();
				return 0;
			}
			else if (strcasecmp(argv[i],"-v") == 0)
			{
				version();
				return 0;
			}
			else if (strcasecmp(argv[i],"-d") == 0)
			{
				bDaemon = FALSE;
			}
			else if (strcasecmp(argv[i],"-s") == 0)
			{
				bFork = FALSE;
			}
		}
	}

	//daemon
	if(bDaemon) 
		if(daemon(1,0) != 0) {//redirect input output errput to /dev/null.
			BLOG("Change to daemon failed\n");
			return -1;
		}

	//fork
	if(!bFork) {
		//single process
		return RunServer();
	}
	else {
		//multi-process
		while(TRUE) {
			pid_t child;
			child = fork();
			if( child <0 ) {
				printf("Fork child process failed\n");
			} else if( child == 0) {
				//child
				bBQuit = FALSE;
				bDaemon = TRUE;
				return RunServer();
			} else {
				//parent
				int iStatus;
				int iRet = wait(&iStatus);
				if(iRet >=0 ) {
					//printf("Child status [%d]\n",iStatus);
					/*
						if child return error code, quit processes
						else restart child
					*/
					if(WIFEXITED(iStatus)) {
						//child quit normally
						printf("Child process quit normally, restart it.\n");
					
					}
					if(WEXITSTATUS(iStatus)) {
						//child quit with error code
						printf("Child process quit on error code[%d]!!!\n",iStatus);
					
						break;
					}
					if(WIFSIGNALED(iStatus)) {
						printf("Child process terminate on exception!!! restart it\n");
					
					}
				} else {
					printf("Wait child failed\n");
					return -1;
				}
			}
		}
	}
#elif WIN32
	return RunServer();
#endif
	
	return 0;
}

