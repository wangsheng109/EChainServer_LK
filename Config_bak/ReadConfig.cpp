#include <stdio.h> 
#include <stdlib.h> 
#include <string.h> 
#include <sys/stat.h> 
#include "ReadConfig.h"
#include "Global.h"

#define MAX_VALUE_BUFFER_SIZE 256

#if 0
int		SConfigPara::m_ListenPort = 0;	//侦听客户端请求端口
int		SConfigPara::m_DebugLog = 0;		//系统运行日志
int		SConfigPara::m_MengAdFlag = 0;		//萌小蜜广告开关标志
	
string	SConfigPara::m_DBAddr;			//SQL服务器IP地址
int		SConfigPara::m_DBPort;			//SQL服务器PORT
string	SConfigPara::m_DBUser;			//SQL服务器用户名
string	SConfigPara::m_DBPassWd;		//SQL服务器密码
string	SConfigPara::m_DBName;			//SQL服务器数据库名
#endif

int ReadIniConfig::OpenIniFile(const char *pFile) 
{ 
	struct stat statbuf; 
	stat(pFile,&statbuf); 
	iBufferLen = 0;  
	if((fp=fopen(pFile, "r+")) == NULL)
	{
		LOG("fopen file %s failed!\n", pFile);
		return -1; 
	}
	if(fread( szBuffer,statbuf.st_size,1, fp) != 1) 
	{ 
		LOG("fread file %s failed!\n", pFile);
		if ( fp != NULL) fclose( fp); 
		 fp = NULL; 
		return -2; 
	} 
	
	 iBufferLen = statbuf.st_size; 
	return 0; 
} 

int ReadIniConfig::CloseIniFile() 
{ 
	if ( fp != NULL) 
	{ 
		if (!fclose( fp)) 
			return 0; 
		else 
			return -1; 
	} 
	else 
		return 0; 
} 

//获取配置文件指定的字符串
int ReadIniConfig::GetIniString(const char *pSection,const char *pIdent, char *pResult) 
{ 
	int i=0; 
	int j=0; 
	int min; 
	int iKeyFound=-1; 
	
	if (!strlen(pSection) || !strlen(pIdent) || ( fp == NULL)) 
	{
		return -1; 
	}
	
	while (i< iBufferLen) 
	{ 
		while ((i< iBufferLen) && 
			(( szBuffer[i]==' ') || ( szBuffer[i]=='\t'))) 
			i++; 
		if (i>= iBufferLen) 
			return -1; 
		if ( szBuffer[i]=='#') 
		{ //ignore the lines beginning with '#' 
			while ((i< iBufferLen) && ( szBuffer[i] != '\n')) 
				i++; 
			if (i>= iBufferLen) 
				return -1; 
			//Jump to the next line 
			i++; 
		} 
		else 
		{ 
			if ( szBuffer[i]=='[') 
			{ 
				i++; 
				while ((i< iBufferLen) && 
					(( szBuffer[i]==' ') || ( szBuffer[i]=='\t'))) 
					i++; 
				if (i>= iBufferLen) 
					return -1; 
				if (strncmp( szBuffer+i, pSection, strlen(pSection))==0)
				{ 
				//	LOG("pSection = %s,i = %d, szBuffer+i = %s\n", pSection, i, szBuffer+i);
					//Section may be found, let's see 
					i += strlen(pSection); 
					while ((i< iBufferLen) && 
						(( szBuffer[i]==' ') || ( szBuffer[i]=='\t'))) 
						i++; 
					if (i>= iBufferLen) 
						return -1; 
					if ( szBuffer[i]==']') 
						iKeyFound=0; 
					i++; 
					//matched ] or not, ignore the line 
					while ((i< iBufferLen) && ( szBuffer[i]!='\n')) 
						i++; 
					if (i>= iBufferLen) 
						return -1; 
					//Jump to the new line 
					i++; 
				}
				else
				{ //ignore the line and forward 
					while ((i< iBufferLen) && ( szBuffer[i]!='\n')) 
						i++; 
					if (i>= iBufferLen) return -1; 
					//Jump to the next line 
					i++; 
				} 
			} 
			else
			{ 
				if (iKeyFound != 0) { //Section has not found, ignore the line 
					while ((i< iBufferLen) && ( szBuffer[i] != '\n')) i++; 
					if (i>= iBufferLen) return -1; 
					//Jump to the new line 
					i++; 
				}
				else 
				{ //it may be the Identity to be found, judge it 
					if (strncmp( szBuffer+i, pIdent, strlen(pIdent))==0) { 
						i += strlen(pIdent); 
						
					//	LOG("pIdent = %s,i = %d, szBuffer+i = %s\n", pIdent, i, szBuffer+i);
						
						if (i>= iBufferLen) return -1; 
						while ((i< iBufferLen) && 
							(( szBuffer[i]=='\t') || ( szBuffer[i]==' '))) i++; 
						if ( szBuffer[i] == '=') 
						{ //Value has found 
							i++; 
							while ((i< iBufferLen) && 
								(( szBuffer[i]=='\t') || ( szBuffer[i]==' '))) i++; 
							if (i>= iBufferLen) return -1; 
							j=i; 
							while ((j< iBufferLen) && 
								( szBuffer[j]!='\n')) j++; j--; 
							while (( szBuffer[j]==' ') || 
								( szBuffer[j]=='\t')) j--; 
							min = j-i+1; 
							strncpy(pResult,  szBuffer+i, min); 
							*(pResult+min) = '\0'; 
							return 0; 
						} else { //ignore the line 
							while ((i< iBufferLen) && ( szBuffer[i]!='\n')) i++; 
							if (i>= iBufferLen) return -1; 
							//Jump to the next line 
							i++; 
						} 

					} 
					else 
					{ //ignore the line 
						while ((i< iBufferLen) && ( szBuffer[i]!='\n')) i++; 
						if (i>= iBufferLen) return -1; 
						//Jump to the next line 
						i++; 
					} 
				} 
			} 
		} 
	} 
	return -1; 
} 

//获取配置文件中的整形数
int ReadIniConfig::GetIniInteger(const char* pSection, const char* pIdent) 
{ 
	char szTempBuffer[MAX_VALUE_BUFFER_SIZE] = {0}; 
	if ( GetIniString(pSection, pIdent, szTempBuffer) == 0 )
	{ 
		if (strlen(szTempBuffer)>2)
		{ 
			if ( (szTempBuffer[0]=='0') && 
				( (szTempBuffer[1]=='x') || (szTempBuffer[1]=='X')) 
				)
				return (int)(strtol(szTempBuffer, (char **)NULL, 16)); 
		} 
		
		return atoi(szTempBuffer); 
	} 
	else 
	{
		LOG("GetIniString failed!\n");
		return 0; 
	}
} 


//获取配置文件中的长整形数
long ReadIniConfig::GetIniLong(const char* pSection, const char* pIdent) 
{ 
	char szTempBuffer[MAX_VALUE_BUFFER_SIZE] = {0}; 
	if ( GetIniString(pSection, pIdent, szTempBuffer) == 0 ) { 
		if (strlen(szTempBuffer)>2) { 
			if ( (szTempBuffer[0]=='0') && 
				( (szTempBuffer[1]=='x') || (szTempBuffer[1]=='X')) 
				) return (strtol(szTempBuffer, (char **)NULL, 16)); 
		} 
		return atol(szTempBuffer); 
	} else return 0; 
} 

double ReadIniConfig::GetIniDouble(const char* pSection, const char* pIdent) 
{ 
	char szTempBuffer[MAX_VALUE_BUFFER_SIZE]; 
	if ( GetIniString(pSection, pIdent, szTempBuffer) == 0 ) { 
		return atof(szTempBuffer); 
	} else return 0; 
} 

int	ReadIni()
{	
	//读取配置文件
	char temp[1024] = {0};
	SConfigPara::m_ListenPort =8888;
	SConfigPara::m_DebugLog = 1;
	return 1;

	ReadIniConfig * pMyconfig = new ReadIniConfig();
#ifdef WIN32
	pMyconfig->OpenIniFile("MengConf.ini");
#elif _LINUX_
	pMyconfig->OpenIniFile("MengConf.ini");
#endif

	SConfigPara::m_ListenPort = pMyconfig->GetIniInteger("Config","ListenPort");
	if(SConfigPara::m_ListenPort <= 0)
	{
		LOG("m_ListenPort <= 0 error!\n");
		return -1;
	}
	
	SConfigPara::m_DebugLog = pMyconfig->GetIniInteger("Config","DebugLog");
	if(SConfigPara::m_DebugLog < 0)
	{
		LOG("m_DebugLog < 0 error!\n");
		return -1;
	}

	SConfigPara::m_MengAdFlag = pMyconfig->GetIniInteger("Config","MengAdFlag");
	if(SConfigPara::m_MengAdFlag < 0)
	{
		LOG("m_MengAdFlag < 0 error!\n");
	//	return -1;
	}
	
	pMyconfig->GetIniString("MySQL","DBAddr",temp);
	SConfigPara::m_DBAddr = temp;
	if(SConfigPara::m_DBAddr.size() <= 0)
	{
		LOG("m_DBAddr error!\n");
		return -1;
	}
	SConfigPara::m_DBPort = pMyconfig->GetIniInteger("MySQL","DBPort");
	if(SConfigPara::m_DBPort < 0)
	{
		LOG("m_DBPort < 0 error!\n");
		return -1;
	}
	
	pMyconfig->GetIniString("MySQL","DBUser",temp);
	SConfigPara::m_DBUser = temp;
	if(SConfigPara::m_DBUser.size() <= 0)
	{
		LOG("m_DBUser error!\n");
		return -1;
	}
	pMyconfig->GetIniString("MySQL","DBPassWd",temp);
	SConfigPara::m_DBPassWd = temp;
	if(SConfigPara::m_DBPassWd.size() <= 0)
	{
		LOG("m_DBPassWd error!\n");
		return -1;
	}
	pMyconfig->GetIniString("MySQL","DBName",temp);
	SConfigPara::m_DBName = temp;
	if(SConfigPara::m_DBName.size() <= 0)
	{
		LOG("m_DBName error!\n");
		return -1;
	}
	
	pMyconfig->CloseIniFile();
	delete pMyconfig;

	return 1;
}


