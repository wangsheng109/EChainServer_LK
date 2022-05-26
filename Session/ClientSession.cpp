#include <vector>
#include <time.h>
#include <ctype.h>
#include "Global.h"
 #include <strings.h>
#include "ClientListMgr.h"
#include "ClientSession.h"
//#include "ReadConfig.h"
//#include "MySQLExecAPI.h"
#include "md5.h"
#include <time.h>
#include <sys/time.h>
#include "json_tokener.h"
#include "bits.h"
#include "api_echain_func.h"
using namespace std;


const char *szProtocalInfo[] = 
{
	"InitHttpType",
	"UserRegister.do",
	"UserCertification",
	"CreateContractAddress.do",
	"BusinessDataStorage.do",
	"BusinessDataUpdate.do",
	"ContractAddressDelete.do",
	"IntegrityVerification.do",
	"DataSharedContent.do",
	"DataSharedResult.do",
	"QueryAddressRecord.do",
	"QueryTransactionHashRecord.do",
	"QueryBlockBrowser.do",
	"QueryBlockTransaction.do",
	"QueryChainInfo.do",
	"QueryNonceInfo.do",
	"IssueAsset.do"
	
};


//生成当前的日期字符串//
static char const* dateHeader() 
{	
	static char buf[200];	
	time_t tt = time(NULL);	
	strftime(buf, sizeof buf, "Date: %a, %b %d %Y %H:%M:%S GMT", gmtime(&tt));	
	return buf;	
}

static int url_decode(char *str)   
{   
    char *dest = str;   
    char *data = str;   
    int len = strlen(str);
	int urlpos = 0;
  
    while (len--)    
    {   
		//匹配%20 过滤首匹配
        if (0 != urlpos && *data == '%' && len >= 2 && isxdigit((int) *(data + 1)) && isxdigit((int) *(data + 2)))    
        {   
						char *s = data + 1;
			
						//hex to char begin  //php_htoi(s);
						int value;   
						int c;     
						c = ((unsigned char *)s)[0];   
						if (isupper(c))   
							c = tolower(c);   
						value = (c >= '0' && c <= '9' ? c - '0' : c - 'a' + 10) * 16;   
			  
						c = ((unsigned char *)s)[1];   
						if (isupper(c))   
							c = tolower(c);   
						value += c >= '0' && c <= '9' ? c - '0' : c - 'a' + 10;   
			
						*dest = (char)value; 
						//hex to char end

            data += 2;   
            len -= 2;   
        }    
        else    
        {   
			urlpos++;
            *dest = *data;   
        }   
        data++;   
        dest++;   
    }
	//  "rtsp://192.168.1.1/abc.3gp   "
    *dest = '\0';
	//去掉后面的空格
	int ndestlen = dest - str;
	while (ndestlen--)
	{
		if (*(str+ndestlen) == ' ')
		{
			*(str+ndestlen) = '\0';
		}
		else
		{
			break;
		}
	}
    return ndestlen++;   
}

int getTimemisc()
{
	int iCurTime = 0;
	struct timeval tv;
    gettimeofday(&tv,NULL);
	iCurTime = tv.tv_sec*1000 + tv.tv_usec/1000;
	return iCurTime;
}

CClientSession::CClientSession(UInt32 v_SessionID)
{
	m_SessionID = v_SessionID;
	m_SocketFD = -1;
	m_EpollFD = -1;
	m_iTaskFlag = 0;
	m_RecvBuf = NULL;
	m_RecvSize  = 0;
	

	memset(m_UserAgent, 0, MAX_USERAGENT_LEN);
	m_SendBuf = NULL;
	m_SendLen = 0;
	memset(m_HttpParam, 0, 1024);
	m_ContentLen = 0;
	m_HeadLen = 0;
	m_ReqMethod = 0;
  	m_ProtocalType = INITHTTPTYPE;
	
}

void CClientSession::CloseSock(void)
{
	if(m_SocketFD != -1)
	{
		shutdown(m_SocketFD,SHUT_RDWR);
		close(m_SocketFD);
		m_SocketFD = -1;
	}
	if(m_EpollFD != -1)
	{
		close(m_EpollFD);
		m_EpollFD = -1;
	}
	
}

CClientSession::~CClientSession()
{
	int i;
	CloseSock();
	
	if(m_RecvBuf != NULL)
  	{
  	//	g_free(m_RecvBuf);
  		delete []m_RecvBuf;
  		m_RecvBuf = NULL;
  	}  	
	if(m_SendBuf != NULL)
  	{
  	//	g_free(m_RecvBuf);
  		delete []m_SendBuf;
  		m_SendBuf = NULL;
		m_SendLen = 0;
  	}  	
	
}

Int32 CClientSession::SetSendTimeOut(Int32 v_Seconds)
{
	struct timeval timeout; 
	Int32 ret;
	if((v_Seconds > 0) && (v_Seconds < 60))
	{
		timeout.tv_sec = v_Seconds; 
    		timeout.tv_usec =0;
	}
	else
	{
		timeout.tv_sec = 30; 
    		timeout.tv_usec =0;
	}
	ret   =   setsockopt(m_SocketFD, SOL_SOCKET, SO_SNDTIMEO, (Int8 *)&timeout, sizeof(timeout));
	return ret;
}

bool CClientSession::Initialize(Int32 v_SocketFD)
{
	m_SocketFD = v_SocketFD;
	m_RecvBuf	= new Int8[MAX_RECVIVE_LENGTH];
//	m_RecvBuf = g_malloc(MAX_RECVIVE_LENGTH);
	if(m_RecvBuf == NULL)
	{
		LOG("CClientSession %d malloc m_RecvBuf failed, m_SessionID = %d!\n", m_SessionID);
		return FALSE;
	}
	memset(m_RecvBuf, 0, MAX_RECVIVE_LENGTH);
 	
	return TRUE;
}

void CClientSession::MakeHttpErrResponse(char *v_responseBuf, int v_errNo)
{	
	int iBufLen = strlen(v_responseBuf);
	
	m_SendBuf	= new Int8[iBufLen + 512];
//	m_SendBuf = g_malloc(MAX_RECVIVE_LENGTH);
	if(m_SendBuf == NULL)
	{
		LOG("CClientSession malloc m_SendBuf failed, iBufLen = %d!\n", iBufLen);
		return;
	}
	memset(m_SendBuf, 0, iBufLen + 512);
	m_SendLen = 0;
	
	if(v_responseBuf != NULL)
	{
		sprintf(m_SendBuf,
			"HTTP/1.1 %d Bad Request\r\n"		
			"%s\r\n"
			"Accept: */*\r\n"
			"Accept-Language: zh-cn\r\n"
			"Cache-Control: no-cache\r\n"
			"Access-Control-Allow-Origin:*\r\n"
			"Connection: Keep-Alive\r\n"
		//	"Content-Type: %s\r\n"		
			"Content-Type: text/xml;charset=utf-8\r\n"					
			"Content-Length: %d\r\n"
			"\r\n"
			"%s",
			v_errNo,
			dateHeader(),	
			iBufLen,
			v_responseBuf);
		m_SendLen = strlen(m_SendBuf);
		
	}
	else
	{
		sprintf(m_SendBuf,		
			"HTTP/1.1 %d Bad Request\r\n"		
			"%s\r\n"
			"Accept: */*\r\n"
			"Accept-Language: zh-cn\r\n"
			"Cache-Control: no-cache\r\n"
			"Access-Control-Allow-Origin:*\r\n"
			"Connection: Keep-Alive\r\n"
		//	"Content-Type: %s\r\n"		
			"Content-Type: text/xml;charset=utf-8\r\n"					
			"Content-Length: %d\r\n"
			"\r\n",	
			v_errNo,
			dateHeader(),
			iBufLen);
		m_SendLen = strlen(m_SendBuf);
	}
	
	
	LOG("m_SendBuf = %s\n", m_SendBuf);
}


void CClientSession::MakeHttpGetResponse(char *v_responseBuf)
{	
	
	int iBufLen = strlen(v_responseBuf);
	
	
	m_SendBuf = new char[iBufLen+512];
//	m_SendBuf = g_malloc(MAX_RECVIVE_LENGTH);

	if(m_SendBuf == NULL)
	{
		LOG("CClientSession malloc m_SendBuf failed, iBufLen = %d!\n", iBufLen);
	//	printf("CClientSession malloc m_SendBuf failed, iBufLen = %d!\n", iBufLen);
		return;
	}
	
	memset(m_SendBuf, 0, iBufLen+512);
	
	m_SendLen = 0;
	
	if(v_responseBuf != NULL)
	{
		sprintf(m_SendBuf,
			"HTTP/1.1 200 OK\r\n"		
			"%s\r\n"
			"Accept: */*\r\n"
			"Accept-Language: zh-cn\r\n"
			"Cache-Control: no-cache\r\n"
			"Access-Control-Allow-Origin:*\r\n" 
			"Connection: Keep-Alive\r\n"
		//	"Content-Type: %s\r\n"		
			"Content-Type: text/xml;charset=utf-8\r\n"					
			"Content-Length: %d\r\n"
			"\r\n"
			"%s",
			dateHeader(),	
			iBufLen,
			v_responseBuf);
		m_SendLen = strlen(m_SendBuf);
		
		
	}
	else
	{
		sprintf(m_SendBuf,		
			"HTTP/1.1 200 OK\r\n"		
			"%s\r\n"
			"Accept: */*\r\n"
			"Accept-Language: zh-cn\r\n"
			"Cache-Control: no-cache\r\n"
			"Access-Control-Allow-Origin:*\r\n"
			"Connection: Keep-Alive\r\n"
		//	"Content-Type: %s\r\n"		
			"Content-Type: text/xml;charset=utf-8\r\n"					
			"Content-Length: %d\r\n"
			"\r\n",			
			dateHeader(),
			iBufLen);
		m_SendLen = strlen(m_SendBuf);
		
	}
//	printf("m_SendBuf = %s!\n", m_SendBuf);
//	LOG("m_SendBuf = %s\n", m_SendBuf);
}

int CClientSession::GetRemoteAddrByString(char *v_IPAddrInfo)
{	
	char IPAddr[32] = {0};
	socklen_t len;	
	UInt32 ret;	
	sockaddr_in t_RemoteAddr;		
//	memset(&m_IPADDRInfo, 0, sizeof(IPADDRINFO));	
	bzero(&t_RemoteAddr, sizeof(t_RemoteAddr));	
	len = sizeof(t_RemoteAddr);		
	ret = getpeername(m_SocketFD, (struct sockaddr*)&t_RemoteAddr, &len);	
	if (ret != 0)	
	{		
		LOG("getpeername error in CClientSession::GetRemoteAddrByString!\n");		
		return 0;	
	}
	
	inet_ntop(AF_INET, &t_RemoteAddr.sin_addr, IPAddr, 32);	
//	IPPort = htons(t_RemoteAddr.sin_port);
	sprintf(v_IPAddrInfo, "%s", IPAddr);
	
	return 1;
}

int CClientSession::GetCurTimeByString(char *v_CurTimeInfo)
{	
	time_t cur_time;
	struct	tm	ptr;
	
	cur_time = time(NULL);
	if (localtime_r(&cur_time, &ptr) != NULL)
	{
		sprintf(v_CurTimeInfo, "%04d-%02d-%02d %02d:%02d:%02d", ptr.tm_year+1900,
			ptr.tm_mon+1, ptr.tm_mday, ptr.tm_hour, ptr.tm_min, ptr.tm_sec);
		return 1;
	}
	
	return 0;
}

int CClientSession::GetCurTimeByNoFormatString(char *v_CurTimeInfo)
{	
	time_t cur_time;
	struct	tm	ptr;
	
	cur_time = time(NULL);
	if (localtime_r(&cur_time, &ptr) != NULL)
	{
		sprintf(v_CurTimeInfo, "%04d%02d%02d%02d%02d%02d", ptr.tm_year+1900,
			ptr.tm_mon+1, ptr.tm_mday, ptr.tm_hour, ptr.tm_min, ptr.tm_sec);
		return 1;
	}
	
	return 0;
}

Int32 CClientSession::SendPushData(Int8 *v_Senddata, Int32 v_Len)
{
  	Int32 sended = 0;
  	Int32 ret;

  	while(sended < v_Len)
	{
		ret  = ::send(m_SocketFD, v_Senddata + sended, v_Len - sended, 0);
		if(ret < 0)
		{
			if(errno == EINTR)
			{
				ret = 0;
			}
			else
			{
				LOG("send fun exit, error = %d, exit info is %s!\n", errno, strerror(errno));
		      		return -1;
			}
		}
		sended += ret;
	}
	LOG("v_senddata = %s!\n", v_Senddata);
  	return v_Len;
}


int CClientSession::ParseUserRegisterInfo(char *v_ParamStr, char *v_UserID, char *v_UserInfo, int *v_UserType)
{
	//http://domain:port/UserRegister.do?userID=10010000&userInfo=13523421000&userType=1
	char *pFind1 = NULL;
	char *pFind2  = NULL;
	
	char szTmp[16] = {0};
	int iLen = 0;

	pFind1 = strstr(v_ParamStr, "userID=");
	if(pFind1 == NULL)
	{
		LOG("Can't find the userID info from ParseUserRegisterInfo!\n");
		return -1;
	}
	
	pFind1 += strlen("userID=");
	pFind2 = strstr(pFind1, "&");
	if(pFind2  == NULL)
	{
		LOG("Can't find sepetar & from ParseUserRegisterInfo!\n");
		return -1;
	}
	if((pFind2 - pFind1) > MAX_USERID_LEN)
	{
		iLen = MAX_USERID_LEN;
	}
	else
	{
		iLen = pFind2 - pFind1;
	}
	memcpy(v_UserID, pFind1, iLen);
	
	pFind1 = strstr(v_ParamStr, "userInfo=");
	if(pFind1 == NULL)
	{
		LOG("Can't find userInfo info from ParseUserRegisterInfo!\n");
		return -1;

	}
	
	pFind1 += strlen("userInfo=");
	pFind2 = strstr(pFind1, "&");
	if(pFind2  == NULL)
	{
		pFind2 = strstr(pFind1, " HTTP");
		if(pFind2 == NULL)
		{
			LOG("Can't find sepetar space from ParseUserRegisterInfo!\n");
			return -1;
		}
	}
	if((pFind2 - pFind1) > MAX_USERID_LEN)
	{
		iLen = MAX_USERID_LEN;
	}
	else
	{
		iLen = pFind2 - pFind1;
	}
	
	memcpy(v_UserInfo, pFind1, iLen);

	pFind1 = strstr(v_ParamStr, "userType=");
	if(pFind1 == NULL)
	{
		LOG("Can't find userType info from ParseUserRegisterInfo!\n");
		return -1;

	}
	
	pFind1 += strlen("userType=");
	pFind2 = strstr(pFind1, "&");
	if(pFind2  == NULL)
	{
		pFind2 = strstr(pFind1, " HTTP");
		if(pFind2 == NULL)
		{
			LOG("Can't find sepetar space from ParseUserRegisterInfo!\n");
			return -1;
		}
	}
	if((pFind2 - pFind1) > 2)
	{
		iLen = 2;
	}
	else
	{
		iLen = pFind2 - pFind1;
	}
	memset(szTmp, 0, 16);
	memcpy(szTmp, pFind1, iLen);
	*v_UserType = atoi(szTmp);
	
	return 1;
}

int CClientSession::ParseUserRegisterInfoFromJson(char *v_ParamStr, char *v_UserID, char *v_UserInfo, int *v_UserType)
{
	//http://domain:port/UserRegister.do
	//{
    //"userID": "1000",
    //"userInfo": "13523421000",
    //"userType": 1
	//}

	json_object *newObj=NULL;
	if((v_ParamStr == NULL)||(strlen(v_ParamStr) < 2))
	{
		LOG("oh, v_ParamStr err in ParseUserRegisterInfoFromJson!\n");
	  	return -1;
	}
	newObj = json_tokener_parse(v_ParamStr);
	if( is_error(v_ParamStr) ) //正确
	{
	  LOG("oh, my god. json_tokener_parse err in ParseUserRegisterInfoFromJson!\n");
	  return -1;
	}
	else
	{
		json_object *sub1obj = json_object_object_get(newObj, "userID");
		if(NULL==sub1obj) //这里就要用NULL判断了, 得不到对应的object就是NULL
		{
		  LOG("sub1obj err, Can't get userID info!\n");
		  return -1;
		}
		else
		{
			strcpy(v_UserID,json_object_get_string(sub1obj)); 
			json_object_put(sub1obj);
		}
		json_object *sub2obj = json_object_object_get(newObj, "userInfo");
		if(NULL==sub2obj) //这里就要用NULL判断了, 得不到对应的object就是NULL
		{
		  LOG("sub2obj err, Can't get contactInfo info!\n");
		  return -1;
		}
		else
		{
			strcpy(v_UserInfo,json_object_get_string(sub2obj)); 
			json_object_put(sub2obj);
		}
		json_object *sub3obj = json_object_object_get(newObj, "userType");
		if(NULL==sub3obj) //�����Ҫ��NULL�ж���, �ò�����Ӧ��object����NULL
		{
		  LOG("sub3obj err, Can't get clientType info!\n");
		  return -1;
		}
		else
		{
			*v_UserType = atoi(json_object_to_json_string(sub3obj)); 
			json_object_put(sub3obj);
		}
		return 1;
	}
}

int CClientSession::ParseUserCertificationInfo(char *v_ParamStr, char *v_BlockAddress, char *v_UserName, char *v_UserInfo)
{
	//http://IP:Port/UserCertification.do?blockAddress=10010000&userName=�������ſ��������޹�˾&userInfo={}
	char *pFind1 = NULL;
	char *pFind2  = NULL;
	
	char szTmp[16] = {0};
	int iLen = 0;

	pFind1 = strstr(v_ParamStr, "blockAddress=");
	if(pFind1 == NULL)
	{
		LOG("Can't find the blockAddress info from ParseUserCertificationInfo!\n");
		return -1;
	}
	
	pFind1 += strlen("blockAddress=");
	pFind2 = strstr(pFind1, "&");
	if(pFind2  == NULL)
	{
		pFind2 = strstr(pFind1, " HTTP");
		if(pFind2 == NULL)
		{
			LOG("Can't find sepetar space from ParseUserCertificationInfo!\n");
			return -1;
		}
	}
	if((pFind2 - pFind1) > MAX_USERID_LEN)
	{
		iLen = MAX_USERID_LEN;
	}
	else
	{
		iLen = pFind2 - pFind1;
	}
	memcpy(v_BlockAddress, pFind1, iLen);

	pFind1 = strstr(v_ParamStr, "userName=");
	if(pFind1 == NULL)
	{
		LOG("Can't find the userName info from ParseUserCertificationInfo!\n");
		return -1;
	}
	
	pFind1 += strlen("userName=");
	pFind2 = strstr(pFind1, "&");
	if(pFind2  == NULL)
	{
		pFind2 = strstr(pFind1, " HTTP");
		if(pFind2 == NULL)
		{
			LOG("Can't find sepetar space from ParseUserCertificationInfo!\n");
			return -1;
		}
	}
	if((pFind2 - pFind1) > MAX_USERNAME_LEN)
	{
		iLen = MAX_USERNAME_LEN;
	}
	else
	{
		iLen = pFind2 - pFind1;
	}
	memcpy(v_UserName, pFind1, iLen);
	
	pFind1 = strstr(v_ParamStr, "userInfo=");
	if(pFind1 == NULL)
	{
		LOG("Can't find the userInfo info from ParseUserCertificationInfo!\n");
		return 1;
	}
	
	pFind1 += strlen("userInfo=");
	pFind2 = strstr(pFind1, "&");
	if(pFind2  == NULL)
	{
		pFind2 = strstr(pFind1, " HTTP");
		if(pFind2 == NULL)
		{
			LOG("Can't find userInfo from ParseUserCertificationInfo!\n");
			return 1;
		}
	}
	if((pFind2 - pFind1) > MAX_JSONINFO_LEN)
	{
		iLen = MAX_JSONINFO_LEN;
	}
	else
	{
		iLen = pFind2 - pFind1;
	}
	
	memcpy(v_UserInfo, pFind1, iLen);
	
	return 1;
}

int CClientSession::ParseUserCertificationInfoFromJson(char *v_ParamStr, char *v_BlockAddress, char *v_UserName, char *v_UserInfo)
{
	// http://domain:port/UserCertification.do?
	//{
    //"blockAddress": "a001f4e51a636bd0d4ec123c94870560f64cbd97758167",
    //"userName": "�������ſ��������޹�˾"
    //"userInfo":{
    //"CompanyName":"������������ѯ��Ϣ���޹�˾","CompanyAddress":"������������" ,"Telephone":"0755-32134897"," Contacter":"����","Certificate":"914492903888272e3f" }
    //}


	json_object *newObj=NULL;
	if((v_ParamStr == NULL)||(strlen(v_ParamStr) < 2))
	{
		LOG("oh, v_ParamStr err in ParseUserCertificationInfoFromJson!\n");
	  	return -1;
	}
	newObj = json_tokener_parse(v_ParamStr);
	if( is_error(v_ParamStr) ) //正确
	{
	  LOG("oh, my god. json_tokener_parse err in ParseUserCertificationInfoFromJson!\n");
	  return -1;
	}
	else
	{
		json_object *sub1obj = json_object_object_get(newObj, "blockAddress");
		if(NULL==sub1obj) //这里就要用NULL判断了, 得不到对应的object就是NULL
		{
		  LOG("sub1obj err, Can't get blockAddress info!\n");
		  return -1;
		}
		else
		{
			strcpy(v_BlockAddress,json_object_get_string(sub1obj)); 
			json_object_put(sub1obj);
		}
		json_object *sub2obj = json_object_object_get(newObj, "userName");
		if(NULL==sub2obj) //这里就要用NULL判断了, 得不到对应的object就是NULL
		{
		  LOG("sub2obj err, Can't get userName info!\n");
		  return -1;
		}
		else
		{
			strcpy(v_UserName,json_object_get_string(sub2obj)); 
			json_object_put(sub2obj);
		}
		json_object *sub3obj = json_object_object_get(newObj, "userInfo");
		if(NULL==sub3obj) //这里就要用NULL判断了, 得不到对应的object就是NULL
		{
		  LOG("sub3obj err, Can't get userInfo info!\n");
		}
		else
		{
			strcpy(v_UserInfo,json_object_get_string(sub3obj)); 
			json_object_put(sub3obj);
		}
		return 1;
	}
}

int CClientSession::ParseCreateContractAddressInfo(char *v_ParamStr, char *v_UserID, char *v_ClassID)
{
	//http://domain:port/CreateContractAddress.do?userID=10010000&classID=13523421000
	char *pFind1 = NULL;
	char *pFind2  = NULL;
	
	char szTmp[16] = {0};
	int iLen = 0;

	pFind1 = strstr(v_ParamStr, "userID=");
	if(pFind1 == NULL)
	{
		LOG("Can't find the userID info from ParseCreateContractAddressInfo!\n");
		return -1;
	}
	
	pFind1 += strlen("userID=");
	pFind2 = strstr(pFind1, "&");
	if(pFind2  == NULL)
	{
		LOG("Can't find sepetar & from ParseCreateContractAddressInfo!\n");
		return -1;
	}
	if((pFind2 - pFind1) > MAX_USERID_LEN)
	{
		iLen = MAX_USERID_LEN;
	}
	else
	{
		iLen = pFind2 - pFind1;
	}
	memcpy(v_UserID, pFind1, iLen);
	
	pFind1 = strstr(v_ParamStr, "classID=");
	if(pFind1 == NULL)
	{
		LOG("Can't find classID info from ParseCreateContractAddressInfo!\n");
		return -1;

	}
	
	pFind1 += strlen("classID=");
	pFind2 = strstr(pFind1, "&");
	if(pFind2  == NULL)
	{
		pFind2 = strstr(pFind1, " HTTP");
		if(pFind2 == NULL)
		{
			LOG("Can't find sepetar space from ParseCreateContractAddressInfo!\n");
			return -1;
		}
	}
	if((pFind2 - pFind1) > MAX_USERID_LEN)
	{
		iLen = MAX_USERID_LEN;
	}
	else
	{
		iLen = pFind2 - pFind1;
	}
	
	memcpy(v_ClassID, pFind1, iLen);
	
	return 1;
}

int CClientSession::ParseCreateContractAddressInfoFromJson(char *v_ParamStr, char *v_UserID, char *v_ClassID)
{
	//http://domain:port/CreateContractAddress.do
	//{
    //"userID": "1000",
    //"classID": "13523421000"
	//}

	json_object *newObj=NULL;
	if((v_ParamStr == NULL)||(strlen(v_ParamStr) < 2))
	{
		LOG("oh, v_ParamStr err in ParseCreateContractAddressFromJson!\n");
	  	return -1;
	}
	newObj = json_tokener_parse(v_ParamStr);
	if( is_error(v_ParamStr) ) //正确
	{
	  LOG("oh, my god. json_tokener_parse err in ParseCreateContractAddressFromJson!\n");
	  return -1;
	}
	else
	{
		json_object *sub1obj = json_object_object_get(newObj, "userID");
		if(NULL==sub1obj) //这里就要用NULL判断了, 得不到对应的object就是NULL
		{
		  LOG("sub1obj err, Can't get userID info!\n");
		  return -1;
		}
		else
		{
			strcpy(v_UserID,json_object_get_string(sub1obj)); 
			json_object_put(sub1obj);
		}
		json_object *sub2obj = json_object_object_get(newObj, "classID");
		if(NULL==sub2obj) //这里就要用NULL判断了, 得不到对应的object就是NULL
		{
		  LOG("sub2obj err, Can't get classID info!\n");
		  return -1;
		}
		else
		{
			strcpy(v_ClassID,json_object_get_string(sub2obj)); 
			json_object_put(sub2obj);
		}
		
		return 1;
	}
}


int CClientSession::ParseDataStorageInfo(char *v_ParamStr, char *v_ContractAddress, int *v_BusinessType, char *v_DataHash, char *v_DataPath, char *v_DescInfo)
{
	//http://IP:Port/BusinessDataStorage.do?contractAddress=10010000&businessType=1&dataHash=a85ec0e98c468ad0d19524b20d22f36f4da6b9e9530631e2fc9d4441d830d8f2&dataPath=http://domain:port/data/1.dat&descInfo={}
	char *pFind1 = NULL;
	char *pFind2  = NULL;
	
	char szTmp[16] = {0};
	int iLen = 0;

	pFind1 = strstr(v_ParamStr, "contractAddress=");
	if(pFind1 == NULL)
	{
		LOG("Can't find the contractAddress info from ParseDataStorageInfo!\n");
		return -1;
	}
	
	pFind1 += strlen("contractAddress=");
	pFind2 = strstr(pFind1, "&");
	if(pFind2  == NULL)
	{
		pFind2 = strstr(pFind1, " HTTP");
		if(pFind2 == NULL)
		{
			LOG("Can't find sepetar space from ParseDataStorageInfo!\n");
			return -1;
		}
	}
	if((pFind2 - pFind1) > MAX_USERID_LEN)
	{
		iLen = MAX_USERID_LEN;
	}
	else
	{
		iLen = pFind2 - pFind1;
	}
	memcpy(v_ContractAddress, pFind1, iLen);

	pFind1 = strstr(v_ParamStr, "businessType=");
	if(pFind1 == NULL)
	{
		LOG("Can't find the businessType info from ParseDataStorageInfo!\n");
		return -1;
	}
	
	pFind1 += strlen("businessType=");
	pFind2 = strstr(pFind1, "&");
	if(pFind2  == NULL)
	{
		pFind2 = strstr(pFind1, " HTTP");
		if(pFind2 == NULL)
		{
			LOG("Can't find sepetar space from ParseDataStorageInfo!\n");
			return -1;
		}
	}
	if((pFind2 - pFind1) > 2)
	{
		iLen = 2;
	}
	else
	{
		iLen = pFind2 - pFind1;
	}
	memset(szTmp, 0, 16);
	memcpy(szTmp, pFind1, iLen);
	*v_BusinessType = atoi(szTmp);
	
	pFind1 = strstr(v_ParamStr, "dataHash=");
	if(pFind1 == NULL)
	{
		LOG("Can't find the dataHash info from ParseDataStorageInfo!\n");
		return 1;
	}
	
	pFind1 += strlen("dataHash=");
	pFind2 = strstr(pFind1, "&");
	if(pFind2  == NULL)
	{
		pFind2 = strstr(pFind1, " HTTP");
		if(pFind2 == NULL)
		{
			LOG("Can't find dataHash from ParseDataStorageInfo!\n");
			return 1;
		}
	}
	if((pFind2 - pFind1) > MAX_ADDRESS_LEN)
	{
		iLen = MAX_ADDRESS_LEN;
	}
	else
	{
		iLen = pFind2 - pFind1;
	}
	
	memcpy(v_DataHash, pFind1, iLen);

	pFind1 = strstr(v_ParamStr, "dataPath=");
	if(pFind1 == NULL)
	{
		LOG("Can't find the dataPath info from ParseDataStorageInfo!\n");
		return 1;
	}
	
	pFind1 += strlen("dataPath=");
	pFind2 = strstr(pFind1, "&");
	if(pFind2  == NULL)
	{
		pFind2 = strstr(pFind1, " HTTP");
		if(pFind2 == NULL)
		{
			LOG("Can't find dataPath from ParseDataStorageInfo!\n");
			return 1;
		}
	}
	if((pFind2 - pFind1) > MAX_FILEPATH_LEN)
	{
		iLen = MAX_FILEPATH_LEN;
	}
	else
	{
		iLen = pFind2 - pFind1;
	}
	
	memcpy(v_DataPath, pFind1, iLen);

	pFind1 = strstr(v_ParamStr, "descInfo=");
	if(pFind1 == NULL)
	{
		LOG("Can't find the descInfo info from ParseDataStorageInfo!\n");
		return 1;
	}
	
	pFind1 += strlen("descInfo=");
	pFind2 = strstr(pFind1, "&");
	if(pFind2  == NULL)
	{
		pFind2 = strstr(pFind1, " HTTP");
		if(pFind2 == NULL)
		{
			LOG("Can't find descInfo from ParseDataStorageInfo!\n");
			return 1;
		}
	}
	if((pFind2 - pFind1) > MAX_JSONINFO_LEN)
	{
		iLen = MAX_JSONINFO_LEN;
	}
	else
	{
		iLen = pFind2 - pFind1;
	}
	
	memcpy(v_DescInfo, pFind1, iLen);
	
	return 1;

}


int CClientSession::ParseDataStorageInfoFromJson(char *v_ParamStr, char *v_ContractAddress, int *v_BusinessType, char *v_DataHash, char *v_DataPath, char *v_DescInfo)
{
	// 	http://domain:port/BusinessDataStorage.do
	//{
    //"contractAddress": "a001f4e51a636bd0d4ec123c94870560f64cbd97758167",
    //"businessType":1,
    //"dataHash": "a85ec0e98c468ad0d19524b20d22f36f4da6b9e9530631e2fc9d4441d830d8f2"
    //"dataPath": "http://domain:port/data/1.dat"
    //"descInfo":{
    //"CompanyName":"������������ѯ��Ϣ���޹�˾","CompanyAddress":"������������" ,"Telephone":"0755-32134897"," Contacter":"����","Certificate":"914492903888272e3f" }
    //}

	json_object *newObj=NULL;
	if((v_ParamStr == NULL)||(strlen(v_ParamStr) < 2))
	{
		LOG("oh, v_ParamStr err in ParseDataStorageInfoFromJson!\n");
	  	return -1;
	}
	newObj = json_tokener_parse(v_ParamStr);
	if( is_error(v_ParamStr) ) //正确
	{
	  LOG("oh, my god. json_tokener_parse err in ParseDataStorageInfoFromJson!\n");
	  return -1;
	}
	else
	{
		json_object *sub1obj = json_object_object_get(newObj, "contractAddress");
		if(NULL==sub1obj) //这里就要用NULL判断了, 得不到对应的object就是NULL
		{
		  LOG("sub1obj err, Can't get contractAddress info!\n");
		  return -1;
		}
		else
		{
			strcpy(v_ContractAddress,json_object_get_string(sub1obj)); 
			json_object_put(sub1obj);
		}
		json_object *sub2obj = json_object_object_get(newObj, "businessType");
		if(NULL==sub2obj) //这里就要用NULL判断了, 得不到对应的object就是NULL
		{
		  LOG("sub2obj err, Can't get businessType info!\n");
		  return -1;
		}
		else
		{
			*v_BusinessType = atoi(json_object_to_json_string(sub2obj)); 
			json_object_put(sub2obj);
		}
		json_object *sub3obj = json_object_object_get(newObj, "dataHash");
		if(NULL==sub3obj) //这里就要用NULL判断了, 得不到对应的object就是NULL
		{
		  LOG("sub3obj err, Can't get dataHash info!\n");
		  return -1;
		}
		else
		{
			strcpy(v_DataHash, json_object_get_string(sub3obj)); 
			json_object_put(sub3obj);
		}
		json_object *sub4obj = json_object_object_get(newObj, "dataPath");
		if(NULL==sub4obj) //这里就要用NULL判断了, 得不到对应的object就是NULL
		{
		  LOG("sub4obj err, Can't get dataPath info!\n");
		  strcpy(v_DataPath, " "); 
		}
		else
		{
			strcpy(v_DataPath, json_object_get_string(sub4obj)); 
			json_object_put(sub4obj);
		}
		json_object *sub5obj = json_object_object_get(newObj, "descInfo");
		if(NULL==sub5obj) //这里就要用NULL判断了, 得不到对应的object就是NULL
		{
		  LOG("sub5obj err, Can't get descInfo info!\n");
		  strcpy(v_DescInfo, " "); 
		}
		else
		{
			strcpy(v_DescInfo,json_object_get_string(sub5obj)); 
			json_object_put(sub5obj);
		}
		return 1;
	}
}

int CClientSession::ParseDataUpdateInfo(char *v_ParamStr, char *v_ContractAddress, int *v_UpdateType, int *v_BusinessType, char *v_TranxHash, char *v_DataHash, char *v_DataPath, char *v_DescInfo)
{
	// 	http://domain:port/BusinessDataUpdate.do
	//{
    //"contractAddress": "a001f4e51a636bd0d4ec123c94870560f64cbd97758167",
    //"updateType": 1,
    //"businessType":1,
    //"transactionHash": "255ec0e98c468ad0d19524b20d22f36f4da6b9e9530631e2fc9d4441d83033da",
    //"dataHash": "a85ec0e98c468ad0d19524b20d22f36f4da6b9e9530631e2fc9d4441d830d8f2"
    //"dataPath": "http://domain:port/data/1.dat"
    //"descInfo":{
    //"CompanyName":"������������ѯ��Ϣ���޹�˾","CompanyAddress":"������������" ,"Telephone":"0755-32134897"," Contacter":"����","Certificate":"914492903888272e3f" }
    //}

	char *pFind1 = NULL;
	char *pFind2  = NULL;
	
	char szTmp[16] = {0};
	int iLen = 0;

	pFind1 = strstr(v_ParamStr, "contractAddress=");
	if(pFind1 == NULL)
	{
		LOG("Can't find the contractAddress info from ParseDataUpdateInfo!\n");
		return -1;
	}
	
	pFind1 += strlen("contractAddress=");
	pFind2 = strstr(pFind1, "&");
	if(pFind2  == NULL)
	{
		pFind2 = strstr(pFind1, " HTTP");
		if(pFind2 == NULL)
		{
			LOG("Can't find sepetar space from ParseDataUpdateInfo!\n");
			return -1;
		}
	}
	if((pFind2 - pFind1) > MAX_USERID_LEN)
	{
		iLen = MAX_USERID_LEN;
	}
	else
	{
		iLen = pFind2 - pFind1;
	}
	memcpy(v_ContractAddress, pFind1, iLen);

	pFind1 = strstr(v_ParamStr, "updateType=");
	if(pFind1 == NULL)
	{
		LOG("Can't find the updateType info from ParseDataUpdateInfo!\n");
		return -1;
	}
	
	pFind1 += strlen("updateType=");
	pFind2 = strstr(pFind1, "&");
	if(pFind2  == NULL)
	{
		pFind2 = strstr(pFind1, " HTTP");
		if(pFind2 == NULL)
		{
			LOG("Can't find sepetar space from ParseDataUpdateInfo!\n");
			return -1;
		}
	}
	if((pFind2 - pFind1) > 2)
	{
		iLen = 2;
	}
	else
	{
		iLen = pFind2 - pFind1;
	}
	memset(szTmp, 0, 16);
	memcpy(szTmp, pFind1, iLen);
	*v_UpdateType = atoi(szTmp);

	pFind1 = strstr(v_ParamStr, "businessType=");
	if(pFind1 == NULL)
	{
		LOG("Can't find the businessType info from ParseDataUpdateInfo!\n");
		return -1;
	}
	
	pFind1 += strlen("businessType=");
	pFind2 = strstr(pFind1, "&");
	if(pFind2  == NULL)
	{
		pFind2 = strstr(pFind1, " HTTP");
		if(pFind2 == NULL)
		{
			LOG("Can't find sepetar space from ParseDataUpdateInfo!\n");
			return -1;
		}
	}
	if((pFind2 - pFind1) > 2)
	{
		iLen = 2;
	}
	else
	{
		iLen = pFind2 - pFind1;
	}
	memset(szTmp, 0, 16);
	memcpy(szTmp, pFind1, iLen);
	*v_BusinessType = atoi(szTmp);

	pFind1 = strstr(v_ParamStr, "transactionHash=");
	if(pFind1 == NULL)
	{
		LOG("Can't find the transactionHash info from ParseDataUpdateInfo!\n");
		return 1;
	}
	
	pFind1 += strlen("transactionHash=");
	pFind2 = strstr(pFind1, "&");
	if(pFind2  == NULL)
	{
		pFind2 = strstr(pFind1, " HTTP");
		if(pFind2 == NULL)
		{
			LOG("Can't find transactionHash from ParseDataUpdateInfo!\n");
			return 1;
		}
	}
	if((pFind2 - pFind1) > MAX_ADDRESS_LEN)
	{
		iLen = MAX_ADDRESS_LEN;
	}
	else
	{
		iLen = pFind2 - pFind1;
	}
	
	memcpy(v_TranxHash, pFind1, iLen);
	
	pFind1 = strstr(v_ParamStr, "dataHash=");
	if(pFind1 == NULL)
	{
		LOG("Can't find the dataHash info from ParseDataUpdateInfo!\n");
		return 1;
	}
	
	pFind1 += strlen("dataHash=");
	pFind2 = strstr(pFind1, "&");
	if(pFind2  == NULL)
	{
		pFind2 = strstr(pFind1, " HTTP");
		if(pFind2 == NULL)
		{
			LOG("Can't find dataHash from ParseDataUpdateInfo!\n");
			return 1;
		}
	}
	if((pFind2 - pFind1) > MAX_ADDRESS_LEN)
	{
		iLen = MAX_ADDRESS_LEN;
	}
	else
	{
		iLen = pFind2 - pFind1;
	}
	
	memcpy(v_DataHash, pFind1, iLen);

	pFind1 = strstr(v_ParamStr, "dataPath=");
	if(pFind1 == NULL)
	{
		LOG("Can't find the dataPath info from ParseDataUpdateInfo!\n");
		return 1;
	}
	
	pFind1 += strlen("dataPath=");
	pFind2 = strstr(pFind1, "&");
	if(pFind2  == NULL)
	{
		pFind2 = strstr(pFind1, " HTTP");
		if(pFind2 == NULL)
		{
			LOG("Can't find dataPath from ParseDataUpdateInfo!\n");
			return 1;
		}
	}
	if((pFind2 - pFind1) > MAX_FILEPATH_LEN)
	{
		iLen = MAX_FILEPATH_LEN;
	}
	else
	{
		iLen = pFind2 - pFind1;
	}
	
	memcpy(v_DataPath, pFind1, iLen);

	pFind1 = strstr(v_ParamStr, "descInfo=");
	if(pFind1 == NULL)
	{
		LOG("Can't find the descInfo info from ParseDataUpdateInfo!\n");
		return 1;
	}
	
	pFind1 += strlen("descInfo=");
	pFind2 = strstr(pFind1, "&");
	if(pFind2  == NULL)
	{
		pFind2 = strstr(pFind1, " HTTP");
		if(pFind2 == NULL)
		{
			LOG("Can't find descInfo from ParseDataUpdateInfo!\n");
			return 1;
		}
	}
	if((pFind2 - pFind1) > MAX_JSONINFO_LEN)
	{
		iLen = MAX_JSONINFO_LEN;
	}
	else
	{
		iLen = pFind2 - pFind1;
	}
	
	memcpy(v_DescInfo, pFind1, iLen);
	
	return 1;

}
	

int CClientSession::ParseDataUpdateInfoFromJson(char *v_ParamStr, char *v_ContractAddress, int *v_UpdateType, int *v_BusinessType, char *v_TranxHash, char *v_DataHash, char *v_DataPath, char *v_DescInfo)
{
	// 	http://domain:port/BusinessDataUpdate.do
	//{
    //"contractAddress": "a001f4e51a636bd0d4ec123c94870560f64cbd97758167",
    //"updateType": 1,
    //"businessType":1,
    //"transactionHash": "255ec0e98c468ad0d19524b20d22f36f4da6b9e9530631e2fc9d4441d83033da",
    //"dataHash": "a85ec0e98c468ad0d19524b20d22f36f4da6b9e9530631e2fc9d4441d830d8f2"
    //"dataPath": "http://domain:port/data/1.dat"
    //"descInfo":{
    //"CompanyName":"������������ѯ��Ϣ���޹�˾","CompanyAddress":"������������" ,"Telephone":"0755-32134897"," Contacter":"����","Certificate":"914492903888272e3f" }
    //}

	json_object *newObj=NULL;
	if((v_ParamStr == NULL)||(strlen(v_ParamStr) < 2))
	{
		LOG("oh, v_ParamStr err in ParseDataUpdateInfoFromJson!\n");
	  	return -1;
	}
	newObj = json_tokener_parse(v_ParamStr);
	if( is_error(v_ParamStr) ) //正确
	{
	  LOG("oh, my god. json_tokener_parse err in ParseDataUpdateInfoFromJson!\n");
	  return -1;
	}
	else
	{
		json_object *sub1obj = json_object_object_get(newObj, "contractAddress");
		if(NULL==sub1obj) //这里就要用NULL判断了, 得不到对应的object就是NULL
		{
		  LOG("sub1obj err, Can't get contractAddress info!\n");
		  return -1;
		}
		else
		{
			strcpy(v_ContractAddress,json_object_get_string(sub1obj)); 
			json_object_put(sub1obj);
		}
		json_object *sub2obj = json_object_object_get(newObj, "updateType");
		if(NULL==sub2obj) //这里就要用NULL判断了, 得不到对应的object就是NULL
		{
		  LOG("sub2obj err, Can't get updateType info!\n");
		  return -1;
		}
		else
		{
			*v_UpdateType = atoi(json_object_to_json_string(sub2obj)); 
			json_object_put(sub2obj);
		}
		json_object *sub3obj = json_object_object_get(newObj, "businessType");
		if(NULL==sub3obj) //这里就要用NULL判断了, 得不到对应的object就是NULL
		{
		  LOG("sub3obj err, Can't get businessType info!\n");
		  return -1;
		}
		else
		{
			*v_BusinessType = atoi(json_object_to_json_string(sub3obj)); 
			json_object_put(sub3obj);
		}
		json_object *sub4obj = json_object_object_get(newObj, "transactionHash");
		if(NULL==sub4obj) //这里就要用NULL判断了, 得不到对应的object就是NULL
		{
		  LOG("sub4obj err, Can't get transactionHash info!\n");
		  json_object_put(sub4obj);
		  return -1;
		}
		else
		{
			strcpy(v_TranxHash, json_object_get_string(sub4obj)); 
			json_object_put(sub4obj);
		}
		json_object *sub5obj = json_object_object_get(newObj, "dataHash");
		if(NULL==sub5obj) //这里就要用NULL判断了, 得不到对应的object就是NULL
		{
		  LOG("sub5obj err, Can't get dataHash info!\n");
		  json_object_put(sub5obj);
		  return -1;
		}
		else
		{
			strcpy(v_DataHash, json_object_get_string(sub5obj)); 
			json_object_put(sub5obj);
		}
		json_object *sub6obj = json_object_object_get(newObj, "dataPath");
		if(NULL==sub6obj) //这里就要用NULL判断了, 得不到对应的object就是NULL
		{
		  LOG("sub6obj err, Can't get dataPath info!\n");
		  strcpy(v_DataPath, " "); 
		  json_object_put(sub6obj);
		}
		else
		{
			strcpy(v_DataPath, json_object_get_string(sub6obj)); 
			json_object_put(sub6obj);
		}
		json_object *sub7obj = json_object_object_get(newObj, "descInfo");
		if(NULL==sub7obj) //这里就要用NULL判断了, 得不到对应的object就是NULL
		{
		  	LOG("sub7obj err, Can't get descInfo info!\n");
		  	strcpy(v_DescInfo, " "); 
		  	json_object_put(sub7obj);
		}
		else
		{
			strcpy(v_DescInfo,json_object_get_string(sub7obj)); 
			json_object_put(sub7obj);
		}
		return 1;
	}
}

int CClientSession::ParseContractAddressDeleteInfo(char *v_ParamStr, char *v_BlockAddress, char *v_ContractAddress, char *v_DescInfo)
{
	// 	http://domain:port/ContractAddressDelete.do
	//{
    //"blockAddress": "a001f4e51a636bd0d4ec123c94870560f64cbd97758167",
    //"contractAddress": "255ec0e98c468ad0d19524b20d22f36f4da6b9e9530631e2fc9d4441d83033da",
    //"descInfo":{
    //"CompanyName":"������������ѯ��Ϣ���޹�˾","CompanyAddress":"������������" ,"Telephone":"0755-32134897"," Contacter":"����","Certificate":"914492903888272e3f" }
    //}

	char *pFind1 = NULL;
	char *pFind2  = NULL;
	
	char szTmp[16] = {0};
	int iLen = 0;

	pFind1 = strstr(v_ParamStr, "blockAddress=");
	if(pFind1 == NULL)
	{
		LOG("Can't find the blockAddress info from ParseContractAddressDeleteInfo!\n");
		return -1;
	}
	
	pFind1 += strlen("blockAddress=");
	pFind2 = strstr(pFind1, "&");
	if(pFind2  == NULL)
	{
		pFind2 = strstr(pFind1, " HTTP");
		if(pFind2 == NULL)
		{
			LOG("Can't find sepetar space from ParseContractAddressDeleteInfo!\n");
			return -1;
		}
	}
	if((pFind2 - pFind1) > MAX_USERID_LEN)
	{
		iLen = MAX_USERID_LEN;
	}
	else
	{
		iLen = pFind2 - pFind1;
	}
	memcpy(v_BlockAddress, pFind1, iLen);

	pFind1 = strstr(v_ParamStr, "contractAddress=");
	if(pFind1 == NULL)
	{
		LOG("Can't find the contractAddress info from ParseContractAddressDeleteInfo!\n");
		return 1;
	}
	
	pFind1 += strlen("transactionHash=");
	pFind2 = strstr(pFind1, "&");
	if(pFind2  == NULL)
	{
		pFind2 = strstr(pFind1, " HTTP");
		if(pFind2 == NULL)
		{
			LOG("Can't find contractAddress from ParseContractAddressDeleteInfo!\n");
			return 1;
		}
	}
	if((pFind2 - pFind1) > MAX_ADDRESS_LEN)
	{
		iLen = MAX_ADDRESS_LEN;
	}
	else
	{
		iLen = pFind2 - pFind1;
	}
	
	memcpy(v_ContractAddress, pFind1, iLen);

	pFind1 = strstr(v_ParamStr, "descInfo=");
	if(pFind1 == NULL)
	{
		LOG("Can't find the descInfo info from ParseContractAddressDeleteInfo!\n");
		return 1;
	}
	
	pFind1 += strlen("descInfo=");
	pFind2 = strstr(pFind1, "&");
	if(pFind2  == NULL)
	{
		pFind2 = strstr(pFind1, " HTTP");
		if(pFind2 == NULL)
		{
			LOG("Can't find descInfo from ParseContractAddressDeleteInfo!\n");
			return 1;
		}
	}
	if((pFind2 - pFind1) > MAX_JSONINFO_LEN)
	{
		iLen = MAX_JSONINFO_LEN;
	}
	else
	{
		iLen = pFind2 - pFind1;
	}
	
	memcpy(v_DescInfo, pFind1, iLen);
	
	return 1;

}
	

int CClientSession::ParseContractAddressDeleteInfoFromJson(char *v_ParamStr, char *v_BlockAddress, char *v_ContractAddress, char *v_DescInfo)
{
	//	http://domain:port/ContractAddressDelete.do
		//{
		//"blockAddress": "a001f4e51a636bd0d4ec123c94870560f64cbd97758167",
		//"contractAddress": "255ec0e98c468ad0d19524b20d22f36f4da6b9e9530631e2fc9d4441d83033da",
		//"descInfo":{
		//"CompanyName":"������������ѯ��Ϣ���޹�˾","CompanyAddress":"������������" ,"Telephone":"0755-32134897"," Contacter":"����","Certificate":"914492903888272e3f" }
		//}

	json_object *newObj=NULL;
	if((v_ParamStr == NULL)||(strlen(v_ParamStr) < 2))
	{
		LOG("oh, v_ParamStr err in ParseDataUpdateInfoFromJson!\n");
	  	return -1;
	}
	newObj = json_tokener_parse(v_ParamStr);
	if( is_error(v_ParamStr) ) //正确
	{
	  LOG("oh, my god. json_tokener_parse err in ParseDataUpdateInfoFromJson!\n");
	  return -1;
	}
	else
	{
		json_object *sub1obj = json_object_object_get(newObj, "blockAddress");
		if(NULL==sub1obj) //这里就要用NULL判断了, 得不到对应的object就是NULL
		{
		  LOG("sub1obj err, Can't get blockAddress info!\n");
		  return -1;
		}
		else
		{
			strcpy(v_BlockAddress,json_object_get_string(sub1obj)); 
			json_object_put(sub1obj);
		}
		
		json_object *sub2obj = json_object_object_get(newObj, "contractAddress");
		if(NULL==sub2obj) //这里就要用NULL判断了, 得不到对应的object就是NULL
		{
		  LOG("sub2obj err, Can't get contractAddress info!\n");
		  json_object_put(sub2obj);
		  return -1;
		}
		else
		{
			strcpy(v_ContractAddress, json_object_get_string(sub2obj)); 
			json_object_put(sub2obj);
		}
		
		json_object *sub3obj = json_object_object_get(newObj, "descInfo");
		if(NULL==sub3obj) //这里就要用NULL判断了, 得不到对应的object就是NULL
		{
		  	LOG("sub3obj err, Can't get descInfo info!\n");
		  	strcpy(v_DescInfo, " "); 
		  	json_object_put(sub3obj);
		}
		else
		{
			strcpy(v_DescInfo,json_object_get_string(sub3obj)); 
			json_object_put(sub3obj);
		}
		return 1;
	}
}


int CClientSession::ParseIntegrityVerificationInfo(char *v_ParamStr, char *v_BlockAddress, char *v_ContractAddress, int *v_BusinessType, char *v_TranxHash, char *v_DataHash)
{
	//	http://domain:port/IntegrityVerification.do
	//{
	//"blockAddress": "a001f4e51a636bd0d4ec123c94870560f64cbd97758167",
	//"contractAddress": "a001f4e51a636bd0d4ec123c94870560f64cbd97758167",
	//"businessType":1,
	//"transactionHash": "255ec0e98c468ad0d19524b20d22f36f4da6b9e9530631e2fc9d4441d83033da",
	//"dataHash": "a85ec0e98c468ad0d19524b20d22f36f4da6b9e9530631e2fc9d4441d830d8f2"
	//}

	char *pFind1 = NULL;
	char *pFind2  = NULL;
	
	char szTmp[16] = {0};
	int iLen = 0;

	pFind1 = strstr(v_ParamStr, "blockAddress=");
	if(pFind1 == NULL)
	{
		LOG("Can't find the blockAddress info from ParseIntegrityVerificationInfo!\n");
		return -1;
	}
	
	pFind1 += strlen("blockAddress=");
	pFind2 = strstr(pFind1, "&");
	if(pFind2  == NULL)
	{
		pFind2 = strstr(pFind1, " HTTP");
		if(pFind2 == NULL)
		{
			LOG("Can't find sepetar space from ParseIntegrityVerificationInfo!\n");
			return -1;
		}
	}
	if((pFind2 - pFind1) > MAX_USERID_LEN)
	{
		iLen = MAX_USERID_LEN;
	}
	else
	{
		iLen = pFind2 - pFind1;
	}
	memcpy(v_BlockAddress, pFind1, iLen);

	pFind1 = strstr(v_ParamStr, "contractAddress=");
	if(pFind1 == NULL)
	{
		LOG("Can't find the contractAddress info from ParseIntegrityVerificationInfo!\n");
		return -1;
	}
	
	pFind1 += strlen("contractAddress=");
	pFind2 = strstr(pFind1, "&");
	if(pFind2  == NULL)
	{
		pFind2 = strstr(pFind1, " HTTP");
		if(pFind2 == NULL)
		{
			LOG("Can't find sepetar space from ParseIntegrityVerificationInfo!\n");
			return -1;
		}
	}
	if((pFind2 - pFind1) > MAX_USERID_LEN)
	{
		iLen = MAX_USERID_LEN;
	}
	else
	{
		iLen = pFind2 - pFind1;
	}
	memcpy(v_ContractAddress, pFind1, iLen);

	pFind1 = strstr(v_ParamStr, "businessType=");
	if(pFind1 == NULL)
	{
		LOG("Can't find the businessType info from ParseIntegrityVerificationInfo!\n");
		return -1;
	}
	
	pFind1 += strlen("businessType=");
	pFind2 = strstr(pFind1, "&");
	if(pFind2  == NULL)
	{
		pFind2 = strstr(pFind1, " HTTP");
		if(pFind2 == NULL)
		{
			LOG("Can't find sepetar space from ParseIntegrityVerificationInfo!\n");
			return -1;
		}
	}
	if((pFind2 - pFind1) > 2)
	{
		iLen = 2;
	}
	else
	{
		iLen = pFind2 - pFind1;
	}
	memset(szTmp, 0, 16);
	memcpy(szTmp, pFind1, iLen);
	*v_BusinessType = atoi(szTmp);

	pFind1 = strstr(v_ParamStr, "transactionHash=");
	if(pFind1 == NULL)
	{
		LOG("Can't find the transactionHash info from ParseIntegrityVerificationInfo!\n");
		return 1;
	}
	
	pFind1 += strlen("transactionHash=");
	pFind2 = strstr(pFind1, "&");
	if(pFind2  == NULL)
	{
		pFind2 = strstr(pFind1, " HTTP");
		if(pFind2 == NULL)
		{
			LOG("Can't find transactionHash from ParseIntegrityVerificationInfo!\n");
			return 1;
		}
	}
	if((pFind2 - pFind1) > MAX_ADDRESS_LEN)
	{
		iLen = MAX_ADDRESS_LEN;
	}
	else
	{
		iLen = pFind2 - pFind1;
	}
	
	memcpy(v_TranxHash, pFind1, iLen);
	
	pFind1 = strstr(v_ParamStr, "dataHash=");
	if(pFind1 == NULL)
	{
		LOG("Can't find the dataHash info from ParseIntegrityVerificationInfo!\n");
		return 1;
	}
	
	pFind1 += strlen("dataHash=");
	pFind2 = strstr(pFind1, "&");
	if(pFind2  == NULL)
	{
		pFind2 = strstr(pFind1, " HTTP");
		if(pFind2 == NULL)
		{
			LOG("Can't find dataHash from ParseIntegrityVerificationInfo!\n");
			return 1;
		}
	}
	if((pFind2 - pFind1) > MAX_ADDRESS_LEN)
	{
		iLen = MAX_ADDRESS_LEN;
	}
	else
	{
		iLen = pFind2 - pFind1;
	}
	
	memcpy(v_DataHash, pFind1, iLen);

	return 1;

}

int CClientSession::ParseIntegrityVerificationInfoFromJson(char *v_ParamStr, char *v_BlockAddress, char *v_ContractAddress, int *v_BusinessType, char *v_TranxHash, char *v_DataHash)
{
	// 	http://domain:port/BusinessDataStorage.do
	//{
    //"blockAddress": "a001f4e51a636bd0d4ec123c94870560f64cbd97758167",
    //"contractAddress": "a001f4e51a636bd0d4ec123c94870560f64cbd97758167",
    //"businessType":1,
    //"transactionHash": "255ec0e98c468ad0d19524b20d22f36f4da6b9e9530631e2fc9d4441d83033da",
    //"dataHash": "a85ec0e98c468ad0d19524b20d22f36f4da6b9e9530631e2fc9d4441d830d8f2"
    //}

	json_object *newObj=NULL;
	if((v_ParamStr == NULL)||(strlen(v_ParamStr) < 2))
	{
		LOG("oh, v_ParamStr err in ParseIntegrityVerificationInfoFromJson!\n");
	  	return -1;
	}
	newObj = json_tokener_parse(v_ParamStr);
	if( is_error(v_ParamStr) ) //正确
	{
	  LOG("oh, my god. json_tokener_parse err in ParseIntegrityVerificationInfoFromJson!\n");
	  return -1;
	}
	else
	{
		json_object *sub1obj = json_object_object_get(newObj, "blockAddress");
		if(NULL==sub1obj) //这里就要用NULL判断了, 得不到对应的object就是NULL
		{
		  LOG("sub1obj err, Can't get blockAddress info!\n");
		  return -1;
		}
		else
		{
			strcpy(v_BlockAddress,json_object_get_string(sub1obj)); 
			json_object_put(sub1obj);
		}
		json_object *sub2obj = json_object_object_get(newObj, "contractAddress");
		if(NULL==sub2obj) //这里就要用NULL判断了, 得不到对应的object就是NULL
		{
		  LOG("sub2obj err, Can't get contractAddress info!\n");
		  return -1;
		}
		else
		{
			strcpy(v_ContractAddress,json_object_get_string(sub2obj)); 
			json_object_put(sub2obj);
		}
		json_object *sub3obj = json_object_object_get(newObj, "businessType");
		if(NULL==sub3obj) //这里就要用NULL判断了, 得不到对应的object就是NULL
		{
		  LOG("sub3obj err, Can't get businessType info!\n");
		  return -1;
		}
		else
		{
			*v_BusinessType = atoi(json_object_to_json_string(sub3obj)); 
			json_object_put(sub3obj);
		}
		json_object *sub4obj = json_object_object_get(newObj, "transactionHash");
		if(NULL==sub4obj) //这里就要用NULL判断了, 得不到对应的object就是NULL
		{
		  LOG("sub4obj err, Can't get transactionHash info!\n");
		  return -1;
		}
		else
		{
			strcpy(v_TranxHash,json_object_get_string(sub4obj)); 
			json_object_put(sub4obj);
		}
		json_object *sub5obj = json_object_object_get(newObj, "dataHash");
		if(NULL==sub5obj) //这里就要用NULL判断了, 得不到对应的object就是NULL
		{
		  LOG("sub5obj err, Can't get dataHash info!\n");
		  return -1;
		}
		else
		{
			strcpy(v_DataHash, json_object_get_string(sub5obj)); 
			json_object_put(sub5obj);
		}
		
		return 1;
	}
}

int CClientSession::ParseDataSharedContentInfo(char *v_ParamStr, char *v_BlockAddress, char *v_ContractAddress, int *v_BusinessType, char *v_TranxHash, char *v_DataHash)
{
//	http://domain:port/DataSharedContent.do
	//{
	//"blockAddress": "a001f4e51a636bd0d4ec123c94870560f64cbd97758167",
	//"contractAddress": "a001f4e51a636bd0d4ec123c94870560f64cbd97758167",
	//"businessType":1,
	//"transactionHash": "255ec0e98c468ad0d19524b20d22f36f4da6b9e9530631e2fc9d4441d83033da",
	//"dataHash": "a85ec0e98c468ad0d19524b20d22f36f4da6b9e9530631e2fc9d4441d830d8f2"
	//}

	char *pFind1 = NULL;
	char *pFind2  = NULL;
	
	char szTmp[16] = {0};
	int iLen = 0;

	pFind1 = strstr(v_ParamStr, "blockAddress=");
	if(pFind1 == NULL)
	{
		LOG("Can't find the blockAddress info from ParseDataSharedContentInfo!\n");
		return -1;
	}
	
	pFind1 += strlen("blockAddress=");
	pFind2 = strstr(pFind1, "&");
	if(pFind2  == NULL)
	{
		pFind2 = strstr(pFind1, " HTTP");
		if(pFind2 == NULL)
		{
			LOG("Can't find sepetar space from ParseDataSharedContentInfo!\n");
			return -1;
		}
	}
	if((pFind2 - pFind1) > MAX_USERID_LEN)
	{
		iLen = MAX_USERID_LEN;
	}
	else
	{
		iLen = pFind2 - pFind1;
	}
	memcpy(v_BlockAddress, pFind1, iLen);

	pFind1 = strstr(v_ParamStr, "contractAddress=");
	if(pFind1 == NULL)
	{
		LOG("Can't find the contractAddress info from ParseDataSharedContentInfo!\n");
		return -1;
	}
	
	pFind1 += strlen("contractAddress=");
	pFind2 = strstr(pFind1, "&");
	if(pFind2  == NULL)
	{
		pFind2 = strstr(pFind1, " HTTP");
		if(pFind2 == NULL)
		{
			LOG("Can't find sepetar space from ParseDataSharedContentInfo!\n");
			return -1;
		}
	}
	if((pFind2 - pFind1) > MAX_USERID_LEN)
	{
		iLen = MAX_USERID_LEN;
	}
	else
	{
		iLen = pFind2 - pFind1;
	}
	memcpy(v_ContractAddress, pFind1, iLen);

	pFind1 = strstr(v_ParamStr, "businessType=");
	if(pFind1 == NULL)
	{
		LOG("Can't find the businessType info from ParseDataSharedContentInfo!\n");
		return -1;
	}
	
	pFind1 += strlen("businessType=");
	pFind2 = strstr(pFind1, "&");
	if(pFind2  == NULL)
	{
		pFind2 = strstr(pFind1, " HTTP");
		if(pFind2 == NULL)
		{
			LOG("Can't find sepetar space from ParseDataSharedContentInfo!\n");
			return -1;
		}
	}
	if((pFind2 - pFind1) > 2)
	{
		iLen = 2;
	}
	else
	{
		iLen = pFind2 - pFind1;
	}
	memset(szTmp, 0, 16);
	memcpy(szTmp, pFind1, iLen);
	*v_BusinessType = atoi(szTmp);

	pFind1 = strstr(v_ParamStr, "transactionHash=");
	if(pFind1 == NULL)
	{
		LOG("Can't find the transactionHash info from ParseDataSharedContentInfo!\n");
		return 1;
	}
	
	pFind1 += strlen("transactionHash=");
	pFind2 = strstr(pFind1, "&");
	if(pFind2  == NULL)
	{
		pFind2 = strstr(pFind1, " HTTP");
		if(pFind2 == NULL)
		{
			LOG("Can't find transactionHash from ParseDataSharedContentInfo!\n");
			return 1;
		}
	}
	if((pFind2 - pFind1) > MAX_ADDRESS_LEN)
	{
		iLen = MAX_ADDRESS_LEN;
	}
	else
	{
		iLen = pFind2 - pFind1;
	}
	
	memcpy(v_TranxHash, pFind1, iLen);
	
	pFind1 = strstr(v_ParamStr, "dataHash=");
	if(pFind1 == NULL)
	{
		LOG("Can't find the dataHash info from ParseDataSharedContentInfo!\n");
		return 1;
	}
	
	pFind1 += strlen("dataHash=");
	pFind2 = strstr(pFind1, "&");
	if(pFind2  == NULL)
	{
		pFind2 = strstr(pFind1, " HTTP");
		if(pFind2 == NULL)
		{
			LOG("Can't find dataHash from ParseDataSharedContentInfo!\n");
			return 1;
		}
	}
	if((pFind2 - pFind1) > MAX_ADDRESS_LEN)
	{
		iLen = MAX_ADDRESS_LEN;
	}
	else
	{
		iLen = pFind2 - pFind1;
	}
	
	memcpy(v_DataHash, pFind1, iLen);

	return 1;

}
	

int CClientSession::ParseDataSharedContentInfoFromJson(char *v_ParamStr, char *v_BlockAddress, char *v_ContractAddress, int *v_BusinessType, char *v_TranxHash, char *v_DataHash)
{
	// 	http://domain:port/DataSharedContent.do
	//{
    //"blockAddress": "a001f4e51a636bd0d4ec123c94870560f64cbd97758167",
    //"contractAddress": "a001f4e51a636bd0d4ec123c94870560f64cbd97758167",
    //"businessType":1,
    //"transactionHash": "255ec0e98c468ad0d19524b20d22f36f4da6b9e9530631e2fc9d4441d83033da",
    //"dataHash": "a85ec0e98c468ad0d19524b20d22f36f4da6b9e9530631e2fc9d4441d830d8f2"
    //}

	json_object *newObj=NULL;
	if((v_ParamStr == NULL)||(strlen(v_ParamStr) < 2))
	{
		LOG("oh, v_ParamStr err in ParseDataSharedContentInfoFromJson!\n");
	  	return -1;
	}
	newObj = json_tokener_parse(v_ParamStr);
	if( is_error(v_ParamStr) ) //正确
	{
	  LOG("oh, my god. json_tokener_parse err in ParseDataSharedContentInfoFromJson!\n");
	  return -1;
	}
	else
	{
		json_object *sub1obj = json_object_object_get(newObj, "blockAddress");
		if(NULL==sub1obj) //这里就要用NULL判断了, 得不到对应的object就是NULL
		{
		  LOG("sub1obj err, Can't get blockAddress info!\n");
		  return -1;
		}
		else
		{
			strcpy(v_BlockAddress,json_object_get_string(sub1obj)); 
			json_object_put(sub1obj);
		}
		json_object *sub2obj = json_object_object_get(newObj, "contractAddress");
		if(NULL==sub2obj) //这里就要用NULL判断了, 得不到对应的object就是NULL
		{
		  LOG("sub2obj err, Can't get contractAddress info!\n");
		  return -1;
		}
		else
		{
			strcpy(v_ContractAddress,json_object_get_string(sub2obj)); 
			json_object_put(sub2obj);
		}
		json_object *sub3obj = json_object_object_get(newObj, "businessType");
		if(NULL==sub3obj) //这里就要用NULL判断了, 得不到对应的object就是NULL
		{
		  LOG("sub3obj err, Can't get businessType info!\n");
		  return -1;
		}
		else
		{
			*v_BusinessType = atoi(json_object_to_json_string(sub3obj)); 
			json_object_put(sub3obj);
		}
		json_object *sub4obj = json_object_object_get(newObj, "transactionHash");
		if(NULL==sub4obj) //这里就要用NULL判断了, 得不到对应的object就是NULL
		{
		  LOG("sub4obj err, Can't get transactionHash info!\n");
		  return -1;
		}
		else
		{
			strcpy(v_TranxHash,json_object_get_string(sub4obj)); 
			json_object_put(sub4obj);
		}
		json_object *sub5obj = json_object_object_get(newObj, "dataHash");
		if(NULL==sub5obj) //这里就要用NULL判断了, 得不到对应的object就是NULL
		{
		  LOG("sub5obj err, Can't get dataHash info!\n");
		  return -1;
		}
		else
		{
			strcpy(v_DataHash, json_object_get_string(sub5obj)); 
			json_object_put(sub5obj);
		}
		
		return 1;
	}
}

int CClientSession::ParseDataSharedResultInfo(char *v_ParamStr, char *v_BlockAddress, char *v_ContractAddress, int *v_BusinessType, char *v_TranxHash, char *v_DataHash, char *v_DescInfo)
{
//	http://domain:port/DataSharedResult.do
	//{
	//"blockAddress": "a001f4e51a636bd0d4ec123c94870560f64cbd97758167",
	//"contractAddress": "a001f4e51a636bd0d4ec123c94870560f64cbd97758167",
	//"businessType":1,
	//"transactionHash": "255ec0e98c468ad0d19524b20d22f36f4da6b9e9530631e2fc9d4441d83033da",
	//"dataHash": "a85ec0e98c468ad0d19524b20d22f36f4da6b9e9530631e2fc9d4441d830d8f2"
	//"descInfo":{
	//"CompanyName":"������������ѯ��Ϣ���޹�˾","CompanyAddress":"������������" ,"Telephone":"0755-32134897"," Contacter":"����","Certificate":"914492903888272e3f" }
	//}

	char *pFind1 = NULL;
	char *pFind2  = NULL;
	
	char szTmp[16] = {0};
	int iLen = 0;

	pFind1 = strstr(v_ParamStr, "blockAddress=");
	if(pFind1 == NULL)
	{
		LOG("Can't find the blockAddress info from ParseDataSharedResultInfo!\n");
		return -1;
	}
	
	pFind1 += strlen("blockAddress=");
	pFind2 = strstr(pFind1, "&");
	if(pFind2  == NULL)
	{
		pFind2 = strstr(pFind1, " HTTP");
		if(pFind2 == NULL)
		{
			LOG("Can't find sepetar space from ParseDataSharedResultInfo!\n");
			return -1;
		}
	}
	if((pFind2 - pFind1) > MAX_USERID_LEN)
	{
		iLen = MAX_USERID_LEN;
	}
	else
	{
		iLen = pFind2 - pFind1;
	}
	memcpy(v_BlockAddress, pFind1, iLen);

	pFind1 = strstr(v_ParamStr, "contractAddress=");
	if(pFind1 == NULL)
	{
		LOG("Can't find the contractAddress info from ParseDataSharedResultInfo!\n");
		return -1;
	}
	
	pFind1 += strlen("contractAddress=");
	pFind2 = strstr(pFind1, "&");
	if(pFind2  == NULL)
	{
		pFind2 = strstr(pFind1, " HTTP");
		if(pFind2 == NULL)
		{
			LOG("Can't find sepetar space from ParseDataSharedResultInfo!\n");
			return -1;
		}
	}
	if((pFind2 - pFind1) > MAX_USERID_LEN)
	{
		iLen = MAX_USERID_LEN;
	}
	else
	{
		iLen = pFind2 - pFind1;
	}
	memcpy(v_ContractAddress, pFind1, iLen);

	pFind1 = strstr(v_ParamStr, "businessType=");
	if(pFind1 == NULL)
	{
		LOG("Can't find the businessType info from ParseDataSharedResultInfo!\n");
		return -1;
	}
	
	pFind1 += strlen("businessType=");
	pFind2 = strstr(pFind1, "&");
	if(pFind2  == NULL)
	{
		pFind2 = strstr(pFind1, " HTTP");
		if(pFind2 == NULL)
		{
			LOG("Can't find sepetar space from ParseDataSharedResultInfo!\n");
			return -1;
		}
	}
	if((pFind2 - pFind1) > 2)
	{
		iLen = 2;
	}
	else
	{
		iLen = pFind2 - pFind1;
	}
	memset(szTmp, 0, 16);
	memcpy(szTmp, pFind1, iLen);
	*v_BusinessType = atoi(szTmp);

	pFind1 = strstr(v_ParamStr, "transactionHash=");
	if(pFind1 == NULL)
	{
		LOG("Can't find the transactionHash info from ParseDataSharedResultInfo!\n");
		return 1;
	}
	
	pFind1 += strlen("transactionHash=");
	pFind2 = strstr(pFind1, "&");
	if(pFind2  == NULL)
	{
		pFind2 = strstr(pFind1, " HTTP");
		if(pFind2 == NULL)
		{
			LOG("Can't find transactionHash from ParseDataSharedResultInfo!\n");
			return 1;
		}
	}
	if((pFind2 - pFind1) > MAX_ADDRESS_LEN)
	{
		iLen = MAX_ADDRESS_LEN;
	}
	else
	{
		iLen = pFind2 - pFind1;
	}
	
	memcpy(v_TranxHash, pFind1, iLen);
	
	pFind1 = strstr(v_ParamStr, "dataHash=");
	if(pFind1 == NULL)
	{
		LOG("Can't find the dataHash info from ParseDataSharedResultInfo!\n");
		return 1;
	}
	
	pFind1 += strlen("dataHash=");
	pFind2 = strstr(pFind1, "&");
	if(pFind2  == NULL)
	{
		pFind2 = strstr(pFind1, " HTTP");
		if(pFind2 == NULL)
		{
			LOG("Can't find dataHash from ParseDataSharedResultInfo!\n");
			return 1;
		}
	}
	if((pFind2 - pFind1) > MAX_ADDRESS_LEN)
	{
		iLen = MAX_ADDRESS_LEN;
	}
	else
	{
		iLen = pFind2 - pFind1;
	}
	
	memcpy(v_DataHash, pFind1, iLen);

	pFind1 = strstr(v_ParamStr, "descInfo=");
	if(pFind1 == NULL)
	{
		LOG("Can't find the descInfo info from ParseDataSharedResultInfo!\n");
		return 1;
	}
	
	pFind1 += strlen("descInfo=");
	pFind2 = strstr(pFind1, "&");
	if(pFind2  == NULL)
	{
		pFind2 = strstr(pFind1, " HTTP");
		if(pFind2 == NULL)
		{
			LOG("Can't find descInfo from ParseDataSharedResultInfo!\n");
			return 1;
		}
	}
	if((pFind2 - pFind1) > MAX_JSONINFO_LEN)
	{
		iLen = MAX_JSONINFO_LEN;
	}
	else
	{
		iLen = pFind2 - pFind1;
	}
	
	memcpy(v_DescInfo, pFind1, iLen);
	
	return 1;

}
	

int CClientSession::ParseDataSharedResultInfoFromJson(char *v_ParamStr, char *v_BlockAddress, char *v_ContractAddress, int *v_BusinessType, char *v_TranxHash, char *v_DataHash, char *v_DescInfo)
{
	// 	http://domain:port/DataSharedContent.do
	//{
    //"blockAddress": "a001f4e51a636bd0d4ec123c94870560f64cbd97758167",
    //"contractAddress": "a001f4e51a636bd0d4ec123c94870560f64cbd97758167",
    //"businessType":1,
    //"transactionHash": "255ec0e98c468ad0d19524b20d22f36f4da6b9e9530631e2fc9d4441d83033da",
    //"dataHash": "a85ec0e98c468ad0d19524b20d22f36f4da6b9e9530631e2fc9d4441d830d8f2"
    //"conditionInfo": "a85ec0e98c468ad0d19524b20d22f36f4da6b9e9530631e2fc9d4441d830d8f2"
    //}

	json_object *newObj=NULL;
	if((v_ParamStr == NULL)||(strlen(v_ParamStr) < 2))
	{
		LOG("oh, v_ParamStr err in ParseDataSharedContentInfoFromJson!\n");
	  	return -1;
	}
	newObj = json_tokener_parse(v_ParamStr);
	if( is_error(v_ParamStr) ) //正确
	{
	  LOG("oh, my god. json_tokener_parse err in ParseDataSharedContentInfoFromJson!\n");
	  return -1;
	}
	else
	{
		json_object *sub1obj = json_object_object_get(newObj, "blockAddress");
		if(NULL==sub1obj) //这里就要用NULL判断了, 得不到对应的object就是NULL
		{
		  LOG("sub1obj err, Can't get blockAddress info!\n");
		  return -1;
		}
		else
		{
			strcpy(v_BlockAddress,json_object_get_string(sub1obj)); 
			json_object_put(sub1obj);
		}
		json_object *sub2obj = json_object_object_get(newObj, "contractAddress");
		if(NULL==sub2obj) //这里就要用NULL判断了, 得不到对应的object就是NULL
		{
		  LOG("sub2obj err, Can't get contractAddress info!\n");
		  return -1;
		}
		else
		{
			strcpy(v_ContractAddress,json_object_get_string(sub2obj)); 
			json_object_put(sub2obj);
		}
		json_object *sub3obj = json_object_object_get(newObj, "businessType");
		if(NULL==sub3obj) //这里就要用NULL判断了, 得不到对应的object就是NULL
		{
		  LOG("sub3obj err, Can't get businessType info!\n");
		  return -1;
		}
		else
		{
			*v_BusinessType = atoi(json_object_to_json_string(sub3obj)); 
			json_object_put(sub3obj);
		}
		json_object *sub4obj = json_object_object_get(newObj, "transactionHash");
		if(NULL==sub4obj) //这里就要用NULL判断了, 得不到对应的object就是NULL
		{
		  LOG("sub4obj err, Can't get transactionHash info!\n");
		  return -1;
		}
		else
		{
			strcpy(v_TranxHash,json_object_get_string(sub4obj)); 
			json_object_put(sub4obj);
		}
		json_object *sub5obj = json_object_object_get(newObj, "dataHash");
		if(NULL==sub5obj) //这里就要用NULL判断了, 得不到对应的object就是NULL
		{
		  LOG("sub5obj err, Can't get dataHash info!\n");
		  return -1;
		}
		else
		{
			strcpy(v_DataHash, json_object_get_string(sub5obj)); 
			json_object_put(sub5obj);
		}
		json_object *sub6obj = json_object_object_get(newObj, "conditionInfo");
		if(NULL==sub6obj) //这里就要用NULL判断了, 得不到对应的object就是NULL
		{
		  LOG("sub6obj err, Can't get conditionInfo info!\n");
		  strcpy(v_DescInfo," "); 
		  json_object_put(sub6obj);
		}
		else
		{
			strcpy(v_DescInfo, json_object_get_string(sub6obj)); 
			json_object_put(sub6obj);
		}
		return 1;
	}
}

int CClientSession::ParseQueryAddressRecordInfo(char *v_ParamStr, char *v_BlockAddress, char *v_ContractAddress, char *v_StartTime, char *v_EndTime, int *v_CurPage, int *v_NumsPerPage)
{
	//http:// domain:port/QueryAddressRecord.do?
	//{
	//"blockAddress": "a00126529bc1d468e296bbb02878838415e99f187c94dd",
	//"contractAddress": "a001f4e51a636bd0d4ec123c94870560f64cbd97758167",
	//"startTime": "2019-10-12 12:05:12",
	//"endTime": "2019-10-13 12:05:12",
	//"curPage": 1,
	//"numsPerPage": 30
	//}
	char *pFind1 = NULL;
	char *pFind2  = NULL;
	
	char szTmp[16] = {0};
	int iLen = 0;

	pFind1 = strstr(v_ParamStr, "blockAddress=");
	if(pFind1 == NULL)
	{
		LOG("Can't find the blockAddress info from ParseQueryAddressRecordInfo!\n");
		return -1;
	}
	
	pFind1 += strlen("blockAddress=");
	pFind2 = strstr(pFind1, "&");
	if(pFind2  == NULL)
	{
		pFind2 = strstr(pFind1, " HTTP");
		if(pFind2 == NULL)
		{
			LOG("Can't find sepetar space from ParseQueryAddressRecordInfo!\n");
			return -1;
		}
	}
	if((pFind2 - pFind1) > MAX_USERID_LEN)
	{
		iLen = MAX_USERID_LEN;
	}
	else
	{
		iLen = pFind2 - pFind1;
	}
	memcpy(v_BlockAddress, pFind1, iLen);

	pFind1 = strstr(v_ParamStr, "contractAddress=");
	if(pFind1 == NULL)
	{
		LOG("Can't find the contractAddress info from ParseQueryAddressRecordInfo!\n");
		return -1;
	}
	
	pFind1 += strlen("contractAddress=");
	pFind2 = strstr(pFind1, "&");
	if(pFind2  == NULL)
	{
		pFind2 = strstr(pFind1, " HTTP");
		if(pFind2 == NULL)
		{
			LOG("Can't find sepetar space from ParseQueryAddressRecordInfo!\n");
			return -1;
		}
	}
	if((pFind2 - pFind1) > MAX_USERID_LEN)
	{
		iLen = MAX_USERID_LEN;
	}
	else
	{
		iLen = pFind2 - pFind1;
	}
	memcpy(v_ContractAddress, pFind1, iLen);

	pFind1 = strstr(v_ParamStr, "startTime=");
	if(pFind1 == NULL)
	{
		LOG("Can't find the startTime info from ParseQueryAddressRecordInfo!\n");
	}
	
	pFind1 += strlen("startTime=");
	pFind2 = strstr(pFind1, "&");
	if(pFind2  == NULL)
	{
		pFind2 = strstr(pFind1, " HTTP");
		if(pFind2 == NULL)
		{
			LOG("Can't find transactionHash from ParseQueryAddressRecordInfo!\n");
			return 1;
		}
	}
	if((pFind2 - pFind1) > MAX_ADDRESS_LEN)
	{
		iLen = MAX_ADDRESS_LEN;
	}
	else
	{
		iLen = pFind2 - pFind1;
	}
	
	memcpy(v_StartTime, pFind1, iLen);
	
	pFind1 = strstr(v_ParamStr, "endTime=");
	if(pFind1 == NULL)
	{
		LOG("Can't find the endTime info from ParseQueryAddressRecordInfo!\n");
	}
	
	pFind1 += strlen("endTime=");
	pFind2 = strstr(pFind1, "&");
	if(pFind2  == NULL)
	{
		pFind2 = strstr(pFind1, " HTTP");
		if(pFind2 == NULL)
		{
			LOG("Can't find endTime from ParseQueryAddressRecordInfo!\n");
			return 1;
		}
	}
	if((pFind2 - pFind1) > MAX_ADDRESS_LEN)
	{
		iLen = MAX_ADDRESS_LEN;
	}
	else
	{
		iLen = pFind2 - pFind1;
	}
	
	memcpy(v_EndTime, pFind1, iLen);

	pFind1 = strstr(v_ParamStr, "curPage=");
	if(pFind1 == NULL)
	{
		LOG("Can't find the curPage info from ParseQueryAddressRecordInfo!\n");
	}
	
	pFind1 += strlen("curPage=");
	pFind2 = strstr(pFind1, "&");
	if(pFind2  == NULL)
	{
		pFind2 = strstr(pFind1, " HTTP");
		if(pFind2 == NULL)
		{
			LOG("Can't find sepetar space from ParseQueryAddressRecordInfo!\n");
			return -1;
		}
	}
	if((pFind2 - pFind1) > 2)
	{
		iLen = 2;
	}
	else
	{
		iLen = pFind2 - pFind1;
	}
	memset(szTmp, 0, 16);
	memcpy(szTmp, pFind1, iLen);
	*v_CurPage= atoi(szTmp);

	pFind1 = strstr(v_ParamStr, "numsPerPage=");
	if(pFind1 == NULL)
	{
		LOG("Can't find the numsPerPage info from ParseQueryAddressRecordInfo!\n");
	}
	
	pFind1 += strlen("numsPerPage=");
	pFind2 = strstr(pFind1, "&");
	if(pFind2  == NULL)
	{
		pFind2 = strstr(pFind1, " HTTP");
		if(pFind2 == NULL)
		{
			LOG("Can't find sepetar space from ParseQueryAddressRecordInfo!\n");
			return -1;
		}
	}
	if((pFind2 - pFind1) > 2)
	{
		iLen = 2;
	}
	else
	{
		iLen = pFind2 - pFind1;
	}
	memset(szTmp, 0, 16);
	memcpy(szTmp, pFind1, iLen);
	*v_NumsPerPage = atoi(szTmp);
	
	return 1;

}

int CClientSession::ParseQueryAddressRecordInfoFromJson(char *v_ParamStr, char *v_BlockAddress, char *v_ContractAddress, char *v_StartTime, char *v_EndTime, int *v_CurPage, int *v_NumsPerPage)
{
	//http:// domain:port/QueryAddressRecord.do?
	//{
    //"blockAddress": "a00126529bc1d468e296bbb02878838415e99f187c94dd",
    //"contractAddress": "a001f4e51a636bd0d4ec123c94870560f64cbd97758167",
    //"startTime": "2019-10-12 12:05:12",
    //"endTime": "2019-10-13 12:05:12",
    //"curPage": 1,
 	//"numsPerPage": 30
	//}

	char szClientType[16] = {0};
	json_object *newObj=NULL;
	if((v_ParamStr == NULL)||(strlen(v_ParamStr) < 2))
	{
		LOG("oh, v_ParamStr err in ParseQueryAddressRecordInfoFromJson!\nJsonStr = \n%s!\n", v_ParamStr);
	  	return -1;
	}
	
	newObj = json_tokener_parse(v_ParamStr);
	if( is_error(v_ParamStr) ) //正确
	{
	  LOG("oh, my god. json_tokener_parse err in ParseQueryAddressRecordInfoFromJson!\n");
	  return -1;
	}
	else
	{
		json_object *sub1obj = json_object_object_get(newObj, "blockAddress");
		if(NULL==sub1obj) //这里就要用NULL判断了, 得不到对应的object就是NULL
		{
		  LOG("sub1obj err, Can't get blockAddress info!\n");
		}
		else
		{
			strcpy(v_BlockAddress,json_object_get_string(sub1obj)); 
			json_object_put(sub1obj);
		}
		json_object *sub2obj = json_object_object_get(newObj, "contractAddress");
		if(NULL==sub2obj) //这里就要用NULL判断了, 得不到对应的object就是NULL
		{
		  LOG("sub2obj err, Can't get contractAddress info!\n");
		  return -1;
		}
		else
		{
			strcpy(v_ContractAddress,json_object_get_string(sub2obj)); 
			json_object_put(sub2obj);
		}
		json_object *sub3obj = json_object_object_get(newObj, "startTime");
		if(NULL==sub3obj) //这里就要用NULL判断了, 得不到对应的object就是NULL
		{
		  LOG("sub3obj err, Can't get startTime info!\n");
		}
		else
		{
			strcpy(v_StartTime,json_object_get_string(sub3obj)); 
			json_object_put(sub3obj);
		}
		
		json_object *sub4obj = json_object_object_get(newObj, "endTime");
		if(NULL==sub4obj) //这里就要用NULL判断了, 得不到对应的object就是NULL
		{
		  LOG("sub4obj err, Can't get endTime info!\n");
		}
		else
		{
			strcpy(v_EndTime,json_object_get_string(sub4obj)); 
			json_object_put(sub4obj);
		}
		
		json_object *sub5obj = json_object_object_get(newObj, "curPage");
		if(NULL==sub5obj) //这里就要用NULL判断了, 得不到对应的object就是NULL
		{
		  LOG("sub5obj err, Can't get curPage info!\n");
		  *v_CurPage = 1;
		}
		else
		{
			*v_CurPage= atoi(json_object_to_json_string(sub5obj)); 
			json_object_put(sub5obj);
		}

		json_object *sub6obj = json_object_object_get(newObj, "numsPerPage");
		if(NULL==sub6obj) //这里就要用NULL判断了, 得不到对应的object就是NULL
		{
		  	LOG("sub6obj err, Can't get numsPerPage info!\n");
		  	*v_NumsPerPage = 20;
		}
		else
		{
			*v_NumsPerPage = atoi(json_object_to_json_string(sub6obj)); 
			json_object_put(sub6obj);
		}
		return 1;
	}
}

int CClientSession::ParseQueryBlockBrowserInfo(char *v_ParamStr, int *v_CurPage, int *v_NumsPerPage)
{
	// 	Get  	http://119.23.36.196:8888/QueryBlockBrowser.do?curPage=1&numsPerPage=30

	char *pFind1 = NULL;
	char *pFind2  = NULL;
	char szTmp[16] = {0};
	int iLen = 0;

	pFind1 = strstr(v_ParamStr, "curPage=");
	if(pFind1 == NULL)
	{
		LOG("Can't find the curPage info from ParseQueryBlockBrowserInfo!\n");
		return -1;
	}
	
	pFind1 += strlen("curPage=");
	
	pFind2 = strstr(pFind1, "&");
	if(pFind2  == NULL)
	{
		LOG("Can't find sepetar & from ParseQueryBlockBrowserInfo!\n");
		return -1;
	}
	if((pFind2 - pFind1) > 8)
	{
		iLen = 8;
	}
	else
	{
		iLen = pFind2 - pFind1;
	}
	memset(szTmp, 0, 16);
	memcpy(szTmp, pFind1, iLen);
	*v_CurPage= atoi(szTmp);

	pFind1 = strstr(v_ParamStr, "numsPerPage=");
	if(pFind1 == NULL)
	{
		LOG("Can't find the numsPerPage info from ParseQueryBlockBrowserInfo!\n");
		return 1;
	}
	
	pFind1 += strlen("numsPerPage=");
	
	pFind2 = strstr(pFind1, "&");
	if(pFind2  == NULL)
	{
		pFind2 = strstr(pFind1, " HTTP");
		if(pFind2 == NULL)
		{
			LOG("Can't find numsPerPage sepetar space from ParseQueryBlockBrowserInfo!\n");
			return -1;
		}
	}
	if((pFind2 - pFind1) > 8)
	{
		iLen = 8;
	}
	else
	{
		iLen = pFind2 - pFind1;
	}
	memset(szTmp, 0, 16);
	memcpy(szTmp, pFind1, iLen);
	*v_NumsPerPage = atoi(szTmp);
	
	return 1;
}

int CClientSession::ParseQueryBlockBrowserInfoFromJson(char *v_ParamStr, int *v_CurPage, int *v_NumsPerPage)
{
	//http://domain:port/QueryBlockBrowser.do
	//{
    //"curPage": 1,
    //"numsPerPage": 30
	//}

	json_object *newObj=NULL;
	if((v_ParamStr == NULL)||(strlen(v_ParamStr) < 2))
	{
		LOG("oh, v_ParamStr err in ParseQueryBlockBrowserInfoFromJson!\n");
	  	return -1;
	}
	newObj = json_tokener_parse(v_ParamStr);
	if( is_error(v_ParamStr) ) //正确
	{
	  LOG("oh, my god. json_tokener_parse err in ParseQueryBlockBrowserInfoFromJson!\n");
	  return -1;
	}
	else
	{
		json_object *sub1obj = json_object_object_get(newObj, "curPage");
		if(NULL==sub1obj) //这里就要用NULL判断了, 得不到对应的object就是NULL
		{
		  	LOG("sub1obj err, Can't get curPage info!\n");
		  	*v_CurPage = 1;
		}
		else
		{
			*v_CurPage = atoi(json_object_to_json_string(sub1obj)); 
			json_object_put(sub1obj);
		}
		
		json_object *sub2obj = json_object_object_get(newObj, "numsPerPage");
		if(NULL==sub2obj) //这里就要用NULL判断了, 得不到对应的object就是NULL
		{
		  	LOG("sub2obj err, Can't get numsPerPage info!\n");
		  	*v_NumsPerPage= 20;
		}
		else
		{
			*v_NumsPerPage= atoi(json_object_to_json_string(sub2obj)); 
			json_object_put(sub2obj);
		}
		
		return 1;
	}
}

int CClientSession::ParseIssueAssetInfo(char *v_ParamStr, int *v_AssetAmount, char *v_AssetCode)
{
	//http://112.113.211.15:8888/IssueAsset.do?assetAmount=1000000000&assetCode=XToken
	char *pFind1 = NULL;
	char *pFind2  = NULL;
	char szTmp[16] = {0};
	int iLen = 0;
	
	pFind1 = strstr(v_ParamStr, "assetAmount=");
	if(pFind1 == NULL)
	{
		LOG("Can't find the assetAmount info from ParseIssueAssetInfo!\n");
		return -1;
	}
	
	pFind1 += strlen("assetAmount=");
	pFind2 = strstr(pFind1, "&");
	if(pFind2  == NULL)
	{
		LOG("Can't find sepetar & in assetAmount from ParseIssueAssetInfo!\n");
		return -1;
	}
	if((pFind2 - pFind1) > 32)
	{
		iLen = 32;
	}
	else
	{
		iLen = pFind2 - pFind1;
	}
	memcpy(szTmp, pFind1, iLen);
	*v_AssetAmount = atoi(szTmp);
	
	pFind1 = strstr(v_ParamStr, "assetCode=");
	if(pFind1 == NULL)
	{
		LOG("Can't find assetCode info from ParseIssueAssetInfo!\n");
		return -1;

	}
	
	pFind1 += strlen("assetCode=");
	pFind2 = strstr(pFind1, "&");
	if(pFind2  == NULL)
	{
		pFind2 = strstr(pFind1, " HTTP");
		if(pFind2 == NULL)
		{
			LOG("Can't find sepetar space in assetCode from ParseIssueAssetInfo!\n");
			return -1;
		}
	}
	if((pFind2 - pFind1) > MAX_DEVIP_LEN)
	{
		iLen = MAX_DEVIP_LEN;
	}
	else
	{
		iLen = pFind2 - pFind1;
	}
	
	memcpy(v_AssetCode, pFind1, iLen);
	
	return 1;
}

int CClientSession::ParseIssueAssetInfoFromJson(char *v_ParamStr, int *v_AssetAmount, char *v_AssetCode)
{
	//http://112.113.211.15:8888/IssueAsset.do?assetAmount=1000000000&assetCode=XToken
	//{
	//"assetAmount":10000,
    //"assetCode": "XToken"
	//}

	json_object *newObj=NULL;
	if((v_ParamStr == NULL)||(strlen(v_ParamStr) < 2))
	{
		LOG("oh, v_ParamStr err in ParseIssueAssetInfoFromJson!\n");
	  	return -1;
	}
	newObj = json_tokener_parse(v_ParamStr);
	if( is_error(v_ParamStr) ) //正确
	{
	  LOG("oh, my god. json_tokener_parse err in ParseIssueAssetInfoFromJson!\n");
	  return -1;
	}
	else
	{
		json_object *sub1obj = json_object_object_get(newObj, "assetAmount");
		if(NULL==sub1obj) //这里就要用NULL判断了, 得不到对应的object就是NULL
		{
		  LOG("sub1obj err, Can't get assetAmount info!\n");
		}
		else
		{
			*v_AssetAmount = atoi(json_object_to_json_string(sub1obj)); 
			json_object_put(sub1obj);
		}
		json_object *sub2obj = json_object_object_get(newObj, "assetCode");
		if(NULL==sub2obj) //这里就要用NULL判断了, 得不到对应的object就是NULL
		{
		  LOG("sub2obj err, Can't get assetCode info!\n");
		}
		else
		{
			strcpy(v_AssetCode,json_object_get_string(sub2obj)); 
			json_object_put(sub2obj);
		}
		return 1;
	}
}

int CClientSession::ParseQueryTransactionHashInfo(char *v_ParamStr, char *v_BlockAddress, char *v_TransactionHash)
{
	//http://domain:port/QueryTransactionHashRecord.do
	//{
		//"contractAddress": "a00126529bc1d468e296bbb02878838415e99f187c94dd"
		//"transactionHash": "255ec0e98c468ad0d19524b20d22f36f4da6b9e9530631e2fc9d4441d83033da"
	//}


	char *pFind1 = NULL;
	char *pFind2  = NULL;
	
	char szTmp[16] = {0};
	int iLen = 0;

	pFind1 = strstr(v_ParamStr, "contractAddress=");
	if(pFind1 == NULL)
	{
		LOG("Can't find the contractAddress info from ParseQueryTransactionHashInfo!\n");
		return -1;
	}
	
	pFind1 += strlen("contractAddress=");
	pFind2 = strstr(pFind1, "&");
	if(pFind2  == NULL)
	{
		pFind2 = strstr(pFind1, " HTTP");
		if(pFind2 == NULL)
		{
			LOG("Can't find sepetar space from ParseQueryTransactionHashInfo!\n");
			return -1;
		}
	}
	if((pFind2 - pFind1) > MAX_USERID_LEN)
	{
		iLen = MAX_USERID_LEN;
	}
	else
	{
		iLen = pFind2 - pFind1;
	}
	memcpy(v_BlockAddress, pFind1, iLen);


	pFind1 = strstr(v_ParamStr, "transactionHash=");
	if(pFind1 == NULL)
	{
		LOG("Can't find the transactionHash info from ParseQueryTransactionHashInfo!\n");
		return 1;
	}
	
	pFind1 += strlen("transactionHash=");
	pFind2 = strstr(pFind1, "&");
	if(pFind2  == NULL)
	{
		pFind2 = strstr(pFind1, " HTTP");
		if(pFind2 == NULL)
		{
			LOG("Can't find transactionHash from ParseQueryTransactionHashInfo!\n");
			return 1;
		}
	}
	if((pFind2 - pFind1) > MAX_ADDRESS_LEN)
	{
		iLen = MAX_ADDRESS_LEN;
	}
	else
	{
		iLen = pFind2 - pFind1;
	}
	
	memcpy(v_TransactionHash, pFind1, iLen);
	
	return 1;

}

int CClientSession::ParseQueryTransactionHashInfoFromJson(char *v_ParamStr, char *v_BlockAddress, char *v_TransactionHash)
{
	//http://domain:port/QueryTransactionHashRecord.do
	//{
		//"contractAddress": "a00126529bc1d468e296bbb02878838415e99f187c94dd"
    	//"transactionHash": "255ec0e98c468ad0d19524b20d22f36f4da6b9e9530631e2fc9d4441d83033da"
    //}

	json_object *newObj=NULL;
	if((v_ParamStr == NULL)||(strlen(v_ParamStr) < 2))
	{
		LOG("oh, v_ParamStr err in ParseQueryTransactionHashInfoFromJson!\n");
	  	return -1;
	}
	newObj = json_tokener_parse(v_ParamStr);
	if( is_error(v_ParamStr) ) //正确
	{
	  LOG("oh, my god. json_tokener_parse err in ParseQueryTransactionHashInfoFromJson!\n");
	  return -1;
	}
	else
	{
		json_object *sub1obj = json_object_object_get(newObj, "contractAddress");
		if(NULL==sub1obj) //这里就要用NULL判断了, 得不到对应的object就是NULL
		{
		  	LOG("sub1obj err, Can't get contractAddress info!\n");
			json_object_put(sub1obj);
		  	return -1;
		}
		else
		{
			strcpy(v_BlockAddress,json_object_get_string(sub1obj)); 
			json_object_put(sub1obj);
		}
		json_object *sub2obj = json_object_object_get(newObj, "transactionHash");
		if(NULL==sub2obj) //这里就要用NULL判断了, 得不到对应的object就是NULL
		{
		  	LOG("sub2obj err, Can't get transactionHash info!\n");
			json_object_put(sub2obj);
		  	return -1;
		}
		else
		{
			strcpy(v_TransactionHash,json_object_get_string(sub2obj)); 
			json_object_put(sub2obj);
		}
		
		return 1;
	}
}

int CClientSession::ParseQueryBlockTransactionInfo(char *v_ParamStr, int *v_BlockSeq)
{
	//http://domain:port/QueryBlockTranscation.do
	//{
		//"ledgerSeq ": 12345
	//}

	char *pFind1 = NULL;
	char *pFind2  = NULL;
	char szTmp[16] = {0};
	int iLen = 0;
	
	pFind1 = strstr(v_ParamStr, "ledgerSeq=");
	if(pFind1 == NULL)
	{
		LOG("Can't find the ledgerSeq info from ParseQueryBlockTransactionInfo!\n");
		return -1;
	}
	
	pFind1 += strlen("ledgerSeq=");
	pFind2 = strstr(pFind1, "&");
	if(pFind2  == NULL)
	{
		LOG("Can't find sepetar & in ledgerSeq from ParseQueryBlockTransactionInfo!\n");
		return -1;
	}
	if((pFind2 - pFind1) > 32)
	{
		iLen = 32;
	}
	else
	{
		iLen = pFind2 - pFind1;
	}
	memcpy(szTmp, pFind1, iLen);
	*v_BlockSeq = atoi(szTmp);
	
	return 1;

}

int CClientSession::ParseQueryBlockTransactionInfoFromJson(char *v_ParamStr, int *v_BlockSeq)
{
	//http://domain:port/QueryBlockTranscation.do
	//{
		//"blockSeq ": 12345
    //}

	json_object *newObj=NULL;
	if((v_ParamStr == NULL)||(strlen(v_ParamStr) < 2))
	{
		LOG("oh, v_ParamStr err in ParseQueryTransactionHashInfoFromJson!\n");
	  	return -1;
	}
	newObj = json_tokener_parse(v_ParamStr);
	if( is_error(v_ParamStr) ) //正确
	{
	  LOG("oh, my god. json_tokener_parse err in ParseQueryTransactionHashInfoFromJson!\n");
	  return -1;
	}
	else
	{
		json_object *sub1obj = json_object_object_get(newObj, "ledgerSeq");
		if(NULL==sub1obj) //这里就要用NULL判断了, 得不到对应的object就是NULL
		{
		  	LOG("sub1obj err, Can't get ledgerSeq info!\n");
			json_object_put(sub1obj);
		  	*v_BlockSeq = 1;
		}
		else
		{
			*v_BlockSeq = atoi(json_object_to_json_string(sub1obj)); 
			json_object_put(sub1obj);
		}
		
		return 1;
	}
}

int CClientSession::ParseBlockAddressNonceInfo(char *v_ParamStr, char *v_BlockAddress)
{
	//http://IP:Port/QueryNonceInfo.do?blockAddress=10010000
	char *pFind1 = NULL;
	char *pFind2  = NULL;
	
	char szTmp[16] = {0};
	int iLen = 0;

	pFind1 = strstr(v_ParamStr, "blockAddress=");
	if(pFind1 == NULL)
	{
		LOG("Can't find the blockAddress info from ParseBlockAddressNonceInfo!\n");
		return -1;
	}
	
	pFind1 += strlen("blockAddress=");
	pFind2 = strstr(pFind1, "&");
	if(pFind2  == NULL)
	{
		pFind2 = strstr(pFind1, " HTTP");
		if(pFind2 == NULL)
		{
			LOG("Can't find sepetar space from ParseBlockAddressNonceInfo!\n");
			return -1;
		}
	}
	if((pFind2 - pFind1) > MAX_USERID_LEN)
	{
		iLen = MAX_USERID_LEN;
	}
	else
	{
		iLen = pFind2 - pFind1;
	}
	memcpy(v_BlockAddress, pFind1, iLen);

	return 1;

}


int CClientSession::ParseBlockAddressNonceInfoFromJson(char *v_ParamStr, char *v_BlockAddress)
{
	// 	http://domain:port/BusinessDataStorage.do
	//{
    //"blockAddress": "ea01f4e51a636bd0d4ec123c94870560f64cbd97758167",
    //}

	json_object *newObj=NULL;
	if((v_ParamStr == NULL)||(strlen(v_ParamStr) < 2))
	{
		LOG("oh, v_ParamStr err in ParseBlockAddressNonceInfoFromJson!\n");
	  	return -1;
	}
	newObj = json_tokener_parse(v_ParamStr);
	if( is_error(v_ParamStr) ) //正确
	{
	  LOG("oh, my god. json_tokener_parse err in ParseBlockAddressNonceInfoFromJson!\n");
	  return -1;
	}
	else
	{
		json_object *sub1obj = json_object_object_get(newObj, "blockAddress");
		if(NULL==sub1obj) //这里就要用NULL判断了, 得不到对应的object就是NULL
		{
		  LOG("sub1obj err, Can't get blockAddress info!\n");
		  return -1;
		}
		else
		{
			strcpy(v_BlockAddress,json_object_get_string(sub1obj)); 
			json_object_put(sub1obj);
		}
		
		return 1;
	}
}


int CClientSession::HttpDateProcess(char *v_ContentBuf)
{
	int iRet = 0;
	switch (m_ProtocalType)
	{
		case	USERREGISTER:
			// 	 	http://domain:port/UserRegister.do
			{
				char szUserID[MAX_USERID_LEN] = {0};
				char szUserInfo[MAX_USERINFO_LEN] = {0};
				int iUserType = 0;
				int iEncryFlag = 0;
				char szEncryKey[MAX_ENCRYKEY_LEN] = {0};

				std::string strUserID;
				std::string strUserInfo;
				std::string strBlockAddress;
				std::string strPrivateKey;
				std::string strPublicKey;
				std::string strTransactionHash;
				char szResBuf[256] = {0};
				int iRet = 0;
				
				url_decode(m_HttpParam);

				if(ParseUserRegisterInfo(m_HttpParam, szUserID, szUserInfo, &iUserType) < 0)
				{
					if(ParseUserRegisterInfoFromJson(v_ContentBuf, szUserID, szUserInfo, &iUserType) < 0)
					{
						LOG("ParseUserRegisterInfoFromJson failed, v_ContentBuf = %s,\nm_HttpParam = %s!\n", v_ContentBuf, m_HttpParam);
						sprintf(szResBuf, "{\"blockAddress\":null, \"prvKey\":null, \"pubKey\":null, \"transactionHash\":null, \"result\":-9}");
						MakeHttpErrResponse(szResBuf, 200);
						if(SendPushData(m_SendBuf, strlen(m_SendBuf)) < 0)		
						{			
							LOG("SendPushData error!\n");
							return -1;
						}
						return -1;
					}
				}
				
				LOG("User Register request, szUserID = %s, szUserInfo = %s!\n", szUserID, szUserInfo);
				strUserID = szUserID;
				strUserInfo = szUserInfo;
				
				//Φ¼Ҽ¤»ʺ³ʇ�֋ºÉ
				iRet = EChain_UserRegister(strUserID, iUserType, strUserInfo, strBlockAddress, strPrivateKey, strPublicKey, strTransactionHash);
				if(iRet < 0)	
				{		
					LOG("EChain_ClientRegister failed!\n");
					sprintf(szResBuf, "{\"blockAddress\":null, \"prvKey\":null, \"pubKey\":null, \"transactionHash\":null, \"result\":%d}", iRet);
					MakeHttpErrResponse(szResBuf, 200);
					if(SendPushData(m_SendBuf, strlen(m_SendBuf)) < 0)		
					{			
						LOG("SendPushData error!\n");
						return -1;
					}
					return -1;	
				}
				
				//HTTP回应PC客户端
				sprintf(szResBuf, "{\"blockAddress\":\"%s\", \"prvKey\":\"%s\", \"pubKey\":\"%s\", \"transactionHash\":\"%s\", \"result\":%d}", strBlockAddress.c_str(), strPrivateKey.c_str(), strPublicKey.c_str(), strTransactionHash.c_str(), iRet);
				MakeHttpGetResponse(szResBuf);
			
				if(SendPushData(m_SendBuf, m_SendLen) < 0)		
				{			
					LOG("SendPushData error!\n");			
					return -1;
				}
				
				//短连接，处理完即退出
				Stop();
				return 1;
			}
			break;
		case	USERCERTIFICATION:
			// 	 	http://IP:Port/UserCertification.do?
			{
				char szBlockAddress[MAX_ADDRESS_LEN] = {0};
				char szUserName[MAX_USERNAME_LEN] = {0};
				
				char *pUserInfo = NULL;
				pUserInfo = (char *)malloc(sizeof(char) * (m_ContentLen + 1));		
				if(pUserInfo == NULL)		
				{			
					LOG("malloc pUserInfo failed!\n");			
					return -1;		
				}	
				memset(pUserInfo, 0, m_ContentLen + 1);
			
				std::string strBlockAddress;
				std::string strUserName;
				std::string strTransactionHash;
				std::string strUserInfo;
				char szResBuf[256] = {0};
				int iRet = 0;
				
				url_decode(m_HttpParam);
				url_decode(v_ContentBuf);
				if(ParseUserCertificationInfo(m_HttpParam, szBlockAddress, szUserName, pUserInfo) < 0)
				{
					if(ParseUserCertificationInfoFromJson(v_ContentBuf, szBlockAddress, szUserName, pUserInfo) < 0)
					{
						LOG("ParseUserCertificationInfoFromJson failed, v_ContentBuf = %s,\nm_HttpParam = %s!\n", v_ContentBuf, m_HttpParam);
						sprintf(szResBuf, "{\"transactionHash\":null, \"result\":-9}");
						MakeHttpErrResponse(szResBuf, 200);
						if(SendPushData(m_SendBuf, strlen(m_SendBuf)) < 0)		
						{			
							LOG("SendPushData error!\n");
							return -1;
						}
						if(pUserInfo != NULL)
						{
							free(pUserInfo);
							pUserInfo = NULL;
						}
						return -1;
					}
				}
				
				LOG("User Certification request, v_ContentBuf = %s!\n", v_ContentBuf);
				strBlockAddress= szBlockAddress;
				strUserName= szUserName;
				strUserInfo = pUserInfo;

				iRet = EChain_UserCertification(strBlockAddress, strUserName, strUserInfo, strTransactionHash);
				if(iRet <= 0)	
				{		
					LOG("EChain_ClientCertification failed, v_ContentBuf is %s!\n", v_ContentBuf);
					sprintf(szResBuf, "{\"transactionHash\":null, \"result\":%d}", iRet);
					MakeHttpErrResponse(szResBuf, 200);
					if(SendPushData(m_SendBuf, strlen(m_SendBuf)) < 0)		
					{			
						LOG("SendPushData error!\n");
						return -1;
					}
					if(pUserInfo != NULL)
					{
						free(pUserInfo);
						pUserInfo = NULL;
					}
					return -1;	
				}

				sprintf(szResBuf, "{\"transactionHash\":\"%s\", \"result\":%d}",strTransactionHash.c_str(), iRet);
				//HTTP回应PC客户端
				MakeHttpGetResponse(szResBuf);
			
				if(SendPushData(m_SendBuf, m_SendLen) < 0)		
				{			
					LOG("SendPushData error!\n");
					if(pUserInfo != NULL)
					{
						free(pUserInfo);
						pUserInfo = NULL;
					}
					return -1;
				}
				if(pUserInfo != NULL)
				{
					free(pUserInfo);
					pUserInfo = NULL;
				}
				//短连接，处理完即退出
				Stop();
				return 1;
			}
			break;
			case	CREATECONTRACTADDRESS:
			// 	 	http://domain:port/CreateContractAddress.do
			{
				char szUserID[MAX_USERID_LEN] = {0};
				char szClassID[MAX_USERID_LEN] = {0};
				
				std::string strUserID;
				std::string strClassID;
				std::string strContractAddress;
				std::string strPrivateKey;
				std::string strPublicKey;
				std::string strTransactionHash;
				char szResBuf[256] = {0};
				int iRet = 0;
				
				url_decode(m_HttpParam);

				if(ParseCreateContractAddressInfo(m_HttpParam, szUserID, szClassID) < 0)
				{
					if(ParseCreateContractAddressInfoFromJson(v_ContentBuf, szUserID, szClassID) < 0)
					{
						LOG("ParseCreateContractAddressInfoFromJson failed, v_ContentBuf = %s,\nm_HttpParam = %s!\n", v_ContentBuf, m_HttpParam);
						sprintf(szResBuf, "{\"contractAddress\":null, \"prvKey\":null, \"pubKey\":null, \"transactionHash\":null, \"result\":-9}");
						MakeHttpErrResponse(szResBuf, 200);
						if(SendPushData(m_SendBuf, strlen(m_SendBuf)) < 0)		
						{			
							LOG("SendPushData error!\n");
							return -1;
						}
						return -1;
					}
				}
				
				LOG("CreateContractAddress request, szUserID = %s, szClassID = %s!\n", szUserID, szClassID);
				strUserID = szUserID;
				strClassID= szClassID;
				
				//Φ¼Ҽ¤»ʺ³ʇ�֋ºÉ
				iRet = EChain_ContractAddressCreate(strUserID, strClassID, strContractAddress, strPrivateKey, strPublicKey, strTransactionHash);
				if(iRet < 0)	
				{		
					LOG("EChain_CreateContractAddress failed!\n");
					sprintf(szResBuf, "{\"contractAddress\":null, \"prvKey\":null, \"pubKey\":null, \"transactionHash\":null, \"result\":%d}", iRet);
					MakeHttpErrResponse(szResBuf, 200);
					if(SendPushData(m_SendBuf, strlen(m_SendBuf)) < 0)		
					{			
						LOG("SendPushData error!\n");
						return -1;
					}
					return -1;	
				}
				
				//HTTP回应PC客户端
				sprintf(szResBuf, "{\"contractAddress\":\"%s\", \"prvKey\":\"%s\", \"pubKey\":\"%s\", \"transactionHash\":\"%s\", \"result\":%d}", strContractAddress.c_str(), strPrivateKey.c_str(), strPublicKey.c_str(), strTransactionHash.c_str(), iRet);
				MakeHttpGetResponse(szResBuf);
			
				if(SendPushData(m_SendBuf, m_SendLen) < 0)		
				{			
					LOG("SendPushData error!\n");			
					return -1;
				}
				
				//短连接，处理完即退出
				Stop();
				return 1;
			}
			break;
			case	BUSINESSDATASTORAGE:
			//http://domain:port/BusinessDataStorage.do
			{
				char szContractAddress[MAX_ADDRESS_LEN] = {0};
				int iBusinessType = 0;
				char szDataHash[MAX_ADDRESS_LEN] = {0};
				char szDataPath[MAX_FILEPATH_LEN] = {0};

				std::string strContractAddress;
				std::string strDataHash;
				std::string strDataPath;
				std::string strTransactionHash;
				std::string strDescInfo;
				char szResBuf[256] = {0};
				int iRet = 0;
				
				char *pDescInfo = NULL;
				pDescInfo = (char *)malloc(sizeof(char) * (m_ContentLen + 1));		
				if(pDescInfo == NULL)		
				{			
					LOG("malloc pDescInfo failed!\n");			
					return -1;		
				}	
				memset(pDescInfo, 0, m_ContentLen + 1);

				url_decode(m_HttpParam);

				if(ParseDataStorageInfo(m_HttpParam, szContractAddress, &iBusinessType, szDataHash,szDataPath, pDescInfo) < 0)
				{
					if(ParseDataStorageInfoFromJson(v_ContentBuf, szContractAddress, &iBusinessType, szDataHash,szDataPath, pDescInfo) < 0)
					{
						LOG("ParseDataStorageInfoFromJson failed, v_ContentBuf = %s,\nm_HttpParam = %s!\n", v_ContentBuf, m_HttpParam);
						sprintf(szResBuf, "{\"transactionHash\":null, \"result\":-9}");
						MakeHttpErrResponse(szResBuf, 200);
						if(SendPushData(m_SendBuf, strlen(m_SendBuf)) < 0)		
						{			
							LOG("SendPushData error!\n");
							if(pDescInfo != NULL)
							{
								free(pDescInfo);
								pDescInfo = NULL;
							}
							return -1;
						}
						if(pDescInfo != NULL)
						{
							free(pDescInfo);
							pDescInfo = NULL;
						}
						return -1;
					}
				}
				
				LOG("BusinessDataStorage request, szContractAddress = %s, szDescInfo = %s!\n", szContractAddress, pDescInfo);
				strContractAddress= szContractAddress;
				strDataHash = szDataHash;
				strDataPath = szDataPath;
				strDescInfo = pDescInfo;

				iRet = EChain_BusinessDataStorage(strContractAddress, iBusinessType, strDataHash, strDataPath, strDescInfo, strTransactionHash);
				if(iRet <= 0)	
				{		
					LOG("EChain_BusinessDataStorage failed, v_ContentBuf is %s!\n", v_ContentBuf);
					sprintf(szResBuf, "{\"transactionHash\":null, \"result\":%d}",iRet);
					MakeHttpErrResponse(szResBuf, 200);
					if(SendPushData(m_SendBuf, strlen(m_SendBuf)) < 0)		
					{			
						LOG("SendPushData error!\n");
						if(pDescInfo != NULL)
						{
							free(pDescInfo);
							pDescInfo = NULL;
						}
						return -1;
					}
					if(pDescInfo != NULL)
					{
						free(pDescInfo);
						pDescInfo = NULL;
					}
					return -1;	
				}

				sprintf(szResBuf, "{\"transactionHash\":\"%s\", \"result\":%d}",strTransactionHash.c_str(), iRet);
				//HTTP回应PC客户端
				MakeHttpGetResponse(szResBuf);
			
				if(SendPushData(m_SendBuf, m_SendLen) < 0)		
				{			
					LOG("SendPushData error!\n");
					if(pDescInfo != NULL)
					{
						free(pDescInfo);
						pDescInfo = NULL;
					}
					return -1;
				}
				if(pDescInfo != NULL)
				{
					free(pDescInfo);
					pDescInfo = NULL;
				}
				//短连接，处理完即退出
				Stop();
				return 1;
			}
			break;
			case	BUSINESSDATAUPDATE:
			//http://domain:port/BusinessDataUpdate.do
			{
				char szContractAddress[MAX_ADDRESS_LEN] = {0};
				int iUpdateType = 0;
				int iBusinessType = 0;
				char szTranxHash[MAX_ADDRESS_LEN] = {0};
				char szDataHash[MAX_ADDRESS_LEN] = {0};
				char szDataPath[MAX_FILEPATH_LEN] = {0};

				std::string strContractAddress;
				std::string strTranxHash;
				std::string strDataHash;
				std::string strDataPath;
				
				std::string strTransactionHash;
				std::string strDescInfo;
				char szResBuf[256] = {0};
				int iRet = 0;
				
				char *pDescInfo = NULL;
				pDescInfo = (char *)malloc(sizeof(char) * (m_ContentLen + 1));		
				if(pDescInfo == NULL)		
				{			
					LOG("malloc pDescInfo failed!\n");			
					return -1;		
				}	
				memset(pDescInfo, 0, m_ContentLen + 1);

				url_decode(m_HttpParam);
				if(ParseDataUpdateInfo(m_HttpParam, szContractAddress, &iUpdateType, &iBusinessType, szTranxHash, szDataHash, szDataPath, pDescInfo) < 0)
				{
					if(ParseDataUpdateInfoFromJson(v_ContentBuf, szContractAddress, &iUpdateType, &iBusinessType, szTranxHash, szDataHash, szDataPath, pDescInfo) < 0)
					{
						LOG("ParseDataUpdateInfoFromJson failed, v_ContentBuf = %s,\nm_HttpParam = %s!\n", v_ContentBuf, m_HttpParam);
						sprintf(szResBuf, "{\"transactionHash\":null, \"result\":-9}");
						MakeHttpErrResponse(szResBuf, 200);
						if(SendPushData(m_SendBuf, strlen(m_SendBuf)) < 0)		
						{			
							LOG("SendPushData error!\n");
							if(pDescInfo != NULL)
							{
								free(pDescInfo);
								pDescInfo = NULL;
							}
							return -1;
						}
						if(pDescInfo != NULL)
						{
							free(pDescInfo);
							pDescInfo = NULL;
						}
						return -1;
					}
				}
				LOG("BusinessDataUpdate request, szContractAddress = %s, szDescInfo = %s!\n", szContractAddress, pDescInfo);
				strContractAddress= szContractAddress;
				strTranxHash = szTranxHash;
				strDataHash = szDataHash;
				strDataPath = szDataPath;
				strDescInfo = pDescInfo;

				iRet = EChain_BusinessDataUpdate(strContractAddress, iUpdateType, iBusinessType, strTranxHash, strDataHash, strDataPath, strDescInfo, strTransactionHash);
				if(iRet <= 0)	
				{		
					LOG("EChain_BusinessDataUpdate failed, v_ContentBuf is %s!\n", v_ContentBuf);
					sprintf(szResBuf, "{\"transactionHash\":null, \"result\":%d}",iRet);
					MakeHttpErrResponse(szResBuf, 200);
					if(SendPushData(m_SendBuf, strlen(m_SendBuf)) < 0)		
					{			
						LOG("SendPushData error!\n");
						if(pDescInfo != NULL)
						{
							free(pDescInfo);
							pDescInfo = NULL;
						}
						return -1;
					}
					if(pDescInfo != NULL)
					{
						free(pDescInfo);
						pDescInfo = NULL;
					}
					return -1;	
				}

				sprintf(szResBuf, "{\"transactionHash\":\"%s\", \"result\":%d}",strTransactionHash.c_str(), iRet);
				//HTTP回应PC客户端
				MakeHttpGetResponse(szResBuf);
			
				if(SendPushData(m_SendBuf, m_SendLen) < 0)		
				{			
					LOG("SendPushData error!\n");
					if(pDescInfo != NULL)
					{
						free(pDescInfo);
						pDescInfo = NULL;
					}
					return -1;
				}
				if(pDescInfo != NULL)
				{
					free(pDescInfo);
					pDescInfo = NULL;
				}
				//短连接，处理完即退出
				Stop();
				return 1;
			}
			break;
			case	CONTRACTADDRESSDELETE:
			//http://domain:port/ContractAddressDelete.do
			{
				char szBlockAddress[MAX_ADDRESS_LEN] = {0};
				char szContractAddress[MAX_ADDRESS_LEN] = {0};
				char szDescInfo[MAX_USERINFO_LEN] = {0};

				std::string strBlockAddress;
				std::string strContractAddress;
				std::string strDescInfo;
				
				char szResBuf[256] = {0};
				int iRet = 0;
				
				char *pDescInfo = NULL;
				pDescInfo = (char *)malloc(sizeof(char) * (m_ContentLen + 1));		
				if(pDescInfo == NULL)		
				{			
					LOG("malloc pDescInfo failed!\n");			
					return -1;		
				}	
				memset(pDescInfo, 0, m_ContentLen + 1);

				url_decode(m_HttpParam);
				if(ParseContractAddressDeleteInfo(m_HttpParam, szBlockAddress, szContractAddress, pDescInfo) < 0)
				{
					if(ParseContractAddressDeleteInfoFromJson(v_ContentBuf, szBlockAddress, szContractAddress, pDescInfo) < 0)
					{
						LOG("ParseContractAddressDeleteInfoFromJson failed, v_ContentBuf = %s,\nm_HttpParam = %s!\n", v_ContentBuf, m_HttpParam);
						sprintf(szResBuf, "{\"result\":-9}");
						MakeHttpErrResponse(szResBuf, 200);
						if(SendPushData(m_SendBuf, strlen(m_SendBuf)) < 0)		
						{			
							LOG("SendPushData error!\n");
							if(pDescInfo != NULL)
							{
								free(pDescInfo);
								pDescInfo = NULL;
							}
							return -1;
						}
						if(pDescInfo != NULL)
						{
							free(pDescInfo);
							pDescInfo = NULL;
						}
						return -1;
					}
				}
				LOG("ContractAddressDelete request, szBlockAddress = %s, szContractAddress = %s, szDescInfo = %s!\n", szBlockAddress, szContractAddress, pDescInfo);
				strBlockAddress = szBlockAddress;
				strContractAddress= szContractAddress;
				strDescInfo = pDescInfo;

				iRet = EChain_ContractAddressDelete(strBlockAddress, strContractAddress, strDescInfo);
				if(iRet <= 0)	
				{		
					LOG("EChain_ContractAddressDelete failed, v_ContentBuf is %s!\n", v_ContentBuf);
					sprintf(szResBuf, "{\"result\":%d}",iRet);
					MakeHttpErrResponse(szResBuf, 200);
					if(SendPushData(m_SendBuf, strlen(m_SendBuf)) < 0)		
					{			
						LOG("SendPushData error!\n");
						if(pDescInfo != NULL)
						{
							free(pDescInfo);
							pDescInfo = NULL;
						}
						return -1;
					}
					if(pDescInfo != NULL)
					{
						free(pDescInfo);
						pDescInfo = NULL;
					}
					return -1;	
				}

				sprintf(szResBuf, "{\"result\":%d}", iRet);
				//HTTP回应PC客户端
				MakeHttpGetResponse(szResBuf);
			
				if(SendPushData(m_SendBuf, m_SendLen) < 0)		
				{			
					LOG("SendPushData error!\n");
					if(pDescInfo != NULL)
					{
						free(pDescInfo);
						pDescInfo = NULL;
					}
					return -1;
				}
				if(pDescInfo != NULL)
				{
					free(pDescInfo);
					pDescInfo = NULL;
				}
				//短连接，处理完即退出
				Stop();
				return 1;
			}
			break;
		case	INTEGRITYVERIFICATION:
			// 	http://domain:port/IntegrityVerification.do
			{
				char szBlockAddress[MAX_ADDRESS_LEN] = {0};
				char szContractAddress[MAX_ADDRESS_LEN] = {0};
				int iBusinessType = 0;
				char szTranxHash[MAX_ADDRESS_LEN] = {0};
				char szDataHash[MAX_ADDRESS_LEN] = {0};

				std::string strBlockAddress;
				std::string strContractAddress;
				std::string strTranxHash;
				std::string strDataHash;
				std::string strDataPath;
				int iRet;
				char szResBuf[256] = {0};
				
				url_decode(m_HttpParam);
				if(ParseIntegrityVerificationInfo(m_HttpParam, szBlockAddress, szContractAddress, &iBusinessType, szTranxHash, szDataHash) < 0)
				{
					if(ParseIntegrityVerificationInfoFromJson(v_ContentBuf, szBlockAddress, szContractAddress, &iBusinessType, szTranxHash, szDataHash) < 0)
					{
						LOG("ParseIntegrityVerificationInfoFromJson failed, v_ContentBuf = %s,\nm_HttpParam = %s!\n", v_ContentBuf, m_HttpParam);
						sprintf(szResBuf, "{\"result\":-1}");
						MakeHttpErrResponse(szResBuf, 200);
						if(SendPushData(m_SendBuf, strlen(m_SendBuf)) < 0)		
						{			
							LOG("SendPushData error!\n");
							return -1;
						}
						return -1;
					}
				}
				LOG("IntegrityVerification request, szBlockAddress = %s, iBusinessType = %d, szTranxHash = %s, szDataHash = %s!\n", szBlockAddress, iBusinessType, szTranxHash, szDataHash);
				strBlockAddress = szBlockAddress;
				strTranxHash = szTranxHash;
				strDataHash = szDataHash;
				
				iRet = EChain_UserIntegrityVerification(strBlockAddress, strContractAddress, iBusinessType, strTranxHash, strDataHash);
				if(iRet <= 0)	
				{		
					LOG("EChain_IntegrityVerification failed, v_ContentBuf is %s!\n", v_ContentBuf);
					sprintf(szResBuf, "{\"result\":%d}",iRet);
					MakeHttpErrResponse(szResBuf, 200);
					if(SendPushData(m_SendBuf, strlen(m_SendBuf)) < 0)		
					{			
						LOG("SendPushData error!\n");
						
						return -1;
					}
					
					return -1;	
				}

				sprintf(szResBuf, "{\"result\":%d}", iRet);
				//HTTP回应PC客户端
				MakeHttpGetResponse(szResBuf);
			
				if(SendPushData(m_SendBuf, m_SendLen) < 0)		
				{			
					LOG("SendPushData error!\n");
					
					return -1;
				}
				
				//短连接，处理完即退出
				Stop();
				return 1;
			}
			break;
		case	DATASHAREDCONTENT:
			// 	http://domain:port/DataSharedContent.do
			{
				char szBlockAddress[MAX_ADDRESS_LEN] = {0};
				char szContractAddress[MAX_ADDRESS_LEN] = {0};
				int iBusinessType = 0;
				char szTranxHash[MAX_ADDRESS_LEN] = {0};
				char szDataHash[MAX_ADDRESS_LEN] = {0};

				std::string strBlockAddress;
				std::string strContractAddress;
				std::string strTranxHash;
				std::string strDataHash;
				std::string strDataPath;
				int iRet;
				char szResBuf[256] = {0};
				
				url_decode(m_HttpParam);
				if(ParseDataSharedContentInfo(m_HttpParam, szBlockAddress, szContractAddress, &iBusinessType, szTranxHash, szDataHash) < 0)
				{
					if(ParseDataSharedContentInfoFromJson(v_ContentBuf, szBlockAddress, szContractAddress, &iBusinessType, szTranxHash, szDataHash) < 0)
					{
						LOG("ParseDataSharedContentInfoFromJson failed, v_ContentBuf = %s,\nm_HttpParam = %s!\n", v_ContentBuf, m_HttpParam);
						sprintf(szResBuf, "{\"dataPath\":null, \"result\":-1}");
						MakeHttpErrResponse(szResBuf, 200);
						if(SendPushData(m_SendBuf, strlen(m_SendBuf)) < 0)		
						{			
							LOG("SendPushData error!\n");
							return -1;
						}
						return -1;
					}
				}
				LOG("DataSharedContent request, szBlockAddress = %s, iBusinessType = %d!\n", szBlockAddress, iBusinessType);
				strBlockAddress = szBlockAddress;
				strContractAddress= szContractAddress;
				strTranxHash = szTranxHash;
				strDataHash = szDataHash;
				
				iRet = EChain_DataSharedContent(strBlockAddress, strContractAddress, iBusinessType, strTranxHash, strDataHash, strDataPath);
				if(iRet <= 0)	
				{		
					LOG("EChain_DataSharedContent failed, v_ContentBuf is %s!\n", v_ContentBuf);
					sprintf(szResBuf, "{\"dataPath\":null, \"result\":%d}",iRet);
					MakeHttpErrResponse(szResBuf, 200);
					if(SendPushData(m_SendBuf, strlen(m_SendBuf)) < 0)		
					{			
						LOG("SendPushData error!\n");
						
						return -1;
					}
					
					return -1;	
				}

				sprintf(szResBuf, "{\"dataPath\":\"%s\", \"result\":%d}", strDataPath.c_str(), iRet);
				//HTTP回应PC客户端
				MakeHttpGetResponse(szResBuf);
			
				if(SendPushData(m_SendBuf, m_SendLen) < 0)		
				{			
					LOG("SendPushData error!\n");
					
					return -1;
				}
				
				//短连接，处理完即退出
				Stop();
				return 1;
			}
			break;
		case	DATASHAREDRESULT:
			// http://domain:port/DataSharedResult.do
			{
				char szBlockAddress[MAX_ADDRESS_LEN] = {0};
				char szContractAddress[MAX_ADDRESS_LEN] = {0};
				int iBusinessType = 0;
				char szTranxHash[MAX_ADDRESS_LEN] = {0};
				char szDataHash[MAX_ADDRESS_LEN] = {0};
				char szConditionInfo[MAX_JSONINFO_LEN] = {0};

				std::string strBlockAddress;
				std::string strContractAddress;
				std::string strTranxHash;
				std::string strDataHash;
				std::string strConditionInfo;
				std::string strDataResult;
				int iRet;
				char szResBuf[256] = {0};
				
				url_decode(m_HttpParam);
				if(ParseDataSharedResultInfo(m_HttpParam, szBlockAddress, szContractAddress, &iBusinessType, szTranxHash, szDataHash, szConditionInfo) < 0)
				{
					if(ParseDataSharedResultInfoFromJson(v_ContentBuf, szBlockAddress, szContractAddress, &iBusinessType, szTranxHash, szDataHash, szConditionInfo) < 0)
					{
						LOG("ParseDataSharedContentInfoFromJson failed, v_ContentBuf = %s,\nm_HttpParam = %s!\n", v_ContentBuf, m_HttpParam);
						sprintf(szResBuf, "{\"dataResult\":null, \"result\":-1}");
						MakeHttpErrResponse(szResBuf, 200);
						if(SendPushData(m_SendBuf, strlen(m_SendBuf)) < 0)		
						{			
							LOG("SendPushData error!\n");
							return -1;
						}
						return -1;
					}
				}
				LOG("DataSharedResult request, szBlockAddress = %s, szContractAddress = %s, iBusinessType = %d!\n", szBlockAddress, szContractAddress, iBusinessType);
				strBlockAddress = szBlockAddress;
				strContractAddress= szContractAddress;
				strTranxHash = szTranxHash;
				strDataHash = szDataHash;
				strConditionInfo= szConditionInfo;
				
				iRet = EChain_DataSharedResult(strBlockAddress, strContractAddress, iBusinessType, strTranxHash, strDataHash, strConditionInfo, strDataResult);
				if(iRet <= 0)	
				{		
					LOG("EChain_DataSharedResult failed, v_ContentBuf is %s!\n", v_ContentBuf);
					sprintf(szResBuf, "{\"dataResult\":null, \"result\":%d}",iRet);
					MakeHttpErrResponse(szResBuf, 200);
					if(SendPushData(m_SendBuf, strlen(m_SendBuf)) < 0)		
					{			
						LOG("SendPushData error!\n");
					}
					
					return -1;	
				}

				sprintf(szResBuf, "{\"dataResult\":\"%s\", \"result\":%d}", strDataResult.c_str(), iRet);
				//HTTP回应PC客户端
				MakeHttpGetResponse(szResBuf);
			
				if(SendPushData(m_SendBuf, m_SendLen) < 0)		
				{			
					LOG("SendPushData error!\n");
					
					return -1;
				}
				
				//短连接，处理完即退出
				Stop();
				return 1;
			}
			break;
		case	QUERYADDRESSRECORD:
			{
				char szBlockAddress[MAX_ADDRESS_LEN] = {0};
				char szContractAddress[MAX_ADDRESS_LEN] = {0};
				char szStartTime[MAX_USERID_LEN] = {0};
				char szEndTime[MAX_ENCRYKEY_LEN] = {0};
				int iEncryFlag = 0;
				char szEncryKey[MAX_ENCRYKEY_LEN] = {0};
				
				std::string strBlockAddress;
				std::string strContractAddress;
				int iCurPage = 0;
				int iNumsPerPage = 0;
				std::string strStartTime;
				std::string strEndTime;
				std::string strTranxInfo;
				
				char szResBuf[256] = {0};
				char *pResBuf = NULL;
				int iRet = 0;
				
				url_decode(m_HttpParam);
			    url_decode(v_ContentBuf);

				if(ParseQueryAddressRecordInfo(m_HttpParam, szBlockAddress, szContractAddress, szStartTime, szEndTime, &iCurPage, &iNumsPerPage) < 0)
				{
					if(ParseQueryAddressRecordInfoFromJson(v_ContentBuf, szBlockAddress, szContractAddress, szStartTime, szEndTime, &iCurPage, &iNumsPerPage) < 0)
					{
						LOG("ParseQueryAddressRecordInfoFromJson failed, v_ContentBuf = %s,\nm_HttpParam = %s!\n", v_ContentBuf, m_HttpParam);
						sprintf(szResBuf, "{\"blockAddress\":null, \"contractAddress\":null,\"recordlist\":null, \"result\":-9}");
						MakeHttpErrResponse(szResBuf, 200);
						if(SendPushData(m_SendBuf, strlen(m_SendBuf)) < 0)		
						{			
							LOG("SendPushData error!\n");
							return -1;
						}
						return -1;
					}
				}
				
				LOG("Client AddressRecordInfo request, blockAddress = %s, contractAddress = %s, iCurPage = %d, iNumsPerPage = %d!\n", szBlockAddress, szContractAddress, iCurPage, iNumsPerPage);
				strBlockAddress = szBlockAddress;
				strContractAddress= szContractAddress;
				strStartTime= szStartTime;
				strEndTime= szEndTime;
				
				iRet = EChain_QueryAddressRecord(strBlockAddress, strContractAddress, strStartTime, strEndTime, iCurPage, iNumsPerPage, strTranxInfo);
				if(iRet <= 0)	
				{		
					LOG("EChain_QueryConditionTransactionRecord failed, v_ContentBuf is %s!\n", v_ContentBuf);
					sprintf(szResBuf, "{\"blockAddress\":null, \"contractAddress\":null, \"list\":null, \"result\":%d}", iRet);
					MakeHttpErrResponse(szResBuf, 200);
					if(SendPushData(m_SendBuf, strlen(m_SendBuf)) < 0)		
					{			
						LOG("SendPushData error!\n");
						return -1;
					}
					return -1;	
				}
				
				int iLen = strTranxInfo.size();
				pResBuf = (char *)malloc(sizeof(char)*(iLen + 1));	
				if(pResBuf == NULL)			
				{					
					LOG("malloc pResBuf failed!\n");	
					sprintf(szResBuf, "{\"blockAddress\":null, \"contractAddress\":null, \"recordlist\":null, \"result\":-9}");
					MakeHttpErrResponse(szResBuf, 200);
					if(SendPushData(m_SendBuf, strlen(m_SendBuf)) < 0)		
					{			
						LOG("SendPushData error!\n");
						return -1;
					}
					return -1;			
				}
				sprintf(pResBuf, "%s", strTranxInfo.c_str());
				//LOG("strTransferInfo = %s!\n", strTransferInfo.c_str());

				MakeHttpGetResponse(pResBuf);
			
				if(SendPushData(m_SendBuf, m_SendLen) < 0)		
				{			
					LOG("SendPushData error!\n");
					return -1;
				}
				if(pResBuf != NULL)	
				{		
					free(pResBuf); 		
					pResBuf = NULL;	
				}
				
				Stop();
				return 1;
			}
			break;	
		case	QUERYTRANSACTIONHASHRECORD:
			// http://domain:port/QueryTransactionHashRecord.do
			{
				char szBlockAddress[MAX_ADDRESS_LEN] = {0};
				char szTransactionHash[MAX_ADDRESS_LEN] = {0};
				int iEncryFlag = 0;
				char szEncryKey[MAX_ENCRYKEY_LEN] = {0};

				std::string strBlockAddress;
				std::string strDataTime;
				int iRet;
				int iLedgerSeq = 0;
				std::string strTransactionHash;
				std::string strTransactionInfo;
				char szResBuf[256] = {0};
				char *pResBuf = NULL;
				
				url_decode(m_HttpParam);	
				if(ParseQueryTransactionHashInfo(m_HttpParam, szBlockAddress, szTransactionHash) < 0)
				{
					if(ParseQueryTransactionHashInfoFromJson(v_ContentBuf, szBlockAddress, szTransactionHash) < 0)
					{
						LOG("ParseQueryTransactionHashInfoFromJson failed, v_ContentBuf = %s,\nm_HttpParam = %s!\n", v_ContentBuf, m_HttpParam);
						sprintf(szResBuf, "{\"contractAddress\":null,\"recordInfo\":null, \"ledgerSeq\":0, \"recordTime\":null, \"result\":-9}");
						MakeHttpErrResponse(szResBuf, 200);
						if(SendPushData(m_SendBuf, strlen(m_SendBuf)) < 0)		
						{			
							LOG("SendPushData error!\n");
						}
						return -1;
					}
				}
				
				LOG("QueryTransactionHashInfo request, szBlockAddress = %s, szTransactionHash = %s!\n", szBlockAddress, szTransactionHash);
				strTransactionHash = szTransactionHash;
				iRet = EChain_QueryTransactionHashRecord(strTransactionHash, strTransactionInfo, iLedgerSeq, strDataTime);
				if(iRet <= 0)	
				{		
					LOG("EChain_QueryTransactionHashRecord failed, v_ContentBuf is %s!\n", v_ContentBuf);
					sprintf(szResBuf, "{\"contractAddress\":null,\"recordInfo\":null, \"ledgerSeq\":0, \"recordTime\":null, \"result\":%d}", iRet);
					MakeHttpErrResponse(szResBuf, 200);
					if(SendPushData(m_SendBuf, strlen(m_SendBuf)) < 0)		
					{			
						LOG("SendPushData error!\n");
					}
					return -1;	
				}

				int iLen = strTransactionInfo.size() + 256;
				pResBuf = (char *)malloc(sizeof(char)*(iLen + 1));	
				if(pResBuf == NULL)			
				{					
					LOG("malloc pResBuf failed!\n");	
					sprintf(szResBuf, "{\"contractAddress\":null,\"recordInfo\":null, \"ledgerSeq\":0, \"recordTime\":null, \"result\":%d}", iRet);
					MakeHttpErrResponse(szResBuf, 200);
					if(SendPushData(m_SendBuf, strlen(m_SendBuf)) < 0)		
					{			
						LOG("SendPushData error!\n");
					}
					return -1;			
				}
				sprintf(pResBuf, "{\"contractAddress\":\"%s\",\"recordInfo\":%s, \"ledgerSeq\":%d, \"dataTime\":\"%s\", \"result\":%d}", 
					szBlockAddress, strTransactionInfo.c_str(), iLedgerSeq, strDataTime.c_str(), iRet);
				LOG("transactionInfo = %s!\n", pResBuf);

				MakeHttpGetResponse(pResBuf);
				
				if(SendPushData(m_SendBuf, m_SendLen) < 0)		
				{			
					LOG("SendPushData error!\n");
				}
			
				if(pResBuf != NULL)	
				{		
					free(pResBuf); 		
					pResBuf = NULL;	
				}
				//短连接，处理完即退出
				Stop();
				
				return 1;
			}
			break;
		case	QUERYBLOCKBROWSER:
			// 	http://domain:port/QueryBlockBrowser.do
			{
				std::string strBlockInfo;
				int iStartSeq = 0;
				int iCurPage = 0;
				int iNumsPerPage = 0;
				int iEncryFlag = 0;
				char szEncryKey[MAX_ENCRYKEY_LEN] = {0};
				char szResBuf[256] = {0};
				char *pResBuf = NULL;
				int iRet = 0;
				int iTime = getTimemisc();
				
				url_decode(m_HttpParam);

				if(ParseQueryBlockBrowserInfo(m_HttpParam, &iCurPage, &iNumsPerPage) < 0)
				{
					if(ParseQueryBlockBrowserInfoFromJson(v_ContentBuf, &iCurPage, &iNumsPerPage) < 0)
					{
						LOG("ParseQueryBlockBrowserInfo failed, v_ContentBuf = %s,\nm_HttpParam = %s!\n", v_ContentBuf, m_HttpParam);
						sprintf(szResBuf, "{\"curPage\":0,\"numsPerPage\":0,\"totalPage\":0,\"list\":null, \"result\":-9}");
						MakeHttpErrResponse(szResBuf, 200);
						if(SendPushData(m_SendBuf, strlen(m_SendBuf)) < 0)		
						{			
							LOG("SendPushData error!\n");
						}
						return -1;
					}
				}
				
				LOG("Client QueryBlockBrowser request, iCurPage = %d, iNumsPerPage = %d!\n", iCurPage, iNumsPerPage);
				
				iRet = EChain_QueryBlockBrowserInfo(iCurPage, iNumsPerPage, strBlockInfo);
				if(iRet<= 0)	
				{		
					LOG("EChain_QueryBlockInfo failed, v_ContentBuf is %s!\n", v_ContentBuf);
					sprintf(szResBuf, "{\"curPage\":%d,\"numsPerPage\":%d,\"totalNums\":0,\"totalPage\":0,\"list\":null, \"result\":%d}", iCurPage, iNumsPerPage, iRet);
					MakeHttpErrResponse(szResBuf, 200);
					if(SendPushData(m_SendBuf, strlen(m_SendBuf)) < 0)		
					{			
						LOG("SendPushData error!\n");
					}
					return -1;	
				}
				
				int iLen = strBlockInfo.size();
				pResBuf = (char *)malloc(sizeof(char)*(iLen + 1));	
				if(pResBuf == NULL)			
				{					
					LOG("malloc pResBuf failed!\n");	
					sprintf(szResBuf, "{\"curPage\":%d,\"numsPerPage\":%d,\"totalNums\":0,\"totalPage\":0,\"list\":null, \"result\":%d}", iCurPage, iNumsPerPage, iRet);
					MakeHttpErrResponse(szResBuf, 200);
					if(SendPushData(m_SendBuf, strlen(m_SendBuf)) < 0)		
					{			
						LOG("SendPushData error!\n");
					}
					return -1;			
				}
				sprintf(pResBuf, "%s", strBlockInfo.c_str());
			//	LOG("strBlockInfo = %s!\n", strBlockInfo.c_str());
				//HTTP回应PC客户端
				MakeHttpGetResponse(pResBuf);
			
				if(SendPushData(m_SendBuf, m_SendLen) < 0)		
				{			
					LOG("SendPushData error!\n");
					return -1;
				}
				if(pResBuf != NULL)	
				{		
					free(pResBuf); 		
					pResBuf = NULL;	
				}
				int iNewTime = getTimemisc();
				LOG("EChain_QueryBlockInfo, time Spend is %d ms!\n", iNewTime - iTime);
				//短连接，处理完即退出
				Stop();
				return 1;
			}
			break;
		case	QUERYBLOCKTRANSACTION:
			// http://domain:port/QueryBlockTranscation.do
			{    
                     
				int iBlockSeq = 0;
				int iRet;
				char szResBuf[256] = {0};
				char *pResBuf = NULL;
				std::string strTransactionInfo;
				

				url_decode(m_HttpParam);	

				if(ParseQueryBlockTransactionInfo(m_HttpParam, &iBlockSeq) < 0)
				{
					if(ParseQueryBlockTransactionInfoFromJson(v_ContentBuf, &iBlockSeq) < 0)
					{
						LOG("ParseQueryBlockTransactionInfoFromJson failed, v_ContentBuf = %s,\nm_HttpParam = %s!\n", v_ContentBuf, m_HttpParam);
						sprintf(szResBuf, "{\"ledgerSeq\":0,\"transactionInfo\":null, \"result\":-9}");
						MakeHttpErrResponse(szResBuf, 200);
						if(SendPushData(m_SendBuf, strlen(m_SendBuf)) < 0)		
						{			
							LOG("SendPushData error!\n");
						}
						return -1;
					}
				}	

				LOG("QueryBlockTransactionInfo request, iBlockSeq = %d!\n", iBlockSeq);
				
				iRet = EChain_QueryBlockTransaction(iBlockSeq, strTransactionInfo);
             //   LOG("Done\n");
			//	return -1;
				if(iRet <= 0)	
				{		
					LOG("EChain_QueryBlockTransaction failed, v_ContentBuf is %s!\n", v_ContentBuf);
					sprintf(szResBuf, "{\"ledgerSeq\":0,\"transactionInfo\":null, \"result\":%d}", iRet);
					MakeHttpErrResponse(szResBuf, 200);
					if(SendPushData(m_SendBuf, strlen(m_SendBuf)) < 0)		
					{			
						LOG("SendPushData error!\n");
					}
					return -1;	
				}
                 
				int iLen = strTransactionInfo.size() + 128;
				pResBuf = (char *)malloc(sizeof(char)*(iLen + 1));	
				if(pResBuf == NULL)			
				{					
					LOG("malloc pResBuf failed!\n");	
					sprintf(szResBuf, "{\"ledgerSeq\":0,\"transactionInfo\":null, \"result\":%d}", iRet);
					MakeHttpErrResponse(szResBuf, 200);
					if(SendPushData(m_SendBuf, strlen(m_SendBuf)) < 0)		
					{			
						LOG("SendPushData error!\n");
					}
					return -1;			
				}
                 

				sprintf(pResBuf, "{\"ledgerSeq\":%d,\"transactionInfo\":\"%s\", \"result\":%d}", //修改\"ledgerSeq\":\"%s\"    修改"transactionInfo\":%s
						iBlockSeq, strTransactionInfo.c_str(), iRet);
				LOG("transactionInfo = %s!\n", pResBuf);
                
				

				MakeHttpGetResponse(pResBuf);

				if(SendPushData(m_SendBuf, strlen(m_SendBuf)) < 0)		//修改m_SendLen为strlen(m_SendBuf)
				{			
					LOG("SendPushData error!\n");
				}
			    
				if(pResBuf != NULL)	
				{		
					free(pResBuf); 		
					pResBuf = NULL;	
				}
				//短连接，处理完即退出
				Stop();
				
				return 1;
			}
			break;
		case	QUERYCHAININFO:
			//http://domain:port/QueryChainInfo.do
			{
				std::string strChainInfo;
				char szResBuf[512] = {0};
				int iRet;
			
				url_decode(m_HttpParam);
			//	printf("a m_HttpParam = %s!\n", m_HttpParam);
							
				LOG("Client QueryChainInfo request!\n");

				iRet = EChain_QueryChainInfo(strChainInfo);
				if(iRet <= 0)	
				{		
					LOG("EChain_QueryChainInfo failed, v_ContentBuf is %s!\n", v_ContentBuf);
					sprintf(szResBuf, "{\"blockHeight\":0, \"blockNodes\":0,\"blockAccounts\":0,\"blockTransX\":0,\"blockAverTime\":0, \"blockTxPerDay\":0}");
					MakeHttpErrResponse(szResBuf, 200);
					if(SendPushData(m_SendBuf, strlen(m_SendBuf)) < 0)		
					{			
						LOG("SendPushData error!\n");
					}
					return -1;	
				}
				
				int iLen = strChainInfo.size();
				sprintf(szResBuf, "%s", strChainInfo.c_str());
				LOG("strChainInfo = %s!\n", strChainInfo.c_str());
				//HTTP回应PC客户端
				MakeHttpGetResponse(szResBuf);
			
				if(SendPushData(m_SendBuf, m_SendLen) < 0)		
				{			
					LOG("SendPushData error!\n");
					return -1;
				}
				
				//短连接，处理完即退出
				Stop();
				return 1;
			}
			break;
		case	QUERYNONCEINFO:
			//http://domain:port/QueryNonceInfo.do
			{
				char szBlockAddress[MAX_ADDRESS_LEN] = {0};
				std::string strBlockAddress;
				char szResBuf[512] = {0};
				int iRet;
			
				url_decode(m_HttpParam);
			//	printf("a m_HttpParam = %s!\n", m_HttpParam);
				
				if(ParseBlockAddressNonceInfo(m_HttpParam, szBlockAddress) < 0)
				{
					if(ParseBlockAddressNonceInfoFromJson(v_ContentBuf, szBlockAddress) < 0)
					{
						LOG("ParseBlockAddressNonceInfoFromJson failed, v_ContentBuf = %s,\nm_HttpParam = %s!\n", v_ContentBuf, m_HttpParam);
						sprintf(szResBuf, "{\"nonce\":-1}");
						MakeHttpErrResponse(szResBuf, 200);
						if(SendPushData(m_SendBuf, strlen(m_SendBuf)) < 0)		
						{			
							LOG("SendPushData error!\n");
							return -1;
						}
						return -1;
					}
				}
							
				LOG("Client QueryNonceInfo request, szBlockAddress = %s!\n", szBlockAddress);
				strBlockAddress = szBlockAddress;

				for(int i = 0; i < 10; i++)
				{
					iRet = EChain_GetBlockAddressNonceInfo(strBlockAddress);
					if(iRet < 0)	
					{		
						LOG("EChain_GetBlockAddressNonceInfo failed, v_ContentBuf is %s!\n", v_ContentBuf);
						sprintf(szResBuf, "{\"nonce\":-1}");
						MakeHttpErrResponse(szResBuf, 200);
						if(SendPushData(m_SendBuf, strlen(m_SendBuf)) < 0)		
						{			
							LOG("SendPushData error!\n");
						}
						return -1;	
					}
					LOG("EChain_GetBlockAddressNonceInfo, Nonce is %d!\n", iRet);
					usleep(1000*500);
				}
				sprintf(szResBuf, "{\"nonce\":%d}", iRet);
				//HTTP回应PC客户端
				MakeHttpGetResponse(szResBuf);
			
				if(SendPushData(m_SendBuf, m_SendLen) < 0)		
				{			
					LOG("SendPushData error!\n");
					return -1;
				}
				
				//短连接，处理完即退出
				Stop();
				return 1;
			}
			break;
		case ISSUEASSET:
			//http://103.118.48.100:8888/IssueAsset.do?assetAmount=1000000000000&assetCode=GToken
			{
				std::string strTxHash;
				std::string strBlockHash;
				std::string strClientID;
				std::string strIssuer;
				std::string strHexInfo;
				std::string strTransHash;
				int iAssetAmount = 0;
				
				char szAssetCode[64] = {0};
				char szResBuf[256] = {0};
				
				
			//	printf("b m_HttpParam = %s!\n", m_HttpParam);
				url_decode(m_HttpParam);
			//	printf("a m_HttpParam = %s!\n", m_HttpParam);
				if(ParseIssueAssetInfo(m_HttpParam, &iAssetAmount, szAssetCode) < 0)
				{
					if(ParseIssueAssetInfoFromJson(v_ContentBuf, &iAssetAmount, szAssetCode) < 0)
					{
						LOG("ParseIssueAssetInfo failed, v_ContentBuf = %s,\nm_HttpParam = %s!\n", v_ContentBuf, m_HttpParam);
						sprintf(szResBuf, "{\"result\":\"failed\"}");
						MakeHttpErrResponse(szResBuf, 200);
						if(SendPushData(m_SendBuf, strlen(m_SendBuf)) < 0)		
						{			
							LOG("SendPushData error!\n");
							return -1;
						}
						return -1;
					}
				}

				LOG("Client IssueAsset request, iAssetAmount = %d, szAssetCode = %s!\n", iAssetAmount,szAssetCode);

				strClientID = "00000000";
				strIssuer = "a001ddf0081d7af582b6e2d9e15439ef5125b843a821ba";
				strHexInfo = "";
				if(EChain_IssueAssets(strClientID, strIssuer, strHexInfo, szAssetCode, iAssetAmount, strTransHash) < 0)	
				{		
					LOG("EChain_IssueAssets failed!\n");
					sprintf(szResBuf, "{\"result\":\"failed\"}");
				//	MakeHttpErrResponse(szResBuf, 200);
					MakeHttpGetResponse(szResBuf);
					if(SendPushData(m_SendBuf, strlen(m_SendBuf)) < 0)		
					{			
						LOG("SendPushData error!\n");
						return -1;
					}
					return -1;	
				}
				
				sprintf(szResBuf, "{\"result\":\"success\"}");
				LOG("Client IssueAsset request, szResBuf = %s!\n", szResBuf);	
				//HTTP回应PC客户端
				MakeHttpGetResponse(szResBuf);
			
				if(SendPushData(m_SendBuf, m_SendLen) < 0)		
				{			
					LOG("SendPushData error!\n");
					return -1;
				}
				
				
				//短连接，处理完即退出
				Stop();
				return 1;
			}
			break;
		default:
			{
			}
			break;
	}
	return 1;
}

int CClientSession::ParseHttpReqParamInfo(char *v_ReqHead)
{
	int i;
	char *p1, *p2;
	char *pFind = NULL;
	char szGetLine[1024] = {0};
	
	if(v_ReqHead == NULL)
	{
		LOG("Invalid parameter in ParseHttpReqParamInfo!\n");
		return -1;
	}
	p1 = strstr(v_ReqHead, "GET ");
	if(p1 != NULL)
	{
		m_ReqMethod = HTTP_GET;
		p1+= strlen("GET ");
		p2 = strstr(p1,"\r\n");
		if(p2 != NULL)
		{
			int iLen = 0;
			if(p2-p1 > 1024)
			{
				iLen = 1023;
			}
			else
			{
				iLen = p2-p1;
			}
			memcpy(szGetLine, p1, iLen);
		}
		else
		{
			LOG("Invalid Request GET Head in ParseHttpReqParamInfo!\n");
			return -1;
		}
	}
	else if((p1 = strstr(v_ReqHead, "POST ")) != NULL)
	{	
		m_ReqMethod = HTTP_POST;
		p1+= strlen("POST ");
		p2 = strstr(p1,"\r\n");
		if(p2 != NULL)
		{
			int iLen = 0;
			if(p2-p1 > 1024)
			{
				iLen = 1023;
			}
			else
			{
				iLen = p2-p1;
			}
			memcpy(szGetLine, p1, iLen);
		}
		else
		{
			LOG("Invalid Request POST Head in ParseHttpReqParamInfo!\n");
			return -1;
		}
	}
	else
	{
		LOG("Invalid Request Head in ParseHttpReqParamInfo!\n");
		return -1;
	}

	int iArrLen = sizeof(szProtocalInfo)/sizeof(char *);
//	LOG("iArrLen = %d,szGetLine = %s!\n", iArrLen, szGetLine);
	for(i = 0; i < iArrLen; i++)
	{
		pFind = strstr(szGetLine, szProtocalInfo[i]);
		if(pFind != NULL)
		{
			m_ProtocalType = i;
		//	pFind += strlen(szProtocalInfo[i] ) + 1;
			printf("m_ProtocalType = %d\n", m_ProtocalType);
			break;
		}
	}
	if(i >= iArrLen)
	{
		m_ProtocalType = 0;
		LOG("Invalid Protocal type in ParseHttpReqParamInfo!\n");
		return -1;
	}
	LOG("%s!\n", szGetLine);
	
	strcpy(m_HttpParam, szGetLine);
//	printf("%s!\n", szGetLine);
	p1 = strstr(v_ReqHead, "User-Agent:");
	if(p1 == NULL)
	{
		LOG("Can't find User-Agent in http request head!\n");
		return -1;
	}
	else
	{
		p1+= strlen("User-Agent:");
	}

	p2 = strstr(p1, "\r\n");
	if(p2 == NULL)
	{
		LOG("Can't find User-Agent end  in http request head!\n");
		return -1;
	}
	memcpy(m_UserAgent, p1, p2 - p1);

	p1 = strstr(v_ReqHead, "Host:");
	if(p1 == NULL)
	{
		LOG("Can't find Host in http request head!\n");
		return -1;
	}
	else
	{
		p1+= strlen("Host:");
	}

	p2 = strstr(p1, "\r\n");
	if(p2 == NULL)
	{
		LOG("Can't find Host end  in http request head!\n");
		return -1;
	}
	memcpy(m_Hosts, p1, p2 - p1);
	
	p1 = strstr(v_ReqHead, "Content-Length:");
	if(p1 == NULL)
	{
		LOG("Can't find Content_Length in http request head!\n");
		m_ContentLen = 0;
		return 1;
	}
	p1+= strlen("Content-Length:");
	p2 = strstr(p1, "\r\n");
	if(p2 == NULL)
	{
		LOG("Can't find Content_Length end  in http request head!\n");
		return -1;
	}
	m_ContentLen = atoi(p1);
//	LOG("p1 = %s, m_ContentLen = %d!\n", p1, m_ContentLen);

	
//	LOG("m_UserAgent = %s!\n",m_UserAgent);
	return 1;
	
}

Int32 CClientSession::RecvHttpRequest(void) 
{	
	unsigned int recv_buf_size =0;	
	int size=0;	
	char *pFindStr = 0;	
	
	int i; 	
	char pReqHead[MAX_REQUEST_BUF_SIZE] = {0};	
	char *pReqBody = NULL;	
	
	recv_buf_size = MAX_RECVIVE_LENGTH - m_RecvSize;
	size = recv(m_SocketFD, m_RecvBuf + m_RecvSize, (Int32)recv_buf_size, 0);
//	LOG("recv size = %d, m_RecvSize = %d!\n", size, m_RecvSize);
	if(size <= 0)	
	{		
		if(errno == EINTR)		
		{			
			LOG("Client_SessionID %d recv fun interrupted by signal!\n", m_SessionID);		
			return 1;	
		}		
		else		
		{			
			LOG("Client_SessionID %d recv data from socket error in Client_SessionID, error = %d, exit info is %s!\n", 
					m_SessionID,errno, strerror(errno));			
			return -1;		
		}		
	}		
	m_RecvSize += size;	
	do{		
		if(m_RecvSize <= 0)		
		{			
			break;		
		}		
		m_RecvBuf[m_RecvSize] = 0;		
		if(m_UserAgent[0] == 0)		
		{			
			pFindStr = strstr(m_RecvBuf,  "\r\n\r\n");			
			if(pFindStr == NULL)	//没收全，下次收			
			{				
				break;			
			}			
			m_HeadLen = pFindStr - m_RecvBuf + 4;			
			memcpy(pReqHead, m_RecvBuf, m_HeadLen);
		//	LOG("pReqHead = %s\n", pReqHead);
		//	printf("pReqHead = %s\n", pReqHead);
			if(ParseHttpReqParamInfo(pReqHead) < 0)
			{
				LOG("ParseHttpReqParamInfo failed!\n");
				return -1;
			}
		//	LOG("m_RecvSize = %d, m_HeadLen = %d, m_ContentLen = %d!\n", m_RecvSize, m_HeadLen, m_ContentLen);
			
		}				
		if(m_RecvSize < m_HeadLen + m_ContentLen)		
		{			
			break;		
		}		
			
		if(m_ContentLen != 0) //带有消息体
		{
			pReqBody = (char *)malloc(sizeof(char) * (m_ContentLen + 1));		
			if(pReqBody == NULL)		
			{			
				LOG("malloc pReqBody failed!\n");			
				return -1;		
			}	
			memset(pReqBody, 0, m_ContentLen + 1);
			memcpy(pReqBody, m_RecvBuf + m_HeadLen, m_ContentLen);
			
		//	ReadXMLData(pReqBody);				
		}
		else
		{
			pReqBody = (char *)malloc(sizeof(char) * 1);		
			if(pReqBody == NULL)		
			{			
				LOG("malloc pReqBody failed!\n");			
				return -1;		
			}	
			memset(pReqBody, 0, 1);
					
		}
	//	LOG("pReqBody = %s\n", pReqBody);

		/*
		char szIPAddrInfo[64] = {0};
		GetRemoteAddrByString(szIPAddrInfo);
		
		if((strcmp(szIPAddrInfo, "127.0.0.1") != 0)&&
			(strncmp(szIPAddrInfo, "172.16.0.13", 9) != 0))
		{
			LOG("Permission denied, m_Hosts = %s, szIPAddrInfo = %s!\n", m_Hosts, szIPAddrInfo);
			if(pReqBody != NULL)
			{
				free(pReqBody);
				pReqBody = NULL;
			}
			return -1;
		}
		*/
		if(HttpDateProcess(pReqBody) < 0)
		{
		//	LOG("HttpDateProcess failed!\n");	
			if(pReqBody != NULL)
			{
				free(pReqBody);
				pReqBody = NULL;
			}
			return -1;
		}

		int iProcessDataLen = m_HeadLen + m_ContentLen;	
		m_RecvSize -= iProcessDataLen;	
	//	LOG("iProcessDataLen = %d, m_RecvSize = %d!\n", iProcessDataLen, m_RecvSize);	
	//	LOG("m_RecvBuf = %s\n", m_RecvBuf);		
		memmove(m_RecvBuf,m_RecvBuf+iProcessDataLen,m_RecvSize);		
		memset(m_ContentType, 0, MAX_CONTENT_TYPE_LEN);	
		if(pReqBody != NULL)
		{
			free(pReqBody);
			pReqBody = NULL;
		}
	}while(m_RecvSize > 0);	
	return 1;	
}


int CClientSession::Stop()
{
	m_iTaskFlag = 0;
	return 1;
}

int CClientSession::Run()
{
	Int32	i;
	Int32 nfds;    
	
	struct epoll_event ev, events[2];
        m_EpollFD = epoll_create(8192);
	
	ev.data.fd = m_SocketFD;
     	//设置要处理的事件类型
//     	ev.events= EPOLLIN | EPOLLET;
	ev.events= EPOLLIN;
     	//注册epoll事件
     	epoll_ctl(m_EpollFD, EPOLL_CTL_ADD, m_SocketFD, &ev);  
//	LOG("Start session %d!\n", m_SessionID);
	while(m_iTaskFlag)
	{
		nfds= epoll_wait(m_EpollFD, events, 2, 100);
		for(i = 0; i < nfds; i++)
        {
             	if((events[i].data.fd == m_SocketFD) && (events[i].events & EPOLLIN))
              	{
              	//	LOG("m_SocketFD %d Client_SessionID = %d detect the recv data!\n",m_SocketFD, m_SessionID);
           			if(RecvHttpRequest() < 0)
					{
					//	LOG("recv data error on RecvAns!\n");
						Stop();
						goto QUIT;
					}
             	}
		}
	}
QUIT:	
	
	CloseSock();
	g_ClientListMgr->DestroyClient(m_SessionID);
	return 1;
}


