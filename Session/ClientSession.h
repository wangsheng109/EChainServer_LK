#ifndef __CLIENTSESSION_HEADER_FILE_2348972348__
#define __CLIENTSESSION_HEADER_FILE_2348972348__
#ifdef __Win32__
#pragma warning(disable:4786)
#endif

#include "OSType.h"
#include "OSTask.h"
#include "OSHeader.h"
#include "Global.h"
#include "DataQueue.h"
#include "TCPSocket.h"
//#include "XMLDoc.h"
//#include "MySQLExecAPI.h"

#define MAX_USERAGENT_LEN		256
#define MAX_HOSTINFO_LEN		64
#define MAX_CONTENT_TYPE_LEN 1024
#define MAX_REQUEST_BUF_SIZE  2048

class CClientSession : public OSTask
{
public:
	CClientSession(UInt32 v_SessionID);
	virtual ~CClientSession();

	bool Initialize(Int32 v_SocketFD);

public:
	UInt32				m_SessionID;
	Int32				m_SocketFD;
	Int32 				m_EpollFD;
	Int32				m_iTaskFlag;
	
	Int8*				m_RecvBuf;
	UInt32				m_RecvSize;

	Int8 					*m_SendBuf;
	int					m_SendLen;
	Int8					m_HttpParam[1024];
	
	//Database_Param *m_pDataBase;
	//HANDLE m_DBClass;
	
	//Database_Param *m_pUserDB;
	//HANDLE m_UserDBClass;

	int					m_ReqMethod;
	int					m_ProtocalType;

	char					m_UserAgent[MAX_USERAGENT_LEN];
	char					m_Hosts[MAX_HOSTINFO_LEN];
	char 				m_ContentType[MAX_CONTENT_TYPE_LEN];		
	
	int 					m_ContentLen;
	int 					m_HeadLen; 	
	
	//XMLDoc *m_pXmlDoc;

	int 		Stop();
	int		Run();
	void CloseSock(void);
		
protected:
	void MakeHttpErrResponse(char *v_responseBuf, int v_errNo);
	void MakeHttpGetResponse(char *v_responseBuf);
	
	
	int ParseUserRegisterInfo(char *v_ParamStr, char *v_UserID, char *v_UserInfo, int *v_UserType);
	int ParseUserRegisterInfoFromJson(char *v_ParamStr, char *v_UserID, char *v_UserInfo, int *v_UserType);
	int ParseUserCertificationInfo(char *v_ParamStr, char *v_BlockAddress, char *v_UserName, char *v_UserInfo);
	int ParseUserCertificationInfoFromJson(char *v_ParamStr, char *v_BlockAddress, char *v_UserName, char *v_UserInfo);
	int ParseCreateContractAddressInfo(char *v_ParamStr, char *v_UserID, char *v_ClassID);
	int ParseCreateContractAddressInfoFromJson(char *v_ParamStr, char *v_UserID, char *v_ClassID);
	int ParseDataStorageInfo(char *v_ParamStr, char *v_ContractAddress, int *v_BusinessType, char *v_DataHash, char *v_DataPath, char *v_DescInfo);
	int ParseDataStorageInfoFromJson(char *v_ParamStr, char *v_ContractAddress, int *v_BusinessType, char *v_DataHash, char *v_DataPath, char *v_DescInfo);
	int ParseDataUpdateInfo(char *v_ParamStr, char *v_contractAddress, int *v_UpdateType, int *v_BusinessType, char *v_TranxHash, char *v_DataHash, char *v_DataPath, char *v_DescInfo);
	int ParseDataUpdateInfoFromJson(char *v_ParamStr, char *v_contractAddress, int *v_UpdateType, int *v_BusinessType, char *v_TranxHash, char *v_DataHash, char *v_DataPath, char *v_DescInfo);
	int ParseContractAddressDeleteInfo(char *v_ParamStr, char *v_BlockAddress, char *v_ContractAddress, char *v_DescInfo);
	int ParseContractAddressDeleteInfoFromJson(char *v_ParamStr, char *v_BlockAddress, char *v_ContractAddress, char *v_DescInfo);
	int ParseIntegrityVerificationInfo(char *v_ParamStr, char *v_BlockAddress, char *v_ContractAddress, int *v_BusinessType, char *v_TranxHash, char *v_DataHash);
	int ParseIntegrityVerificationInfoFromJson(char *v_ParamStr, char *v_BlockAddress, char *v_ContractAddress, int *v_BusinessType, char *v_TranxHash, char *v_DataHash);
	int ParseDataSharedContentInfo(char *v_ParamStr, char *v_BlockAddress, char *v_ContractAddress, int *v_BusinessType, char *v_TranxHash, char *v_DataHash);
	int ParseDataSharedContentInfoFromJson(char *v_ParamStr, char *v_BlockAddress, char *v_ContractAddress, int *v_BusinessType, char *v_TranxHash, char *v_DataHash);
	int ParseDataSharedResultInfo(char *v_ParamStr, char *v_BlockAddress, char *v_ContractAddress, int *v_BusinessType, char *v_TranxHash, char *v_DataHash, char *v_DescInfo);
	int ParseDataSharedResultInfoFromJson(char *v_ParamStr, char *v_BlockAddress, char *v_ContractAddress, int *v_BusinessType, char *v_TranxHash, char *v_DataHash, char *v_DescInfo);
	int ParseQueryBlockBrowserInfo(char *v_ParamStr, int *v_CurPage, int *v_NumsPerPage);
	int ParseQueryBlockBrowserInfoFromJson(char *v_ParamStr, int *v_CurPage, int *v_NumsPerPage);
	int ParseQueryAddressRecordInfo(char *v_ParamStr, char *v_BlockAddress, char *v_ContractAddress, char *v_StartTime, char *v_EndTime, int *v_CurPage, int *v_NumsPerPage);
	int ParseQueryAddressRecordInfoFromJson(char *v_ParamStr, char *v_BlockAddress, char *v_ContractAddress, char *v_StartTime, char *v_EndTime, int *v_CurPage, int *v_NumsPerPage);
	int ParseQueryTransactionHashInfo(char *v_ParamStr, char *v_BlockAddress, char *v_TransactionHash);
	int ParseQueryTransactionHashInfoFromJson(char *v_ParamStr, char *v_BlockAddress, char *v_TransactionHash);
	int ParseQueryBlockTransactionInfo(char *v_ParamStr, int *v_BlockSeq);
	int ParseQueryBlockTransactionInfoFromJson(char *v_ParamStr, int *v_BlockSeq);
	int ParseBlockAddressNonceInfo(char *v_ParamStr, char *v_BlockAddress);
	int ParseBlockAddressNonceInfoFromJson(char *v_ParamStr, char *v_BlockAddress);
	int ParseIssueAssetInfo(char *v_ParamStr, int *v_AssetAmount, char *v_AssetCode);
	int ParseIssueAssetInfoFromJson(char *v_ParamStr, int *v_AssetAmount, char *v_AssetCode);
	
	
	int HttpDateProcess(char *v_ContentBuf);
	int ParseHttpReqParamInfo(char *v_ReqHead);
	Int32 SetSendTimeOut(Int32 Seconds);
	Int32 SendPushData(Int8 *v_Senddata, Int32 v_Len);
	Int32 RecvHttpRequest(void) ;
	void MakeMobileLoginResponse();


	int GetRemoteAddrByString(char *v_IPAddrInfo);
	int GetCurTimeByString(char *v_CurTimeInfo);
	int GetCurTimeByNoFormatString(char *v_CurTimeInfo);
};

#endif



