#ifndef GLOBAL_H
#define	GLOBAL_H

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include "OSType.h"
#include <time.h>
#include "OSMutex.h"
#include "json_object.h"

#define HANDLE void*

#define VERSION	"XChainServerV1.0"

extern void BLOG(const Int8 *fmt, ...);

extern void version();

extern int CheckLogFileName();

//#define LOG BLOG 

#define		DEBUG_VERSION
//#define	RELEASE_VERSION

#if defined	DEBUG_VERSION
	#define LOG 	BLOG
#elif defined	RELEASE_VERSION
	#define	LOG
#else
	#define	LOG 	
#endif


#define		TRUE	1
#define		FALSE	0

//HTTP 请求方法
#define		HTTP_GET		1
#define		HTTP_POST		2

//请求协议类型
enum PROTOCALTYPE
{
		INITHTTPTYPE				=		0,
		USERREGISTER				=		1,	 //用户注册
		USERCERTIFICATION 			=		2, 	 //用户实名认证
		CREATECONTRACTADDRESS		=		3,   //创建合约账号
		BUSINESSDATASTORAGE			=		4,	 //用户数据上链存证
		BUSINESSDATAUPDATE	    	=		5,	 //用户数据修正存证
		CONTRACTADDRESSDELETE		=		6,   //合约账号数据清除存证
		INTEGRITYVERIFICATION		=		7,   //用户数据身份和完整性验证
		DATASHAREDCONTENT			=		8,   //基于内容的用户数据共享
		DATASHAREDRESULT			=		9,	 //基于结果的用户数据共享
		QUERYADDRESSRECORD			=		10,	 //数据存证全记录查询
		QUERYTRANSACTIONHASHRECORD	=		11,	 //基于交易Hash的数据存证记录查询
		QUERYBLOCKBROWSER			=		12,	 //链浏览器信息查询
		QUERYBLOCKTRANSACTION		=		13,	 //区块交易信息查询
		QUERYCHAININFO				=		14,	 //联盟链交易统计信息查询
		QUERYNONCEINFO				=		15,  //查询具体帐号的Nonce信息
		ISSUEASSET					=		16	 //发行资产
};


#define   MAX_DEVID_LEN  		64
#define   MAX_DEVIP_LEN  		16


#define   MAX_ENCRYKEY_LEN  	64
#define   MAX_ADDRESS_LEN  		128
#define   MAX_FILEPATH_LEN  	1024
#define   MAX_USERID_LEN  		32
#define   MAX_USERNAME_LEN  	256
#define   MAX_USERINFO_LEN  	1024*2
#define   MAX_JSONINFO_LEN  	1024*6
#define	MAX_RECVIVE_LENGTH	(1024 * 80)
#define	MAX_SEND_LENGTH	(1024 * 100)



extern int GetLocalIP(char *v_LocalIP);

#endif

