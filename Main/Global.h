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

//HTTP ���󷽷�
#define		HTTP_GET		1
#define		HTTP_POST		2

//����Э������
enum PROTOCALTYPE
{
		INITHTTPTYPE				=		0,
		USERREGISTER				=		1,	 //�û�ע��
		USERCERTIFICATION 			=		2, 	 //�û�ʵ����֤
		CREATECONTRACTADDRESS		=		3,   //������Լ�˺�
		BUSINESSDATASTORAGE			=		4,	 //�û�����������֤
		BUSINESSDATAUPDATE	    	=		5,	 //�û�����������֤
		CONTRACTADDRESSDELETE		=		6,   //��Լ�˺����������֤
		INTEGRITYVERIFICATION		=		7,   //�û�������ݺ���������֤
		DATASHAREDCONTENT			=		8,   //�������ݵ��û����ݹ���
		DATASHAREDRESULT			=		9,	 //���ڽ�����û����ݹ���
		QUERYADDRESSRECORD			=		10,	 //���ݴ�֤ȫ��¼��ѯ
		QUERYTRANSACTIONHASHRECORD	=		11,	 //���ڽ���Hash�����ݴ�֤��¼��ѯ
		QUERYBLOCKBROWSER			=		12,	 //���������Ϣ��ѯ
		QUERYBLOCKTRANSACTION		=		13,	 //���齻����Ϣ��ѯ
		QUERYCHAININFO				=		14,	 //����������ͳ����Ϣ��ѯ
		QUERYNONCEINFO				=		15,  //��ѯ�����ʺŵ�Nonce��Ϣ
		ISSUEASSET					=		16	 //�����ʲ�
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

