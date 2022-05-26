
#ifdef WIN32
	#pragma comment(lib, "libmysql")
#endif

#include "MySQLExecAPI.h"
#include "MySQLDataBase.h"
#include <stdlib.h>
#include <stdarg.h>
#include "Global.h"

#ifdef WIN32
#include "stdafx.h"
#endif


int string_to_datetime(const char* string,int& year,int& month, int& day);

HANDLE  mysql_connect(Database_Param *p)
{
	CDatabase* pMain  = new CDatabase;
	if (0 == pMain )
	{
		LOG("pMain is NULL!\n");
		return  0;
	}
	
	if( pMain->ConnectDB(p) == 0 )
	{
		LOG("ConnectDB failed!\n");
		delete pMain;
		return 0;
	}
	
	HANDLE hObj = pMain;
	return hObj;
}

int mysql_disconnect(HANDLE& hObj)
{
	CDatabase* pMain = (CDatabase*)hObj;
	if (0 == pMain )
		return  -1;
	
	pMain->Disconnect();
	
	delete pMain;
	hObj = 0;
	return 1;
}

int  mysql_use_db(HANDLE hObj,char* DBName)
{
	CDatabase* pMain = (CDatabase*)hObj;
	if (0 == pMain )
		return  -1;
	return ( pMain->SelectDB(DBName) );
} 

int  mysql_open_tbl(HANDLE hObj,const char* sqlfmt, ...)
{
	char buff[4096] = {0};
	CDatabase* pMain = (CDatabase*)hObj;
	if (0 == pMain )
		return  -1;
	
	va_list vl;
	va_start(vl, sqlfmt);
	vsprintf((char *)buff, sqlfmt, vl);
	va_end(vl);
	
	return ( pMain->Open_Table(buff) );
}

int  mysql_exec_sql(HANDLE hObj,const char* sqlfmt, ...)
{
	char buff[4096] = {0};
	CDatabase* pMain = (CDatabase*)hObj;
	if (0 == pMain )
		return  -1;
	
	va_list vl;
	va_start(vl, sqlfmt);
	vsprintf((char *)buff, sqlfmt, vl);
	va_end(vl);
	
	return ( pMain->Exec(buff) );
}

unsigned int  mysql_get_cols(HANDLE hObj)
{
	CDatabase* pMain = (CDatabase*)hObj;
	if (0 == pMain )
		return  -1;
	return ( pMain->GetColumnNum() );
}

unsigned long  mysql_get_rows(HANDLE hObj)
{
	CDatabase* pMain = (CDatabase*)hObj;
	if (0 == pMain )
		return  -1;
	return ( pMain->GetRowNum() );
}
 
char*  mysql_get_col_name(HANDLE hObj,int idx)
{
	CDatabase* pMain = (CDatabase*)hObj;
	if (0 == pMain )
		return  0;
	return ( pMain->GetColumnName(idx) );
}

unsigned long  mysql_get_col_len(HANDLE hObj,int idx)
{
	CDatabase* pMain = (CDatabase*)hObj;
	if (0 == pMain )
		return  -1;
	return ( pMain->GetColumnLength(idx) );
}
 
char  mysql_get_char_id(HANDLE hObj,int idx)
{
	CDatabase* pMain = (CDatabase*)hObj;
	if (0 == pMain )
		return  0;
	return ( pMain->GetValue_Char(idx) );
}

char  mysql_get_char(HANDLE hObj,char* col_name)
{
	CDatabase* pMain = (CDatabase*)hObj;
	if (0 == pMain )
		return  0;
	return ( pMain->GetValue_Char(col_name) );
}

int  mysql_get_int_id(HANDLE hObj,int idx,int& value)
{
	CDatabase* pMain = (CDatabase*)hObj;
	if (0 == pMain )
		return  -1;
	return ( pMain->GetValue_Int(idx,value) );
}
 
int  mysql_get_int(HANDLE hObj,char* col_name,int& value)
{
	CDatabase* pMain = (CDatabase*)hObj;
	if (0 == pMain )
		return  -1;
	return ( pMain->GetValue_Int(col_name,value) );
}


int  mysql_get_long_id(HANDLE hObj,int idx,long& value)
{
	CDatabase* pMain = (CDatabase*)hObj;
	if (0 == pMain )
		return  -1;
	return ( pMain->GetValue_Long(idx,value) );
}
 
int  mysql_get_long(HANDLE hObj,char* col_name,long& value)
{
	CDatabase* pMain = (CDatabase*)hObj;
	if (0 == pMain )
		return  -1;
	return ( pMain->GetValue_Long(col_name,value) );
}

int  mysql_get_float_id(HANDLE hObj,int idx,float& value)
{
	CDatabase* pMain = (CDatabase*)hObj;
	if (0 == pMain )
		return  -1;
	return ( pMain->GetValue_Float(idx,value) );
}
 
int  mysql_get_float(HANDLE hObj,char* col_name,float& value)
{
	CDatabase* pMain = (CDatabase*)hObj;
	if (0 == pMain )
		return  -1;
	return ( pMain->GetValue_Float(col_name,value) );
}

int  mysql_get_double_id(HANDLE hObj,int idx,double& value)
{
	CDatabase* pMain = (CDatabase*)hObj;
	if (0 == pMain )
		return  -1;
	return ( pMain->GetValue_Double(idx,value) );
}
 
int  mysql_get_double(HANDLE hObj,char* col_name,double& value)
{
	CDatabase* pMain = (CDatabase*)hObj;
	if (0 == pMain )
		return  -1;
	return ( pMain->GetValue_Double(col_name,value) );
}

char*  mysql_get_string_id(HANDLE hObj,int idx)
{
	CDatabase* pMain = (CDatabase*)hObj;
	if (0 == pMain )
	return  0;
	return ( pMain->GetValue_String(idx) );
}
 
char*  mysql_get_string(HANDLE hObj,char* col_name)
{
	CDatabase* pMain = (CDatabase*)hObj;
	if (0 == pMain )
		return  0;
	return ( pMain->GetValue_String(col_name) );
}

int  mysql_next(HANDLE hObj)
{
	CDatabase* pMain = (CDatabase*)hObj;
	if (0 == pMain )
		return  0;
	return ( pMain->MoveToNextRecord() );
}

int  mysql_close_db(HANDLE hObj)
{
	CDatabase* pMain = (CDatabase*)hObj;
	if (0 == pMain )
		return  -1;
	pMain->FreeRecord();
	return 1;
}
 
int  mysql_iseof(HANDLE hObj)
{
	CDatabase* pMain = (CDatabase*)hObj;
	if (0 == pMain )
		return  -1;
	return ( pMain->IsEnd() );
}

int	mysql_get_datetime_id(HANDLE hObj,int idx,int& year,int& month, int& day)
{

	CDatabase* pMain = (CDatabase*)hObj;
	if (0 == pMain )
		return  0;
	char *p =  pMain->GetValue_String(idx);
	string_to_datetime(p,year,month, day);
	return 1;
}

int	mysql_get_datetme(HANDLE hObj,char* col_name, int& year,int& month, int& day)
{
	CDatabase* pMain = (CDatabase*)hObj;
	if (0 == pMain )
		return  0;
	char *p =  pMain->GetValue_String(col_name);
	string_to_datetime(p,year,month, day);
	return 1;
}

int string_to_datetime(const char* string,int& year,int& month, int& day)
{
//	char *endptr;
	char date_buf[32]= {0},time_buf[32] = {0};
	int my_year,my_mon,my_date;
	int hour,min,sec;
	sscanf(string,"%d-%d-%d %d:%d:%d",&my_year,&my_mon,&my_date,&hour,&min,&sec);
	year = my_year; 
	month = my_mon;
	day = my_date;
//	sprintf(date_buf,"%d%02d%02d",my_year,my_mon,my_date);
//	sprintf(time_buf,"%d%02d%02d",hour,min,sec);
//	date = strtol(date_buf,&endptr,10);
//	time = strtol(time_buf,&endptr,10);
	return 1;
}

