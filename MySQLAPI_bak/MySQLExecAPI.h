#ifndef __MYSQL_EXEC_API_H__
#define __MYSQL_EXEC_API_H__

#ifdef WIN32
	#include <windows.h>
#else
	#define HANDLE void*
	#define BOOL   int	
#endif

typedef struct tagDatabase_Param//数据库参数
{
	char host[128];				//主机名
	char user[128];				//用户名
	char password[128];			//密码
	char db_name[128];			//数据库名
	char table_name[128];		//表名
	unsigned int port;			//端口，一般为0
	const char *unix_socket;	 //套接字，一般为NULL
	unsigned int client_flag;	 //一般为0
	char filed_file_path[128];
	char filed_file_time[128];
}Database_Param,*LPDatabase_Param;




/*************************************************/
HANDLE			mysql_connect(Database_Param *p);			//建立跟mysql 服务器的连接
int				mysql_disconnect(HANDLE &hObj);				//断开跟mysql 服务器的连接

int			mysql_use_db(HANDLE hObj,char* dbname);	//选择mysql 数据库

//mysql_open_tbl(m_db,"select * from mp4test;");			//打开数据库中的一个表
int				mysql_open_tbl(HANDLE hObj,const char* sqlfmt, ...);
int				mysql_close_db(HANDLE hObj);	//关闭数据库中的一个表
int				mysql_next(HANDLE hObj);					//取得下一条记录
int			mysql_iseof(HANDLE hObj);					//是否到了记录的结尾

//mysql_exec_sql(m_db,"sql 语句");							//执行sql 语句
int				mysql_exec_sql(HANDLE hObj,const char* sqlfmt, ...);

//**************************************
unsigned int	mysql_get_cols(HANDLE hObj);				//取表的列数
unsigned long	mysql_get_rows(HANDLE hObj);				//取表的行数
char*			mysql_get_col_name(HANDLE hObj,int idx);	//取列的名字
unsigned long	mysql_get_col_len(HANDLE hObj,int idx);		//取列的长度

//根据id或列名返回日期或时间			date:20071118		time:143026
int				mysql_get_datetime_id(HANDLE hObj,int idx,int& year,int& month, int& day);
//int				mysql_get_datetme(HANDLE hObj,char* col_name,long& date,long& time);
int				mysql_get_datetme(HANDLE hObj,char* col_name, int& year,int& month, int& day);

char			mysql_get_char_id(HANDLE hObj,int idx);		//根据列id取一个字符
char			mysql_get_char(HANDLE hObj,char* col_name);	//根据列名取一个字符

int			mysql_get_int_id(HANDLE hObj,int idx,int& value);	//根据列id取一个整数
int			mysql_get_int(HANDLE hObj,char* col_name,int& value);		//根据列名取一个整数

int			mysql_get_long_id(HANDLE hObj,int idx,long& value);
int			mysql_get_long(HANDLE hObj,char* col_name,long& value);

int			mysql_get_float_id(HANDLE hObj,int idx,float& value);
int			mysql_get_float(HANDLE hObj,char* col_name,float& value);

int			mysql_get_double_id(HANDLE hObj,int idx,double& value);
int			mysql_get_double(HANDLE hObj,char* col_name,double& value);

char*			mysql_get_string_id(HANDLE hObj,int idx);						//根据列id取回字符串
char*			mysql_get_string(HANDLE hObj,char* col_name);					//根据列名取回字符串

#endif  //__MYSQL_EXEC_API_H__

