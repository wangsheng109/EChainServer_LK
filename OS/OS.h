#ifndef __OS_H__
#define __OS_H__

#include "OSHeader.h"


extern  int32  g_system_quit;
typedef int32(* Std_CallBack)(uint32 key,int32  event,void *hparam,void *lparam);
extern  Std_CallBack g_std_CallBack;

#include <map>
#include <vector>
#include <list>
using namespace std;

extern void * g_malloc(uint32 size);
extern void   g_free(void *pBuff) ;

extern int32  OS_InitSystem();
extern int32  OS_GetErrno();
extern void   OS_Sleep(int32 n);
extern int32  OS_CloseSocket(int32 fd);
extern int	  OS_strupr(char* str);
extern int	  OS_strlwr(char* str);
extern unsigned long OS_Gettickcount();


#endif////////__OSHEADER_H__
