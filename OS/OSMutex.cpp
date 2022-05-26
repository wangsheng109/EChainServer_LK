/*
    File:       OSMutex.cpp

    Contains:   Platform - independent mutex header. The implementation of this object
                is platform - specific. Each platform must define an independent
                QTSSMutex.h & QTSSMutex.cpp file.
                
                This file is for Mac OS X Server only

    

*/

#include "OSMutex.h"
#include <stdlib.h>
#include <string.h>


#ifdef WIN32
#define __PTHREADS_MUTEXES__  0
#else
#define __PTHREADS_MUTEXES__ 1
#endif



OSMutex::OSMutex()
{
#ifdef WIN32
	::InitializeCriticalSection(&fMutex);
#else
	pthread_mutexattr_init(&fMutexttr);
	pthread_mutexattr_settype(&fMutexttr,PTHREAD_MUTEX_RECURSIVE);										 
	pthread_mutex_init(&fMutex,&fMutexttr);
#endif
	
}

OSMutex::~OSMutex()
{
#ifdef WIN32
    ::DeleteCriticalSection(&fMutex);
#else
    pthread_mutex_destroy(&fMutex);
	pthread_mutexattr_destroy(&fMutexttr);
#endif
	
}


void        OSMutex::Lock()
{
#ifdef WIN32
    ::EnterCriticalSection(&fMutex);
#else
    (void)pthread_mutex_lock(&fMutex);
#endif
}

void        OSMutex::Unlock()
{
       
#ifdef WIN32
        ::LeaveCriticalSection(&fMutex);
#else
        pthread_mutex_unlock(&fMutex);
#endif

}



