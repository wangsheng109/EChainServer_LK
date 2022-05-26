/*
File:       OSMutex.h

 Contains:   Platform - independent mutex header. The implementation of this object
 is platform - specific. Each platform must define an independent
 OSMutex.h & OSMutex.cpp file.
 
  This file is for Mac OS X Server only	
*/

#ifndef _OSMUTEX_H_
#define _OSMUTEX_H_

#include "OS.h"

class OSMutex
{
public:
	
	OSMutex();
	virtual ~OSMutex();
	
	void Lock();
	void Unlock();
	
	// Returns true on successful grab of the lock, false on failure
	
private:
	
#ifdef WIN32
	CRITICAL_SECTION fMutex;                
#else
	pthread_mutex_t fMutex;
	pthread_mutexattr_t		fMutexttr;
#endif
	
};

class   OSMutexLocker
{
public:
	
	OSMutexLocker(OSMutex *inMutexP) : fMutex(inMutexP) { if (fMutex != NULL) fMutex->Lock(); }
	virtual ~OSMutexLocker() {  if (fMutex != NULL) fMutex->Unlock(); }
	
	void Lock()         { if (fMutex != NULL) fMutex->Lock(); }
	void Unlock()       { if (fMutex != NULL) fMutex->Unlock(); }
	
private:
	
	OSMutex*    fMutex;
};


#endif //_OSMUTEX_H_

