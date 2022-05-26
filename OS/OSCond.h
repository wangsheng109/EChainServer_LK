/*
    File:       OSCond.h

    Contains:   A simple condition variable abstraction   

*/

#ifndef _OSCOND_H_
#define _OSCOND_H_

#ifndef WIN32
    #if __PTHREADS_MUTEXES__
        #include <pthread.h>
    #else
        //#include "mycondition.h"
    #endif
#endif


#include "OS.h"
#include "OSMutex.h"


class OSCond 
{
    public:

        OSCond();
        virtual ~OSCond();
        
        inline void     Signal();
        inline void     Wait(OSMutex* inMutex, int32 inTimeoutInMilSecs = 0);
        inline void     Broadcast();

    private:
#ifdef WIN32
        HANDLE              fCondition;
        uint32              fWaitCount;
#else
        pthread_cond_t      fCondition;
        void                TimedWait(OSMutex* inMutex, int32 inTimeoutInMilSecs);
#endif
};

/*
 * 函数介绍：等待
 * 输入参数：inMutex - 互斥量
 *           inTimeoutInMilSecs -  0 :阻塞，直到有信号
 *                               非0:阻塞，直到有信号或inTimeoutInMilSecs微秒后超时
 *           使用前后应配合OSMutex::Lock，OSMutex::Unlock。
 * 输出参数：无
 * 返回值  ：无
 */
inline void OSCond::Wait(OSMutex* inMutex, int32 inTimeoutInMilSecs)
{ 
#ifdef WIN32
    DWORD theTimeout = INFINITE;
    if (inTimeoutInMilSecs > 0)
        theTimeout = inTimeoutInMilSecs;
	
    fWaitCount++;
    inMutex->Unlock();
    DWORD theErr = ::WaitForSingleObject(fCondition, theTimeout);
//    Assert((theErr == WAIT_OBJECT_0) || (theErr == WAIT_TIMEOUT));
    inMutex->Lock();
	fWaitCount--;
	
#elif WIN32
    this->TimedWait(inMutex, inTimeoutInMilSecs);
#else
	/*
    Assert(fCondition != NULL);
    mycondition_wait(fCondition, inMutex->fMutex, inTimeoutInMilSecs);
	*/
#endif
}


/*
 * 函数介绍：发信号。
 *           使用前后应配合OSMutex::Lock，OSMutex::Unlock。
 * 输入参数：无
 * 输出参数：无
 * 返回值  ：无
 */
inline void OSCond::Signal()
{
#ifdef WIN32
    bool theErr = ::SetEvent(fCondition);
//    Assert(theErr == TRUE);
#else
    pthread_cond_signal(&fCondition);
//#else
	/*
    Assert(fCondition != NULL);
    mycondition_signal(fCondition);
	*/
#endif
}

/*
 * 函数介绍：发信号给阻塞在同一个OSCond的线程。
 *           使用前后应配合OSMutex::Lock，OSMutex::Unlock。
 * 输入参数：无
 * 输出参数：无
 * 返回值  ：无
 */
inline void OSCond::Broadcast()
{
#ifdef WIN32
    //
    // There doesn't seem like any more elegant way to
    // implement Broadcast using events in Win32.
    // This will work, it may generate spurious wakeups,
    // but condition variables are allowed to generate
    // spurious wakeups
    uint32 waitCount = fWaitCount;
    for (uint32 x = 0; x < waitCount; x++)
    {
        int32 theErr = ::SetEvent(fCondition);
//        Assert(theErr == TRUE);
    }
#elif __PTHREADS_MUTEXES__
    pthread_cond_broadcast(&fCondition);
#else
	/*
    Assert(fCondition != NULL);
    mycondition_broadcast(fCondition);
	*/
#endif
}

#endif //_OSCOND_H_
