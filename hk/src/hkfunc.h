#pragma once

#include "define.h"

extern TAllocateVirtualMemory hkAllocateVirtualMemory;
extern TCreateProcess hkCreateProcess;
extern TCreateSection hkCreateSection;
extern TCreateUserThread hkCreateUserThread;
extern TGetContextThread hkGetContextThread;
extern TMapViewOfSection hkMapViewOfSection;
extern TQueryInformationProcess hkQueryInformationProcess;
extern TResumeProcess hkResumeProcess;
extern TSetContextThread hkSetContextThread;
extern TSuspendProcess hkSuspendProcess;
extern TUnmapViewOfSection hkUnmapViewOfSection;
extern TWriteVirtualMemory hkWriteVirtualMemory;

void initializeWinAPIFunctions();