
#pragma once

#ifndef HUD_H
#define HUD_H

#include "stdafx.h"
#include <stdio.h>
#include "utilities.h"

#define HUD_FamilySettings_String  "Launch XShell"
#define HUD_FamilySettings_Len     15

int patch_HUD_ReturnToXshell(void);

//static HUD_FILLLAUNCHDATA HUD_FillLaunchData = (HUD_FILLLAUNCHDATA)HUD_FillLaunchData_Func;*/
#define FamilySettings_Str1 0x119B8
#define FamilySettings_Str2 0x11F02

typedef DWORD (*HUD_FILLLAUNCHDATA)(DWORD* XDashLaunchData ,DWORD r4, DWORD selection);
typedef DWORD (*HUD_BOOTTODASHHELPER)(DWORD* _XUIOBJ, _XDASHLAUNCHDATA* LaunchData , DWORD* cstr, DWORD* r6, DWORD* r7);
DWORD HUD_BootToDashHelper_Hook(DWORD* _XUIOBJ, _XDASHLAUNCHDATA* LaunchData , DWORD* cstr, DWORD* r6, DWORD* r7);

static BOOL testhud=false;

#endif