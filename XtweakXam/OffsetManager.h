#pragma once

#include "stdafx.h"

struct XBDMOffsets
{
DWORD map_internal_check;  //nop check drivemap internal=1 
DWORD mass0_obname_ptr; //ptr of device name
DWORD mass0_enable;
DWORD mass0_obname; //device name obj

DWORD mass1_obname_ptr; //ptr of device name
DWORD mass1_enable;
DWORD mass1_obname; //device name obj

DWORD mass2_obname_ptr; //ptr of device name
DWORD mass2_enable;
DWORD mass2_obname; //device name obj

DWORD flash_obname_ptr; //ptr of device name
DWORD flash_enable;
DWORD flash_obname; //device name obj

DWORD hddsysext_obname_ptr; //ptr of device name
DWORD hddsysext_enable;
DWORD hddsysext_obname; //device name obj

DWORD intusbsysext_obname_ptr; //ptr of device name
DWORD intusbsysext_enable;
DWORD intusbsysext_obname; //device name obj

DWORD hddsysaux_obname_ptr; //ptr of device name
DWORD hddsysaux_enable;
DWORD hddsysaux_obname; //device name obj

};

struct SIGNINOffsets
{
	DWORD NoSignNotice;
};

struct XSHELLOffsets
{
	DWORD loc1, loc2, loc3, loc4;
};

class OffsetManager
{
public:
	OffsetManager();
	XBDMOffsets* getXbdmOffsets();
	SIGNINOffsets* getSigninOffsets();
	XSHELLOffsets* getXshellOffsets();
private:
	short getKernelVersion();
	short _kernel;
};