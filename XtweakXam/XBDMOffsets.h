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

// Offsets for adding additional drives to xbox neighborhood in 2.0.17489.0
XBDMOffsets xbdm_17489 = {
0x91F329DC, //check
0x91F96F68, //mass0
0x91F96F90,
0x91F00980,
0x91F96F94, //mass1
0x91F96FBC,
0x91F00990,
0x91F96FC0, //mass2
0x91F96FE8,
0x91F009A0,
0x91F96EE4, //flash
(0x91F96EE4 + 0x28),
0x91F00970,
0x91F97044, //hddsysext
(0x91F97044 + 0x28) ,
0x91F00A08,
0x91F970C8, //intusbsysext
(0x91F970C8 + 0x28) ,
0x91F00A9C,
0x91F97070,
(0x91F97070 + 0x28) ,
0x91F00A30
};