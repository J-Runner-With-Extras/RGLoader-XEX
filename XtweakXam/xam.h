#pragma once

#include "stdafx.h"
#include <xbdm.h>
#include <stdio.h>
#include "utilities.h"

typedef DWORD (*XEKEYSUNOBFUSCATE)(DWORD r3, BYTE* r4, DWORD r5, BYTE* r6, DWORD r7);

typedef DWORD (*XEKEYSOBFUSCATE)(DWORD r3, BYTE* r4, DWORD r5, BYTE* r6, DWORD* r7);


#define XAM_XeKeysUnObfuscate 0x81CC11DC //for retail profile decryption

DWORD XeKeysUnObfuscateHook(DWORD r3, BYTE* r4, DWORD r5, BYTE* r6, DWORD r7);


BOOL Xam_Profile_Crypto_Hook_Setup(void);
