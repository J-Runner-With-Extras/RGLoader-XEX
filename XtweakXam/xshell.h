#pragma once

#ifndef XSHELL_H
#define XSHELL_H

#include "stdafx.h"
#include <xbdm.h>
#include <stdio.h>
#include "utilities.h"
#include "OffsetManager.h"
#include <string>

static char* startXex;
static char* startPath;

// xshell patch offsets for 2.0.17489.0
#define loc1 0x9203EC14
#define loc2 0x9204A564
#define loc3 0x9204D734
#define loc4 0x92065454

int patch_Xshell_start_path(std::string newpath);

#endif