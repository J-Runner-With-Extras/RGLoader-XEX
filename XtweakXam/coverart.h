#pragma once

#include "stdafx.h"
#include <stdio.h>
#include "utilities.h"

// Covers in this folder (<titleid>.jpg or .png, 8 hex digits) are shown on library tiles
#define COVERART_DEFAULT_FOLDER	"Hdd:\\Filesystems\\CoverArt"

// Titles without a local cover can also load art from an images root (off unless
// Cover_Art_Root is set): <root>/66acd000-77fe-1000-9115-d802<titleid>/1033/boxartlg.jpg

// dash.xex resource holding the Marketplace.GameLibrary Lua chunk
#define COVERART_DASH_SECTION	"contapp"

BOOL CoverArt_Set_Root(const char* root);
BOOL CoverArt_Set_Folder(const char* folder);
BOOL CoverArt_Hook_Dash(HANDLE hDash);
