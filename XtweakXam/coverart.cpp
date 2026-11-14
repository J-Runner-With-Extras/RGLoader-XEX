#include "coverart.h"
#include "gamelib_patch.h"

// Offline the dash never gets box art for library tiles: Marketplace.GameLibrary's
// ConvertToLibraryItem leaves boxart empty and only the Live catalog reply fills it.
// Swap in a build of that Lua chunk which sets boxart from a local cover folder. The
// chunk is stored uncompressed in the dash image, so it is replaced in place.
//
// Dash Lua has no way to test for a file, so the covers in the cover folder are
// listed into the chunk ("|<tid>" per .jpg, "|<tid>p" per .png) each time the dash
// loads, and a listed title gets boxart = file://<folder>\<tid>.jpg. When a cover art
// root is set, other titles get ImageCache.GetImage(<root>/...d802<tid>/1033/boxartlg.jpg)
// (the art on download.xbox.com is a plain download keyed by title id).

static char coverArtRoot[0x200];
static char coverArtFolder[0x100] = COVERART_DEFAULT_FOLDER;

BOOL CoverArt_Set_Root(const char* root)
{
	size_t len = strlen(root);
	while(len > 0 && root[len-1] == '/')
		len--;
	if(len == 0 || len >= sizeof(coverArtRoot))
	{
		coverArtRoot[0] = 0;
		return FALSE;
	}
	memcpy(coverArtRoot, root, len);
	coverArtRoot[len] = 0;
	return TRUE;
}

BOOL CoverArt_Set_Folder(const char* folder)
{
	size_t len = strlen(folder);
	while(len > 0 && (folder[len-1] == '\\' || folder[len-1] == '/'))
		len--;
	if(len == 0 || len >= sizeof(coverArtFolder))
	{
		coverArtFolder[0] = 0;
		return FALSE;
	}
	memcpy(coverArtFolder, folder, len);
	coverArtFolder[len] = 0;
	return TRUE;
}

static BOOL IsHex8(const char* s)
{
	for(int i = 0; i < 8; i++)
		if(!isxdigit((unsigned char)s[i]))
			return FALSE;
	return TRUE;
}

// Fill list with "|<tid>" / "|<tid>p" for each cover in the cover folder, up to max
// bytes. Returns the list length.
static DWORD BuildLocalList(char* list, DWORD max)
{
	DWORD len = 0, skipped = 0;
	if(coverArtFolder[0] == 0)
		return 0;
	char pattern[sizeof(coverArtFolder) + 2];
	sprintf_s(pattern, sizeof(pattern), "%s\\*", coverArtFolder);
	WIN32_FIND_DATA fd;
	HANDLE hFind = FindFirstFile(pattern, &fd);
	if(hFind == INVALID_HANDLE_VALUE)
		return 0;
	do
	{
		const char* name = fd.cFileName;
		if((fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) || strlen(name) != 12 || !IsHex8(name))
			continue;
		BOOL png = _stricmp(name + 8, ".png") == 0;
		if(!png && _stricmp(name + 8, ".jpg") != 0)
			continue;
		DWORD need = png ? 10 : 9;
		if(len + need > max)
		{
			skipped++;
			continue;
		}
		list[len++] = '|';
		for(int i = 0; i < 8; i++)
			list[len++] = (char)tolower((unsigned char)name[i]);
		if(png)
			list[len++] = 'p';
	} while(FindNextFile(hFind, &fd));
	FindClose(hFind);
	if(skipped)
		RGLDbgPrint("     WARNING: no room for %d covers in %s\n", skipped, coverArtFolder);
	return len;
}

// Write a Lua string field: u32 length including the NUL, then the bytes and the NUL.
static PBYTE PutLuaString(PBYTE p, const char* a, DWORD aLen, const char* b, DWORD bLen)
{
	DWORD strLen = aLen + bLen + 1;
	memcpy(p, &strLen, 4); // chunk is unaligned; native order is the chunk's big-endian
	p += 4;
	memcpy(p, a, aLen);
	p += aLen;
	memcpy(p, b, bLen);
	p += bLen;
	*p++ = 0;
	return p;
}

static DWORD Fnv1a(const BYTE* data, DWORD size)
{
	DWORD h = 0x811C9DC5;
	for(DWORD i = 0; i < size; i++)
		h = (h ^ data[i]) * 0x01000193;
	return h;
}

// Call from the xex load hook once dash.xex is loaded, before it runs.
BOOL CoverArt_Hook_Dash(HANDLE hDash)
{
	if(coverArtRoot[0] == 0 && coverArtFolder[0] == 0)
		return FALSE;

	PBYTE section = NULL;
	DWORD sectionSize = 0;
	if(hDash == NULL || !XGetModuleSection(hDash, COVERART_DASH_SECTION, (PVOID*)&section, &sectionSize))
	{
		RGLDbgPrint("     ERROR: dash.xex section %s not found\n", COVERART_DASH_SECTION);
		return FALSE;
	}

	PBYTE chunk = NULL;
	for(DWORD i = 0; i + GAMELIB_ORIG_SIZE <= sectionSize; i++)
	{
		if(section[i] == GameLib_OrigStart[0] && memcmp(&section[i], GameLib_OrigStart, sizeof(GameLib_OrigStart)) == 0
			&& Fnv1a(&section[i], GAMELIB_ORIG_SIZE) == GAMELIB_ORIG_FNV1A)
		{
			chunk = &section[i];
			break;
		}
	}
	if(chunk == NULL)
	{
		RGLDbgPrint("     ERROR: Marketplace.GameLibrary chunk not found (unknown dash version?)\n");
		return FALSE;
	}

	// XUI path of the folder the listed covers are loaded from. Our drive links are
	// not visible to the dash (opening them fails with STATUS_OBJECT_PATH_NOT_FOUND),
	// so name the device behind the drive instead.
	static const char* drives[][2] = {
		{ "Hdd:", "\\Device\\Harddisk0\\Partition1" },
		{ "Mass0:", "\\Device\\Mass0" },
		{ "Mass1:", "\\Device\\Mass1" },
		{ "Mass2:", "\\Device\\Mass2" },
	};
	const char* device = "";
	const char* rest = coverArtFolder;
	for(int i = 0; i < ARRAYSIZE(drives); i++)
	{
		size_t n = strlen(drives[i][0]);
		if(_strnicmp(coverArtFolder, drives[i][0], n) == 0)
		{
			device = drives[i][1];
			rest = coverArtFolder + n;
			break;
		}
	}
	char folderUrl[sizeof(coverArtFolder) + 48];
	sprintf_s(folderUrl, sizeof(folderUrl), "file://%s%s\\", device, rest);

	// With no root the root string is left empty, which makes the Lua skip the image cache
	DWORD rootLen = strlen(coverArtRoot);
	DWORD prefixLen = rootLen ? sizeof(GAMELIB_PATH_PREFIX) - 1 : 0;
	DWORD folderUrlLen = strlen(folderUrl);
	DWORD fixedSize = sizeof(GameLib_Part0) + 4 + 1 + sizeof(GameLib_Part1) + 4 + folderUrlLen + 1
		+ sizeof(GameLib_Part2) + 4 + rootLen + prefixLen + 1 + sizeof(GameLib_Part3);
	if(fixedSize > GAMELIB_ORIG_SIZE)
	{
		RGLDbgPrint("     ERROR: cover art root or folder too long\n");
		return FALSE;
	}

	static char localList[GAMELIB_ORIG_SIZE];
	DWORD listLen = BuildLocalList(localList, GAMELIB_ORIG_SIZE - fixedSize);
	if(listLen == 0 && rootLen == 0)
	{
		RGLDbgPrint("     * No covers in %s, dash left alone\n", coverArtFolder);
		return FALSE;
	}

	// Lua stops reading at the end of the main function, so the old bytes past
	// the new chunk are never looked at.
	PBYTE p = chunk;
	memcpy(p, GameLib_Part0, sizeof(GameLib_Part0));
	p += sizeof(GameLib_Part0);
	p = PutLuaString(p, localList, listLen, "", 0);
	memcpy(p, GameLib_Part1, sizeof(GameLib_Part1));
	p += sizeof(GameLib_Part1);
	p = PutLuaString(p, folderUrl, folderUrlLen, "", 0);
	memcpy(p, GameLib_Part2, sizeof(GameLib_Part2));
	p += sizeof(GameLib_Part2);
	p = PutLuaString(p, coverArtRoot, rootLen, GAMELIB_PATH_PREFIX, prefixLen);
	memcpy(p, GameLib_Part3, sizeof(GameLib_Part3));
	DWORD covers = 0;
	for(DWORD i = 0; i < listLen; i++)
		covers += localList[i] == '|';
	RGLDbgPrint("     * %d local covers in %s (%s)\n", covers, coverArtFolder, folderUrl);
	return TRUE;
}
