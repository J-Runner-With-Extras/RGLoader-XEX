#include "stdafx.h"
#include "sysredirect.h"
#include "utilities.h"
#include <stdio.h>
#include <string.h>

#pragma warning (disable: 4996)

// Every named open (NtCreateFile/NtOpenFile -> IoCreateFile, and others) ends up in
// ObOpenObjectByName with the caller's name before symbolic links are resolved. Xam opens
// the system partitions by their raw device paths, so the hook rewrites those prefixes.
#define ObOpenObjectByNameOrd 269

typedef struct _SYSREDIR_PREFIX {
	const char* from;   // matched case-insensitively, must be followed by '\' or end
	char to[128];       // replacement
	USHORT fromLen;
	USHORT toLen;
} SYSREDIR_PREFIX;

static SYSREDIR_PREFIX g_prefixes[] = {
	{ "\\Device\\Harddisk0\\SystemExtPartition", "", 0, 0 },
	{ "\\Device\\Harddisk0\\SystemAuxPartition", "", 0, 0 },
	{ "\\SystemExtPartition", "", 0, 0 },	// kernel links to the active system partitions
	{ "\\SystemAuxPartition", "", 0, 0 },
	// Links xam uses (it creates \??\SEP: -> \SEP and \??\SAP: -> \SAP). Ob resolves links
	// after this hook sees the name, so they have to be matched by name too.
	{ "\\??\\SEP:", "", 0, 0 },
	{ "\\??\\SAP:", "", 0, 0 },
	{ "\\SEP", "", 0, 0 },
	{ "\\SAP", "", 0, 0 },
};
#define SYSREDIR_COUNT (sizeof(g_prefixes) / sizeof(g_prefixes[0]))
#define SYSREDIR_MAXPATH 400
#define SYSREDIR_LOGMAX 40

static DWORD g_logged = 0;
static DWORD g_redirects = 0;

typedef NTSTATUS (*OBOPENOBJECTBYNAME)(POBJECT_ATTRIBUTES attr, PVOID objType, PVOID parseCtx, PHANDLE handle);

VOID __declspec(naked) ObOpenObjectByNameSaveVar(VOID)
{
	__asm{
		li r3, 455 //make this unique for each hook
		nop
		nop
		nop
		nop
		nop
		nop
		blr
	}
}
static OBOPENOBJECTBYNAME ObOpenObjectByNameSave = (OBOPENOBJECTBYNAME)ObOpenObjectByNameSaveVar;
static DWORD obOpenOld[4];

static NTSTATUS ObOpenObjectByNameHook(POBJECT_ATTRIBUTES attr, PVOID objType, PVOID parseCtx, PHANDLE handle)
{
	if (attr != NULL && attr->RootDirectory == NULL && attr->ObjectName != NULL) {
		PSTRING name = attr->ObjectName;
		USHORT len = name->Length;
		const char* buf = name->Buffer;
		if (buf != NULL && len > 1 && buf[0] == '\\') {
			for (DWORD i = 0; i < SYSREDIR_COUNT; i++) {
				SYSREDIR_PREFIX* p = &g_prefixes[i];
				if (len < p->fromLen || _strnicmp(buf, p->from, p->fromLen) != 0)
					continue;
				if (len > p->fromLen && buf[p->fromLen] != '\\')
					continue;	// e.g. "...SystemExtPartition2" is something else
				USHORT rest = len - p->fromLen;
				if (p->toLen + rest >= SYSREDIR_MAXPATH)
					break;

				char newBuf[SYSREDIR_MAXPATH];
				memcpy(newBuf, p->to, p->toLen);
				memcpy(newBuf + p->toLen, buf + p->fromLen, rest);
				newBuf[p->toLen + rest] = 0;

				STRING newName;
				newName.Length = p->toLen + rest;
				newName.MaximumLength = newName.Length + 1;
				newName.Buffer = newBuf;
				OBJECT_ATTRIBUTES newAttr = *attr;
				newAttr.ObjectName = &newName;

				NTSTATUS st = ObOpenObjectByNameSave(&newAttr, objType, parseCtx, handle);
				g_redirects++;
				if (g_logged < SYSREDIR_LOGMAX) {
					g_logged++;
					DbgPrint("[RGL sysredirect] %.*s -> %s : %08X\n", len, buf, newBuf, st);
				}
				return st;
			}
		}
	}
	return ObOpenObjectByNameSave(attr, objType, parseCtx, handle);
}

BOOL SysRedirect_Install(const char* hddFolder)
{
	// hddFolder is relative to the HDD root, e.g. "Filesystems\\17559-sysext"
	char base[100];
	_snprintf(base, sizeof(base), "\\Device\\Harddisk0\\Partition1\\%s", hddFolder);
	base[sizeof(base) - 1] = 0;
	size_t baseLen = strlen(base);
	while (baseLen > 0 && base[baseLen - 1] == '\\') base[--baseLen] = 0;

	char check[160];
	_snprintf(check, sizeof(check), "Hdd:\\%s\\SystemExtPartition\\system.manifest", hddFolder);
	check[sizeof(check) - 1] = 0;
	if (!FileExists(check)) {
		RGLDbgPrint(" * System partition redirect: %s not found, skipping\n", check);
		return FALSE;
	}

	for (DWORD i = 0; i < SYSREDIR_COUNT; i++) {
		SYSREDIR_PREFIX* p = &g_prefixes[i];
		p->fromLen = (USHORT)strlen(p->from);
		BOOL ext = strstr(p->from, "SystemExtPartition") != NULL || strstr(p->from, "SEP") != NULL;
		const char* leaf = ext ? "SystemExtPartition" : "SystemAuxPartition";
		_snprintf(p->to, sizeof(p->to), "%s\\%s", base, leaf);
		p->to[sizeof(p->to) - 1] = 0;
		p->toLen = (USHORT)strlen(p->to);
	}

	PDWORD target = (PDWORD)resolveFunct("xboxkrnl.exe", ObOpenObjectByNameOrd);
	// Expected prologue: mflr r12 ; bl __savegprlr_xx ; stwu r1,-x(r1) ; ...
	if (target == NULL || target[0] != 0x7D8802A6 || (target[1] & 0xFC000003) != 0x48000001
		|| (target[2] & 0xFFFF0000) != 0x94210000) {
		RGLDbgPrint(" * System partition redirect: ObOpenObjectByName at %08X has an unexpected prologue, skipping\n", (DWORD)target);
		return FALSE;
	}
	hookFunctionStart(target, (PDWORD)ObOpenObjectByNameSaveVar, obOpenOld, (DWORD)ObOpenObjectByNameHook);
	RGLDbgPrint(" * System partitions redirected to %s\n", base);
	return TRUE;
}
