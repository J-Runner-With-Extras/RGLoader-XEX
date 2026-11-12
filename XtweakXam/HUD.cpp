#include "HUD.h"

HANDLE searchForHandle(const char* mName)
{

	PLDR_DATA_TABLE_ENTRY curTab = (PLDR_DATA_TABLE_ENTRY)GetModuleHandle("xboxkrnl.exe");
	PXEX_HEADER_STRING peName;

	curTab = (PLDR_DATA_TABLE_ENTRY)curTab->InLoadOrderLinks.Flink;

	while(curTab != NULL)
	{
		peName = (PXEX_HEADER_STRING)RtlImageXexHeaderField(curTab->XexHeaderBase, 0x000183FF);

		if((peName != NULL) && (peName->Data[0] != 0))
		{
			if(stricmp((char*)peName->Data, mName) == 0)
			{
				HANDLE ret = (HANDLE)curTab;
				return ret;
			}
		}
		curTab = (PLDR_DATA_TABLE_ENTRY)curTab->InLoadOrderLinks.Flink;
	}
	return INVALID_HANDLE_VALUE;
}


void replaceHudString( const char* newtext, DWORD addr, int length)
{

	char* temp = new char[length+1];
	for(int i=0; i<length; i++)
	{
		temp[i]=' ';
	}
	temp[length]='\0';

	int nLen=strlen(newtext);
	for(int i=0; i<nLen; i++)
	{
		temp[i]=newtext[i];
	}

	memcpy((LPVOID)addr, temp, length+1);
}

void patchHUDStrings(void)
{

	HANDLE hModule = searchForHandle( "hud.dll" );
	if(hModule == INVALID_HANDLE_VALUE)
	{
		RGLDbgPrint("\nERROR: Unable to get handle to hud.dll\n");
	}

	VOID* pSectionData;
	DWORD dwSectionSize;
	if( !XGetModuleSection(hModule ,"hud", &pSectionData, &dwSectionSize ) )
	{
		RGLDbgPrint("\nERROR: Unable to get module section data from hud.dll\n");
	}

	replaceHudString(HUD_FamilySettings_String, (DWORD)pSectionData + FamilySettings_Str1, HUD_FamilySettings_Len);
	replaceHudString(HUD_FamilySettings_String, (DWORD)pSectionData + FamilySettings_Str2, HUD_FamilySettings_Len);
}


DWORD HUD_BootToDashHelper_Hook(DWORD* _XUIOBJ, _XDASHLAUNCHDATA* LaunchData , DWORD* cstr, DWORD* r6, DWORD* r7)
{

	if(LaunchData->dwCommand==(DWORD)LaunchData_FamilySettings)
	{
		RGLDbgPrint("\n[RGLOADER]: Jumping back to xshell!\n");
		XSetLaunchData( NULL, 0 );

		XamLoaderLaunchTitleEx("\\SystemRoot\\xshell.xex", "\\SystemRoot", NULL, 0);
		//close HUD menu
		setmemdm((DWORD)((unsigned long)0x60 + (unsigned long)r7), 0);
		setmemdm((DWORD)((unsigned long)0x5C + (unsigned long)r7), 0);
		return 0;
	}
	else
	{

		return ((HUD_BOOTTODASHHELPER)BootToDashHelper_Func)(_XUIOBJ, LaunchData , cstr, r6,  r7);
	}
}



BOOL HUDPatchInJump(DWORD destination, BOOL linked=false)
{

	setmemdm( BootToDashHelper_Jump, makeBranch( BootToDashHelper_Jump, (FamilySettings_LaunchStr)+0x4, true));

	setmemdm( FamilySettings_LaunchStr, 0x4E800020); //blr
	BYTE data[0x10];
	patchInJump((PDWORD)data, (DWORD)destination, linked);
	HRESULT hr;
	hr = (HRESULT)memcpy((PDWORD)((FamilySettings_LaunchStr)+4), (LPCVOID)data, 0x10);
	return 1;
}


int patch_HUD_ReturnToXshell()
{

	char* newLabel= "RGLoader\0\0";

	HUDPatchInJump((DWORD)HUD_BootToDashHelper_Hook);
	patchHUDStrings();


	return 1;
}
