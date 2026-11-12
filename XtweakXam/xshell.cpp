#include "xshell.h"

using namespace std;


VOID patchInDashStrings(DWORD* addr, DWORD xex, DWORD path)
{
	DWORD data[4];

	if(xex & 0x8000) // If bit 16 is 1
	{
		data[0] = 0x3D600000 + (((xex >> 16) & 0xFFFF) + 1); // lis 	%r11, dest>>16 + 1
	}
	else
	{
		data[0] = 0x3D600000 + ((xex >> 16) & 0xFFFF); // lis 	%r11, dest>>16
	}
	if(path & 0x8000) // If bit 16 is 1
	{
		data[1] = (DWORD)0x3D400000 + (((path >> 16) & 0xFFFF) + 1); // lis 	%r11, dest>>16 + 1
	}
	else
	{
		data[1] = (DWORD)0x3D400000 + ((path >> 16) & 0xFFFF); // lis 	%r11, dest>>16
	}

	data[2] = 0x388B0000 + (xex & 0xFFFF);
	data[3] = (DWORD)0x386A0000 + (DWORD)(path & 0xFFFF);

	memcpy((LPVOID)addr, (LPCVOID)data, 0x10);
}

int patch_Xshell_start_path(string nPath)
{

	int backslash = nPath.rfind("\\");
	string xex = nPath.substr(backslash+1, nPath.length()-(backslash+1));
	nPath=nPath.substr(0, backslash);

	RGLDbgPrint("\n[RGLOADER]: Setting xshell start button to: %s  %s !\n", nPath.c_str(), xex.c_str());

	startXex=new char[xex.length() + 1];
	strcpy(startXex, xex.c_str());
	startPath=new char[nPath.length() + 1];
	strcpy(startPath, nPath.c_str());

	/*Search for:
	lis       r11, ((aDash_xex+0x10000)@h) # "dash.xex"
	lis       r10, ((aSystemroot+0x10000)@h) # "\\SystemRoot"
	*/
	//patch all references
	patchInDashStrings((DWORD*)loc1 , (DWORD)startXex, (DWORD)startPath);
	patchInDashStrings((DWORD*)loc2 , (DWORD)startXex, (DWORD)startPath);
	patchInDashStrings((DWORD*)loc3 , (DWORD)startXex, (DWORD)startPath);
	patchInDashStrings((DWORD*)loc4 , (DWORD)startXex, (DWORD)startPath);

	return 1;
}
