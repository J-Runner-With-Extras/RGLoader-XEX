// XtweakXam.cpp : Defines the entry point for the application.
//

#include "stdafx.h"
#include <xbdm.h>
#include <fstream>
#include <string>
#include <stdio.h>
#include "INIReader.h"
#include "xam.h"
#include "HUD.h"
#include "xshell.h"
#include "XBDMOffsets.h"
#include "sysext.h"
#include "sysredirect.h"
using namespace std;

static bool fKeepMemory=true;
static bool fExpansionEnabled = false;
static INIReader* reader;

#define setmem(addr, data) { DWORD d = data; memcpy((LPVOID)addr, &d, 4);}

void patch_BLOCK_LIVE()
{
	{
		RGLDbgPrint(" * Blocking xbox live DNS\r\n");

		char* nullStr = "NO.%sNO.NO\0";
		DWORD nullStrSize = 18;

		// null out xbox live dns tags
		// TODO replace this with a DNS hook like what DashLaunch does
		memcpy( (LPVOID)0x8161EB14, (LPCVOID)nullStr, nullStrSize); // siflc
		memcpy( (LPVOID)0x8161EB2C, (LPCVOID)nullStr, nullStrSize); // piflc
		memcpy( (LPVOID)0x8161EB44, (LPCVOID)nullStr, nullStrSize); // notice
		memcpy( (LPVOID)0x8161EB58, (LPCVOID)nullStr, nullStrSize); // xexds
		memcpy( (LPVOID)0x8161EB70, (LPCVOID)nullStr, nullStrSize); // xetgs
		memcpy( (LPVOID)0x8161EB88, (LPCVOID)nullStr, nullStrSize); // xeas
		memcpy( (LPVOID)0x8161EB9C, (LPCVOID)nullStr, nullStrSize); // xemacs
	}

}

// Enable USBMASS0-2 in neighborhood
void patch_MAP_USB(void)
{

	RGLDbgPrint(" * Adding extra devices to xbox neighborhood\r\n");
	{
		//add usb devices to xbn
		setmem(xbdm_17489.mass0_obname_ptr, xbdm_17489.mass0_obname);
		setmem(xbdm_17489.mass1_obname_ptr, xbdm_17489.mass1_obname);
		setmem(xbdm_17489.mass2_obname_ptr, xbdm_17489.mass2_obname);
		setmem(xbdm_17489.mass0_enable, 0x01);
		setmem(xbdm_17489.mass1_enable, 0x01);
		setmem(xbdm_17489.mass2_enable, 0x01);

		//add flash to xbn
		setmem(xbdm_17489.flash_obname_ptr, xbdm_17489.flash_obname);
		setmem(xbdm_17489.flash_enable, 0x01);

		//add hdd system ext partition  to xbn
		setmem(xbdm_17489.hddsysext_obname_ptr, xbdm_17489.hddsysext_obname);
		setmem(xbdm_17489.hddsysext_enable, 0x01);

		//add intusb system ext partition to xbn
		setmem(xbdm_17489.intusbsysext_obname_ptr, xbdm_17489.intusbsysext_obname);
		setmem(xbdm_17489.intusbsysext_enable, 0x01);

		//add intusb system ext partition to xbn
		setmem(xbdm_17489.hddsysaux_obname_ptr, xbdm_17489.hddsysaux_obname);
		setmem(xbdm_17489.hddsysaux_enable, 0x01);

		//nop drivemap internal check (always be 1)
		setmem(xbdm_17489.map_internal_check, 0x60000000);
	}

}

//21076
// Changes the default dashboard
void patch_default_dash(string path)
{

	RGLDbgPrint(" * Reconfiguring default dash to: %s\r\n", path.c_str());

	ofstream dashxbx;

	dashxbx.open("Root:\\dashboard.xbx", ofstream::out);

	if(dashxbx.is_open())
	{

		dashxbx<<path;
		for(int i=path.length(); i<0x100; i++)
		{
			dashxbx<<'\0';
		}
		dashxbx.close();
	}
	else
	{
		RGLDbgPrint("   ERROR: unable to write dashboard.xbx\r\n");
	}

}




static string xexNamestr = "";
static int backslash = 0;
static string rTemp="";


bool strCompare(char* one, char* two, int len)
{
	int i=0;
	for(i=0; i<len; i++)
	{
		if(i>0 && (one[i]=='\0' || two[i]=='\0'))
		{
			return true;
		}
		if(one[i]!=two[i])
		{
			return false;
		}

	}
	return true;
}



VOID __declspec(naked) XexpLoadImageSaveVar(VOID)
{
	__asm
	{
		li r3, 454 //make this unique for each hook
		nop
		nop
		nop
		nop
		nop
		nop
		blr
	}
}

#define XexLoadExecutableOrd 408

#define XexLoadImageOrd 409

#define XEXLOADIMAGE_MAX_SEARCH		9

NTSTATUS XexpLoadImageHook(LPCSTR xexName, DWORD typeInfo, DWORD ver, PHANDLE modHandle);
typedef NTSTATUS (*XEXPLOADIMAGEFUN)(LPCSTR xexName, DWORD typeInfo, DWORD ver, PHANDLE modHandle); // XexpLoadImage
static DWORD xexLoadOld[4];

int patch_hook_xexload(void)
{
	PDWORD xexLoadHookAddr = (PDWORD)findInterpretBranchOrd("xboxkrnl.exe", XexLoadImageOrd, XEXLOADIMAGE_MAX_SEARCH);
	RGLDbgPrint("  - Found addr\r\n");
	if(xexLoadHookAddr != NULL)
	{
		hookFunctionStart(xexLoadHookAddr, (PDWORD)XexpLoadImageSaveVar, xexLoadOld, (DWORD)XexpLoadImageHook);

	}

	return 1;
}

#define XEXLOAD_DASH	"\\Device\\Flash\\dash.xex"
#define XEXLOAD_DASH2	"\\SystemRoot\\dash.xex"

#define XEXLOAD_SIGNIN	"signin.xex"
#define XEXLOAD_CREATE	"createprofile.xex"
#define XEXLOAD_HUD		"hud.xex"

XEXPLOADIMAGEFUN XexpLoadImageSave = (XEXPLOADIMAGEFUN)XexpLoadImageSaveVar;
NTSTATUS XexpLoadImageHook(LPCSTR xexName, DWORD typeInfo, DWORD ver, PHANDLE modHandle)
{

	NTSTATUS ret = XexpLoadImageSave(xexName, typeInfo, ver, modHandle);

	if(ret >= 0)
	{

		if(stricmp(xexName, XEXLOAD_HUD) == 0)
		{
			RGLDbgPrint("\n\n ***RGLoader.xex*** \n   -Re-applying patches to: %s!\n\n", xexName);

			rTemp = reader->Get("Expansion", "HUD_Jump_To_XShell", "NOTFOUND");
			if(rTemp != "NOTFOUND" && (rTemp == "1" || rTemp == "true" || rTemp=="on"))
			{
				RGLDbgPrint("     * Replacing family settings button with \"Jump to XShell\"");
				patch_HUD_ReturnToXshell();
			}

		}

		const char * xshellName = "xshell.xex";
		if(strlen(xexName) >= 10)
		{
			if(stricmp(xexName + strlen(xexName) - 10, xshellName) == 0)
			{
				RGLDbgPrint("\n\n ***RGLoader.xex*** \n   -Re-applying patches to: %s!\n\n", xexName);

				rTemp = reader->Get("Config", "Redirect_Xshell_Start_But", "NOTFOUND");
				if(rTemp != "NOTFOUND" && (rTemp != "1" && rTemp != "true" && rTemp!="on")  && (rTemp != "0" && rTemp != "false" && rTemp!="off"))
				{
					RGLDbgPrint("     * Remapping xshell start button to %s.\n\n", rTemp.c_str());
					patch_Xshell_start_path(rTemp);
				}
			}
		}
		else if(stricmp(xexName, XEXLOAD_SIGNIN) == 0)
		{
			RGLDbgPrint("\n\n ***RGLoader.xex*** \n   -Re-applying patches to: %s!\n", xexName);

			rTemp = reader->Get("Config", "No_Sign_Notice", "NOTFOUND");
			if(rTemp == "NOTFOUND" || (rTemp == "1" || rTemp == "true" || rTemp=="on"))
			{
				RGLDbgPrint("     * Disabling xbox live sign in notice.\n\n");

				// xbdm_17489.NoSignNotice
				//_HandleError_CLogonErrorChainOfResponsibility in CSigninModel::SignInProfiles  -> 38600000 li r3, 0
				// This offset is specific to the 2.0.17489.0 RGL flash and the various kernel spoofs based on it
				setmem(0x9011841C, 0x38600000);
			}

		}
	}
	return ret;
}

//######################################


int patch_apply_binary(string filepath)
{

	FILE* patches;
	BYTE* buffer;
	DWORD size=0, patchesApplied=0;

	patches= fopen(filepath.c_str(), "rb");
	if(!patches)
	{
		return false;
	}

	fseek(patches, 0, SEEK_END);
	size = ftell(patches);
	if(size%4!=0)
	{
		RGLDbgPrint("   ERROR: Invalid patch size\n");
		fclose(patches);
		return 0;
	}
	fseek(patches, 0, SEEK_SET);
	buffer = new BYTE[size];
	fread(buffer, 1, size, patches);

	DWORD offset=0;
	if(*(DWORD*)&buffer[offset]==0x52474C50)
	{
		offset+=4;
	}
	DWORD dest=*(DWORD*)&buffer[offset];
	offset+=4;

	while(dest!=0xFFFFFFFF && offset<size)
	{
		DWORD numPatches = *(DWORD*)&buffer[offset];
		offset+=4;
		for(DWORD i=0; i<numPatches; i++, offset+=4, dest+=4)
		{
			setmem(dest, *(DWORD*)&buffer[offset]);
		}
		dest=*(DWORD*)&buffer[offset];
		offset+=4;
		patchesApplied++;
	}
	fclose(patches);
	return patchesApplied;
}


void patch_search_binary(void)
{
	WIN32_FIND_DATA FindFileData;
	HANDLE hFind;

	RGLDbgPrint(" * Searching for additional RGLP binary patch files\n");

	hFind = FindFirstFile("Root:\\*.rglp", &FindFileData);
	while(hFind!= INVALID_HANDLE_VALUE)
	{
		RGLDbgPrint("  **located binary: %s\n", FindFileData.cFileName);

		if(patch_apply_binary("Root:\\"+(string)FindFileData.cFileName)<=0)
		{
			RGLDbgPrint("  ERROR: Cannot apply patch\n");
		}

		if(!FindNextFile(hFind, &FindFileData))
		{
			hFind=INVALID_HANDLE_VALUE;
		}
	}
}

VOID loadPlugins()
{

	string temp = reader->Get("Plugins", "Plugin1", "NOTFOUND");
	if(temp!="NOTFOUND" && temp!="none")
	{
		if(XexLoadImage(temp.c_str(),8,0,NULL))
		{
			RGLDbgPrint(" ERROR: Failed to load %s", temp.c_str());
		}
	}
	temp = reader->Get("Plugins", "Plugin2", "NOTFOUND");
	if(temp!="NOTFOUND" && temp!="none")
	{
		if(XexLoadImage(temp.c_str(),8,0,NULL))
		{
			RGLDbgPrint(" ERROR: Failed to load %s", temp.c_str());
		}
	}
	temp = reader->Get("Plugins", "Plugin3", "NOTFOUND");
	if(temp!="NOTFOUND" && temp!="none")
	{
		if(XexLoadImage(temp.c_str(),8,0,NULL))
		{
			RGLDbgPrint(" ERROR: Failed to load %s", temp.c_str());
		}
	}
	temp = reader->Get("Plugins", "Plugin4", "NOTFOUND");
	if(temp!="NOTFOUND" && temp!="none")
	{
		if(XexLoadImage(temp.c_str(),8,0,NULL))
		{
			RGLDbgPrint(" ERROR: Failed to load %s", temp.c_str());
		}
	}
	temp = reader->Get("Plugins", "Plugin5", "NOTFOUND");
	if(temp!="NOTFOUND" && temp!="none")
	{
		if(XexLoadImage(temp.c_str(),8,0,NULL))
		{
			RGLDbgPrint(" ERROR: Failed to load %s", temp.c_str());
		}
	}
}


BOOL Initialize(HANDLE hModule)
{

	RGLDbgPrint("===RGLoader Runtime Patcher - Kernel 17489 + spoofs===\r\n\r\n");

	RGLDbgPrint(" * Reverting XBDM hard drive load patch\n");
	setmem(0x801D0824,0x80041BA0);

	RGLDbgPrint(" * Mounting devices\n");
	Mount("\\Device\\Harddisk0\\Partition1", "\\System??\\Hdd:");
	Mount("\\Device\\Harddisk0\\Partition1", "\\System??\\HDD:");
	Mount("\\Device\\Mass0", "\\System??\\Mass0:");
	Mount("\\Device\\Mass1", "\\System??\\Mass1:");
	Mount("\\Device\\Mass2", "\\System??\\Mass2:");
	Mount("\\Device\\Flash", "\\System??\\sfcx:");
	Mount("\\SystemRoot", "\\System??\\Root:");

	RGLDbgPrint(" * Parsing rgloader.ini\n");

	reader = new INIReader("Mass0:\\rgloader.ini");
	if(reader->ParseError() < 0)
	{
		reader = new INIReader("Mass1:\\rgloader.ini");
	}
	if(reader->ParseError() < 0)
	{
		reader = new INIReader("Mass2:\\rgloader.ini");
	}
	if(reader->ParseError() < 0)
	{
		reader= new INIReader("Hdd:\\rgloader.ini");
	}
	if(reader->ParseError() < 0)
	{
		reader= new INIReader("sfcx:\\rgloader.ini");
	}

	if(reader->ParseError() < 0)
	{
		RGLDbgPrint("ERROR: Unable to open ini file!\r\n");
		patch_MAP_USB();
		fKeepMemory=false;
		return 0;
	}

	string temp = reader->Get("Filters", "Block_Live_DNS", "NOTFOUND");
	if (temp != "NOTFOUND" && (temp == "1" || temp == "true" || temp == "on"))
	{
		patch_BLOCK_LIVE();
	}

	//search for extra binary patches
	temp = reader->Get("Config", "NoRGLP", "NOTFOUND");
	if (temp == "NOTFOUND" || temp != "FALSE" || temp != "false")
	{
		patch_search_binary();
	}

	char* SysExtPath = "HDD:\\Filesystems\\17489-dev\\$SystemUpdate";
	if (FileExists(SysExtPath))
	{
		RGLDbgPrint(" * Attemping to install system extended partion from %s\n", SysExtPath);

		if (setupSysPartitions(SysExtPath) == ERROR_SEVERITY_SUCCESS)
		{
			RGLDbgPrint("  -Success!\n");
		}
		else
		{
			RGLDbgPrint("  -Failed\n");
		}

		RGLDbgPrint(" * Fixing XAM FEATURES\n");
#define XamFeatureEnableDisable 0x817483A8
		((void(*)(...))XamFeatureEnableDisable)(1, 2);
		((void(*)(...))XamFeatureEnableDisable)(1, 3);
		((void(*)(...))XamFeatureEnableDisable)(1, 4);

		((void(*)(...))XamFeatureEnableDisable)(0, 1);
		((void(*)(...))XamFeatureEnableDisable)(0, 5);
		((void(*)(...))XamFeatureEnableDisable)(0, 6);
		((void(*)(...))XamFeatureEnableDisable)(0, 7);
		((void(*)(...))XamFeatureEnableDisable)(0, 0x21);
		((void(*)(...))XamFeatureEnableDisable)(0, 0x22);
		((void(*)(...))XamFeatureEnableDisable)(0, 0x23);
		((void(*)(...))XamFeatureEnableDisable)(0, 0x24);
		((void(*)(...))XamFeatureEnableDisable)(0, 0x26);
		((void(*)(...))XamFeatureEnableDisable)(0, 0x27);


	}
	else
	{
		RGLDbgPrint(" * No system extended files found, skipping..\n");
	}

	// Keep this boot's system extended/aux partition contents (avatars, dash extensions) in a
	// folder on the HDD, so the real partitions can keep the set another boot (e.g. stock)
	// needs. Off unless SysExt_Redirect names the folder, relative to Hdd:.
	// Must stay after the $SystemUpdate installer above: it wipes/formats the partitions by their
	// device paths, which the hook would otherwise send to a folder on Partition1.
	temp = reader->Get("Config", "SysExt_Redirect", "NOTFOUND");
	if(temp != "NOTFOUND" && temp != "0" && temp != "false" && temp != "off" && temp != "none")
	{
		if(temp == "1" || temp == "true" || temp == "on")
			RGLDbgPrint(" * SysExt_Redirect needs a folder name (e.g. Filesystems\\sysext), skipping\n");
		else
			SysRedirect_Install(temp.c_str());
	}


	RGLDbgPrint(" Patches successfully applied! \r\n\r\n");

	loadPlugins();

	/*
	{
		//uncomment to make it only run on the first boot, then will be disabled.  Good for debugging things that crash.
		FILE* temp;
		temp= fopen("Hdd:\\test.test", "rb");
		if(temp)
		{
			RGLDbgPrint(" * ALREADY BOOTED ONCE! Quitting Rgloader.xex!\r\n");
			fclose(temp);
			return 0;
		}
	}
	{
		FILE* temp;
		temp= fopen("Hdd:\\test.test", "w");
		fclose(temp);
	}
	*/

	temp = reader->Get("Expansion", "Map_USB_Mass", "NOTFOUND");
	if(temp == "1" || temp == "true" || temp=="on")
	{
		patch_MAP_USB();
	}
	temp = reader->Get("Expansion", "Persistent_Patches", "NOTFOUND");
	if(temp == "1" || temp == "true" || temp=="on")
	{
		patch_hook_xexload();
	}

	temp = reader->Get("Config", "Default_Dashboard", "NOTFOUND");
	if(temp!="NOTFOUND")
	{
		patch_default_dash(temp);
	}

	temp = reader->Get("Expansion", "Boot_Animation", "NOTFOUND");
	if(temp!="NOTFOUND" && (temp == "1" || temp == "true") && FileExists("Root:\\RGL_bootanim.xex"))
	{
		patch_default_dash("\\SystemRoot\\RGL_bootanim.xex");
	}

	temp = reader->Get("Expansion", "Retail_Profile_Encryption", "NOTFOUND");
	if(temp == "1" || temp == "true" || temp=="on")
	{
		RGLDbgPrint(" * Setting up retail profile encryption\n");
		Xam_Profile_Crypto_Hook_Setup();
	}

	return TRUE;
}



BOOL APIENTRY DllMain(HANDLE hModule, DWORD dwReason, LPVOID lpReserved)
{
	if(dwReason == DLL_PROCESS_ATTACH)
	{

		if(XboxKrnlVersion->Build < 17489)
		{
			RGLDbgPrint("This version of RGLoader.xex is unsupported on kernel versions earlier than 17489.\n");
			RGLDbgPrint("No patches will be applied.\n\n");
			return true;
		}

		Initialize(hModule);

		//set load count to 1
		if(!fKeepMemory)
		{
			*(WORD*)((DWORD)hModule + 64) = 1;
			return FALSE;
		}
		else
		{
			return true;
		}
	}
	return TRUE;
}
