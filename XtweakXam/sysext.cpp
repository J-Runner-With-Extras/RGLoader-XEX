
#include "sysext.h"
#include "utilities.h"
#include <string>
#include <vector>

#pragma warning (disable: 4996)
using namespace std;

DWORD threadWaitStatus = 0;
DWORD formatStatus = 0;

char hddSysEx[] = "\\Device\\Harddisk0\\SystemExtPartition\\";
char hddSysAux[] = "\\Device\\Harddisk0\\SystemAuxPartition\\";


#define MANIFEST            "\\system.manifest"
#define DESTINATION_BASE	"USEP:\\"
#define PACKAGE_BASE		"Content\\0000000000000000\\" //FFFE07DF\\00008000"

typedef struct _ITEM_INFO
{
	string source;
	string dest;
	PBYTE data;
	DWORD len;
} ITEM_INFO, *PITEM_INFO;

vector<ITEM_INFO> inf;
DWORD errcnt = 0;

u32 getBe32(unsigned char* data)
{
	u32 ret = (data[0]&0xFF)<<24;
	ret |= (data[1]&0xFF)<<16;
	ret |= (data[2]&0xFF)<<8;
	ret |= (data[3]&0xFF);
	return ret;
}

u16 getBe16(unsigned char* data)
{
	u16 ret = (data[0]&0xFF)<<8;
	ret |= (data[1]&0xFF);
	return ret;
}

BOOL checkZeros(void* vbuf, u32 len)
{
	unsigned char* buf = (unsigned char*)vbuf;
	u32 i;
	for(i = 0; i<len; i++)
	{
		if(buf[i] != 0x0)
		{
			return FALSE;
		}
	}
	return TRUE;
}

int getFileSize(FILE* fptr)
{
	int len;
	if(fptr == NULL)
	{
		return 0;
	}
	fseek(fptr, 0 , SEEK_END);
	len = ftell(fptr);
	rewind (fptr);
	return len;
}

u8* readFileToBuf(const char* fname, int* len)
{
	FILE* fin;
	unsigned char* buf = NULL;
	fin = fopen(fname, "rb");
	if(fin != NULL)
	{
		int sz = getFileSize(fin);
		buf = (unsigned char*)malloc(sz);
		if(buf != NULL)
		{
			fread(buf, sz, 1, fin);
			if(len != NULL)
			{
				*len = sz;
			}
		}
		fclose(fin);
	}
	return buf;
}

BOOL verifyManifestHeader(PSU_MANIFEST man)
{
	u8 shaBuf[0x14];
	BYTE* tdat;
	if(man->body.cont.dwSchemaVer != 3)
	{
		RGLDbgPrint("manifest schema != 3!\n");
		return FALSE;
	}
	if((man->body.cont.dwMagic != MAGIC_XSYM)&&(man->body.cont.dwMagic != MAGIC_XONM))
	{
		RGLDbgPrint("manifest revision 0x%08x != xonm|xsym!\n", man->body.cont.dwMagic);
		return FALSE;
	}
	if(man->header.dwMagic != MAGIC_XMNP)
	{
		RGLDbgPrint("manifest magic 0x%08x != XMNP!\n", man->header.dwMagic);
		return FALSE;
	}
	tdat = new BYTE[man->body.cont.size];
	memcpy(tdat, &man->body.cont.dwMagic, man->body.cont.size);
	XeCryptSha(tdat, man->body.cont.size, NULL, 0, NULL, 0, shaBuf, 0x14);
	delete[] tdat;
	if(memcmp(shaBuf, man->header.baDataSha, 0x14) != 0)
	{
		RGLDbgPrint("manifest checksum failed!\n");
		return FALSE;
	}
	return TRUE;
}

int getManifestString(BYTE* sdat, char* dest)
{
	WORD len;
	len = getBe16(sdat);
	if(len != 0)
	{
		memcpy(dest, &sdat[2], len);
		dest[len] = 0x0;
	}
	else
	{
		RGLDbgPrint("err len = 0!\n");
	}
	return len;
}

BOOL loadVerifyFile(PITEM_INFO citm, BYTE* hdat)
{
	if(citm->len != 0)
	{
		DWORD len;
		citm->data = ReadFileToBuf(citm->source.c_str(), &len);
		if(citm->data != NULL)
		{
			if(len == citm->len)
			{
				BYTE hashbuf[0x14];
				PBYTE databuf = new BYTE[len];
				memcpy(databuf, citm->data, len);
				XeCryptSha(databuf, len, NULL, 0, NULL, 0, hashbuf, 0x14);
				delete[] databuf;
				if(memcmp(hashbuf, hdat, 0x14) == 0)
				{
					RGLDbgPrint(" OK");
					return TRUE;
				}
			}
			delete[] citm->data;
		}
	}
	RGLDbgPrint(" FAILED!\n");
	errcnt++;
	return FALSE;
}

BOOL conCheckHashes(PXCONTENT_FULL_HEADER xcfh, BYTE* conData, DWORD conDataStart, DWORD conDataLen, u32* blockInfo)
{
	PBYTE tcon;
	PSTF_DIRECTORY_ENTRY dent;
	int i, j = 0;
	u32 currBlock = 0;
	u8 hashout[XECRYPT_SHA_DIGEST_SIZE];
	tcon = new BYTE[conDataStart-sizeof(XCONTENT_HEADER)];
	memcpy(tcon, &conData[sizeof(XCONTENT_HEADER)], conDataStart-sizeof(XCONTENT_HEADER));
	XeCryptSha(tcon, conDataStart-sizeof(XCONTENT_HEADER), NULL, 0, NULL, 0, hashout, XECRYPT_SHA_DIGEST_SIZE);
	delete[] tcon;
	// checking header hash

	if(memcmp(xcfh->Header.ContentId, hashout, XECRYPT_SHA_DIGEST_SIZE) == 0)
	{
		BOOL contProcess = TRUE;
		u32 currOffset = conDataStart+sizeof(STF_HASH_BLOCK);
		PSTF_HASH_BLOCK hb = (PSTF_HASH_BLOCK)&conData[conDataStart];
		PSTF_HASH_BLOCK mhb = NULL;
		dent = (PSTF_DIRECTORY_ENTRY)&conData[currOffset];
		// checking fragment hashes
		while(contProcess)
		{
			for(i = 0; i < 0xAA; i++) // this fragment is complete at 0xAA
			{
				if(checkZeros(&hb->Entries[i], 0x18))
				{
					i = 0xAA;
					contProcess = FALSE;
				}
				else
				{
					BYTE tdat[0x1000];
					memcpy(tdat, &conData[currOffset], 0x1000);
					XeCryptSha(tdat, 0x1000, NULL, 0, NULL, 0, hashout, XECRYPT_SHA_DIGEST_SIZE);
					if(memcmp(hashout, hb->Entries[i].Hash, XECRYPT_SHA_DIGEST_SIZE))
					{
						return FALSE;
					}
					blockInfo[currBlock] = currOffset;
					currBlock++;
					currOffset += 0x1000;
				}
			}
			if((currOffset+0x2000) >= conDataLen)
			{
				contProcess = FALSE;
			}
			else
			{
				hb = (PSTF_HASH_BLOCK)&conData[currOffset];
				j++;

				if(hb->Entries[0].LevelAsULONG == 0)
				{
					BYTE tdat[0x1000];

					mhb = hb; // the main hash block is backed by hash in header, and hashes all the other hash blocks
					memcpy(tdat, &conData[currOffset], 0x1000);
					XeCryptSha(tdat, 0x1000, NULL, 0, NULL, 0, hashout, XECRYPT_SHA_DIGEST_SIZE);
					if(memcmp(xcfh->Meta.Volume.StfsVolumeDescriptor.RootHash, hashout, XECRYPT_SHA_DIGEST_SIZE))
					{
						return FALSE;
					}

					memcpy(tdat, &conData[conDataStart], 0x1000);
					XeCryptSha(tdat, 0x1000, NULL, 0, NULL, 0, hashout, XECRYPT_SHA_DIGEST_SIZE);
					if(memcmp(hashout, mhb->Entries[0].Hash, XECRYPT_SHA_DIGEST_SIZE))
					{
						return FALSE;
					}

					currOffset += 0x1000;
					hb = (PSTF_HASH_BLOCK)&conData[currOffset];

				}
				if(mhb != NULL)
				{
					BYTE tdat[0x1000];
					memcpy(tdat, &conData[currOffset], 0x1000);
					XeCryptSha(tdat, 0x1000, NULL, 0, NULL, 0, hashout, XECRYPT_SHA_DIGEST_SIZE);
					if(memcmp(hashout, mhb->Entries[j].Hash, XECRYPT_SHA_DIGEST_SIZE))
					{
						return FALSE;
					}
				}

				currOffset += 0x1000;
			}
		}

		return TRUE;
	}
	return FALSE;
}

BOOL conCheckHeader(BYTE* conData, DWORD conDataLen, unsigned char* headHash)
{
	u32* blockInfo;
	u32 conDataStart;
	PXCONTENT_FULL_HEADER xcfh = (PXCONTENT_FULL_HEADER)conData;
	conDataStart = XCONTENT_ROUND_UP_TO_ALIGNMENT(xcfh->Header.SizeOfHeaders);
	u32 numBlocks = (conDataLen/0x1000)+1;
	blockInfo = (u32*)malloc((numBlocks*4));
	if(blockInfo != NULL)
	{
		if(headHash)
		{
			if(!checkZeros(headHash, 0x14))
			{
				if(memcmp(xcfh->Header.ContentId, headHash, 0x14) != 0)
				{
					return FALSE;
				}
			}
		}
		if(conCheckHashes(xcfh, conData, conDataStart, conDataLen, blockInfo))
		{
			return TRUE;
		}
	}
	return FALSE;
}

BOOL loadVerifyContainer(PITEM_INFO citm, unsigned char* hash)
{
	if(citm->len != 0)
	{
		DWORD len;
		citm->data = ReadFileToBuf(citm->source.c_str(), &len);
		if(citm->data != NULL)
		{
			if(len == citm->len)
			{
				if(conCheckHeader(citm->data, citm->len, hash))
				{
					RGLDbgPrint(" OK");
					return TRUE;
				}
			}
			delete[] citm->data;
		}
	}
	errcnt++;
	RGLDbgPrint(" FAILED!\n");
	return FALSE;
}

BOOL verifyManifestItems(BYTE* bodydat, int maxlen, BOOL verifyOnly, char* manifest_base)
{
	char sbuf[512];
	char tbuf[512];
	PSU_MANIFEST_BODY bod = (PSU_MANIFEST_BODY)bodydat;
	DWORD i;
	RGLDbgPrint("Loading and checking %d items in manifest contents...\n", bod->items.dwNumEntries);
	for(i = 0; i < bod->items.dwNumEntries; i++)
	{
		ITEM_INFO litm;
		PSU_ITEM_ENTRY itm;
		DWORD ver = 0;
		itm = &bod->items.ents[i];
		if(itm->dwSrcNameOff != 0)
		{
			getManifestString(&bodydat[itm->dwSrcNameOff], sbuf);
			litm.source = manifest_base;
			litm.source += sbuf;
			RGLDbgPrint("\r\n%d - %s", i+1, sbuf);
		}
		litm.len = itm->dwFileSize;
		ver = getBe32(&bodydat[itm->dwVersionOff]);

		if(itm->dwSrcNameOff != 0)
		{
			getManifestString(&bodydat[itm->dwSrcNameOff], sbuf);
			if(strcmp(sbuf, "flash") != 0)
			{
				getManifestString(&bodydat[itm->dwDestNameOff], sbuf);
				switch(itm->dwEntryType)
				{
				case 2: // xcontent
					if(loadVerifyContainer(&litm, itm->contHash))
					{
						sprintf(tbuf, "%s%s%08X\\%08X\\%s", DESTINATION_BASE, PACKAGE_BASE, itm->dwContentTitleId, itm->dwContentType, sbuf);
						litm.dest = tbuf;
						inf.push_back(litm);
					}
					else if(!verifyOnly) // abort so as to not waste time
					{
						return FALSE;
					}
					break;
				case 3: // file
					if(loadVerifyFile(&litm, itm->dataHash))
					{
						sprintf(tbuf, "%s%08X\\%s", DESTINATION_BASE, ver, sbuf);
						litm.dest = tbuf;
						inf.push_back(litm);
					}
					else if(!verifyOnly) // abort so as to not waste time
					{
						return FALSE;
					}
					break;
				default:
					break;
				}
			}
		}
	}
	return TRUE;
}

void cleanInfList(void)
{
	int sz = inf.size();
	if(sz != 0)
	{
		int i;
		for(i = 0; i < sz; i++)
		{
			if(inf.at(i).data != NULL)
			{
				delete[] inf.at(i).data;
			}
		}
	}
	inf.clear();
}

// load an parse manifest, and it's contents
BOOL loadManifest(BOOL verifyOnly, char* manifest_folder)
{
	char manifest_file[80];
	strcpy(manifest_file, manifest_folder);
	strcat(manifest_file, MANIFEST);

	ITEM_INFO litm;
	PSU_MANIFEST man;
	litm.data = ReadFileToBuf(manifest_file, &litm.len);
	if(litm.data != NULL)
	{
		man = (PSU_MANIFEST) litm.data;
		if((litm.len <= 0x10000)&&(litm.len >= 0x164))
		{
			if(verifyManifestHeader(man))
			{
				DWORD ver = man->body.cont.dwFlashVer;
				if(!verifyOnly)
				{
					DWORD cver = XamGetSystemVersion();
					if(ver != cver)
					{
						RGLDbgPrint("Error! Version mismatch\n");
						RGLDbgPrint("Kernel version: %d.%d.%d.%d\n", (cver>>28)&0xF, (cver>>24)&0xF, (cver>>8)&0xFFFF, cver&0xF);
						RGLDbgPrint("Update version: %d.%d.%d.%d\n", (ver>>28)&0xF, (ver>>24)&0xF, (ver>>8)&0xFFFF, ver&0xF);
						delete[] litm.data;
						return FALSE;
					}
				}
				RGLDbgPrint("Manifest ok! Version: %d.%d.%d.%d\n", (ver>>28)&0xF, (ver>>24)&0xF, (ver>>8)&0xFFFF, ver&0xF);
				// check version match to running kernel!!!
				litm.source = manifest_file;
				litm.dest = DESTINATION_BASE;
				litm.dest += "system.manifest";
				inf.push_back(litm);
				if(verifyManifestItems(&litm.data[sizeof(SU_MAINIFEST_HEADER)], litm.len-sizeof(SU_MAINIFEST_HEADER), verifyOnly, manifest_folder))
				{
					RGLDbgPrint("\n\nUpdate contents of %d installable items verified OK!\n", inf.size());
					return TRUE;
				}
				else if(verifyOnly)
				{
					RGLDbgPrint("total errors %d\n", errcnt);
				}
			}
		}
		delete[] litm.data;
	}
	RGLDbgPrint("could not load %s!\n", manifest_file);
	return FALSE;
}

BOOL installFiles(void)
{
	DWORD i;
	RGLDbgPrint("installing %d files\n", inf.size());
	for(i = 0; i < inf.size(); i++)
	{
		RGLDbgPrint("\r\n%d - %s", i+1, inf.at(i).dest.c_str());
		if(WriteBufToFile(inf.at(i).dest.c_str(), inf.at(i).data, inf.at(i).len, FALSE) == FALSE)
		{
			RGLDbgPrint("ERROR WRITING TO DISK!\n");
		}
	}
	RGLDbgPrint("\n");
	return TRUE;
}

// SEP:\203f4b00 << version specific
// SEP:\32000100
// SEP:\Content\0000000000000000\fffe07df\00008000
BOOL doDirCreate(char* cdir)
{
	char dirname[512] = DESTINATION_BASE;
	strcat(dirname, cdir);
	if(CreateDirectory(dirname, NULL) == 0)
	{
		RGLDbgPrint("error %d creating directory %s\n", GetLastError(), dirname);
		return FALSE;
	}
	return TRUE;
}

char* dirs[] =
{
	"32000100",
	"Content",
	"Content\\0000000000000000",
	"Content\\0000000000000000\\FFFE07DF",
	"Content\\0000000000000000\\FFFE07DF\\00008000",
};

BOOL createDefaultDirs(void)
{
	int i;
	char dirname[16];
	sprintf(dirname, "%08X", XamGetSystemVersion());
	if(doDirCreate(dirname) == FALSE)
	{
		return FALSE;
	}

	for(i = 0; i < sizeof(dirs)/sizeof(char*); i++)
	{
		if(doDirCreate(dirs[i]) == FALSE)
		{
			return FALSE;
		}
	}
	return TRUE;
}

void mountSepAux(void)
{
	MountPath("USEP:", "\\SEP", FALSE);
	MountPath("USAP:", "\\SAP", FALSE);
}

void unmountSepAux(void)
{
	deleteLink("USEP:", FALSE);
	deleteLink("USAP:", FALSE);
}

NTSTATUS wipePartition(char* path)
{
	NTSTATUS sts = -1;
	STRING devi;
	HANDLE hDevi;
	OBJECT_ATTRIBUTES oat;
	IO_STATUS_BLOCK ios;
	RtlInitAnsiString(&devi, path);
	oat.RootDirectory = 0;
	oat.ObjectName = &devi;
	oat.Attributes = FILE_ATTRIBUTE_DEVICE;

	sts = NtOpenFile(&hDevi, GENERIC_WRITE|GENERIC_READ|SYNCHRONIZE, &oat, &ios, OPEN_EXISTING, FILE_SYNCHRONOUS_IO_NONALERT);
	if(sts >= 0)
	{
		BYTE buf[0x4000];
		LARGE_INTEGER lint;
		lint.QuadPart = 0ULL;
		XMemSet(buf, 0, 0x1000);
		sts = NtWriteFile(hDevi, NULL, NULL, NULL, &ios, buf, 0x1000, &lint);
		if(sts >= 0)
		{
			RGLDbgPrint("wipe partition %s succeeded\n", path);
		}
		else
		{
			RGLDbgPrint("wipe partition failed to overwrite header: 0x%08x\n", sts);
		}
		NtClose(hDevi);
	}
	else
	{
		RGLDbgPrint("wipe partition %s failed to open the partition: 0x%08x\n", path, sts);
	}
	return sts;
}

NTSTATUS formatPartition(char* path)
{
	STRING devi;
	DWORD val;
	RtlInitAnsiString(&devi, path);
	val = (DWORD)devi.Length;
	val = (val+0x10000)-1;
	devi.Length = val&0xFFFF;
	return XapiFormatFATVolume(&devi);
}

void delinkPartitions(void)
{
	HRESULT res;
	STRING LinkName;
	RtlInitAnsiString(&LinkName, "\\sap");
	res = ObDeleteSymbolicLink(&LinkName);
	RGLDbgPrint("delete \\sap result %x\n", res);
	RtlInitAnsiString(&LinkName, "\\sep");
	res = ObDeleteSymbolicLink(&LinkName);
	RGLDbgPrint("delete \\sep result %x\n", res);
}

void relinkPartitions(char* sepdev, char* sapdev)
{
	HRESULT res;
	STRING LinkName;
	STRING DeviName;
	RtlInitAnsiString(&LinkName, "\\sep");
	RtlInitAnsiString(&DeviName, sepdev);
	res = ObCreateSymbolicLink(&LinkName, &DeviName);
	RGLDbgPrint("create \\sep result %x\n", res);

	RtlInitAnsiString(&LinkName, "\\sap");
	RtlInitAnsiString(&DeviName, sapdev);
	res = ObCreateSymbolicLink(&LinkName, &DeviName);
	RGLDbgPrint("create \\sap result %x\n", res);
}

void formatThread(void)
{
	NTSTATUS ret;
	formatStatus = (DWORD)-1;
	RGLDbgPrint("format thread started\n");
	delinkPartitions();
	ret = wipePartition(hddSysEx);
	RGLDbgPrint("ex wipe  : 0x%x\n", ret);
	ret = formatPartition(hddSysEx);
	RGLDbgPrint("ex format: 0x%x\n", ret);
	if(ret >= 0)
	{
		ret = wipePartition(hddSysAux);
		RGLDbgPrint("ax wipe  : 0x%x\n", ret);
		ret = formatPartition(hddSysAux);
		RGLDbgPrint("ax format: 0x%x\n", ret);
		if(ret >= 0)
		{
			relinkPartitions(hddSysEx, hddSysAux);
			formatStatus = 0;
		}
	}
	doLightSync(&formatStatus);
	threadWaitStatus = 0;
	doLightSync(&threadWaitStatus);
}

BOOL doFormatPartitions(void)
{
	HANDLE pthread;
	DWORD pthreadid;
	threadWaitStatus = 1;
	unmountSepAux();
	doLightSync(&threadWaitStatus);
	RGLDbgPrint("starting format thread\n");
	ExCreateThread(&pthread, 0x8000, &pthreadid, (PVOID) XapiThreadStartup , (LPTHREAD_START_ROUTINE)formatThread, NULL, 0x2);
	XSetThreadProcessor(pthread, 4);
	ResumeThread(pthread);
	CloseHandle(pthread);
	while(threadWaitStatus == 1)
	{
		Sleep(400);
	}
	if(formatStatus == 0)
	{
		mountSepAux();
		RGLDbgPrint("format completed successfully!\n");
		return TRUE;
	}
	RGLDbgPrint("format failed horribly!\n");
	return FALSE;
}

HRESULT setupSysPartitions(char* manifest)
{

	if(!FileExists(manifest))
	{
		return ERROR_SEVERITY_WARNING;
	}

	if(doFormatPartitions())
	{
		RGLDbgPrint("format succeeded!\n");
		Mount("\\Device\\Harddisk0\\SystemExtPartition", "\\System??\\SysExt:");
		int retError = CopyDirectory(manifest, "SysExt:");
		if(!retError)
		{
			DeleteDirectory(manifest, TRUE);
			RGLDbgPrint("sysex install successful!\n");
		}
		else
		{
			RGLDbgPrint("failed to install sysex partition: %08X\n", retError);
		}

		Mount("\\Device\\Harddisk0\\SystemAuxPartition", "\\System??\\SysAux:");
		retError = CopyDirectory("HDD:\\Filesystems\\17489-dev\\$SystemUpdate_aux", "SysAux:");
		if(!retError)
		{
			DeleteDirectory("HDD:\\Filesystems\\17489-dev\\$SystemUpdate_aux", TRUE);
			RGLDbgPrint("sysaux install successful!\n");
		}
		else
		{
			RGLDbgPrint("failed to install sysaux partition: %08X\n", retError);
		}
	}
	else
	{
		RGLDbgPrint("format FAILED!\n");
	}

	cleanInfList();
	return ERROR_SEVERITY_SUCCESS;
}
