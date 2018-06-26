#include "stdafx.h"
#include "hardware.h"
#include <intrin.h>
#include <stdio.h>
#if defined(_MSC_VER) // MSVC
#include <windows.h>
#include <iptypes.h>
#include <iphlpapi.h>
#include <winioctl.h>
#include <minwinbase.h>
#endif
#include <assert.h>


char* ConvertToString(DWORD dwDiskData[256], int nFirstIndex, int nLastIndex)
{
	static char szResBuf[1024];
	char ss[256];
	int nIndex = 0;
	int nPosition = 0;

	for (nIndex = nFirstIndex; nIndex <= nLastIndex; nIndex++)
	{
		ss[nPosition] = (char)(dwDiskData[nIndex] / 256);
		nPosition++;

		// Get low BYTE for 2nd character
		ss[nPosition] = (char)(dwDiskData[nIndex] % 256);
		nPosition++;
	}

	// End the string
	ss[nPosition] = '\0';

	int i, index = 0;
	for (i = 0; i < nPosition; i++)
	{
		if (ss[i] == 0 || ss[i] == 32)   continue;
		szResBuf[index] = ss[i];
		index++;
	}
	szResBuf[index] = 0;

	return szResBuf;
}


void getcpuidex(unsigned int cpuinfo[4], unsigned int flag, unsigned int ecxvalue)
{
#if defined(_MSC_VER) // MSVC
#if defined(_WIN64) // 64位下不支持内联汇编. 1600: VS2010, 据说VC2008 SP1之后才支持__cpuidex.
	__cpuidex((int*)(void*)cpuinfo, (int)flag, (int)ecxvalue);
#else
	if (NULL == cpuinfo)  return;
	_asm{
		// load. 读取参数到寄存器.
		mov edi, cpuinfo;
		mov eax, flag;
		mov ecx, ecxvalue;
		// CPUID
		cpuid;
		// save. 将寄存器保存到CPUInfo
		mov[edi], eax;
		mov[edi + 4], ebx;
		mov[edi + 8], ecx;
		mov[edi + 12], edx;
	}
#endif
#endif
}

void get_cupid(unsigned int cpuinfo[4], unsigned int type)
{
#if defined(__GNUC__)// GCC
	__cpuid(type, cpuinfo[0], cpuinfo[1], cpuinfo[2], cpuinfo[3]);
#elif defined(_MSC_VER)// MSVC
#if _MSC_VER >= 1400 //VC2005才支持__cpuid
	__cpuid((int*)(void*)cpuinfo, (int)(type));
#else //其他使用getcpuidex
	getcpuidex(cpuinfo, type, 0);
#endif
#endif
}


void get_cupid_ex(char cpuid[CPU_ID_MAX_LEN])
{
	unsigned int cpuinfo[4];
	get_cupid(cpuinfo, 1);
	sprintf_s(cpuid, CPU_ID_MAX_LEN, "%08x-%08x-%08x-%08x", cpuinfo[0], cpuinfo[1], cpuinfo[2], cpuinfo[3] );
}

#if defined(_MSC_VER) // MSVC
BOOL __fastcall DoIdentify(HANDLE hPhysicalDriveIOCTL,
	PSENDCMDINPARAMS pSCIP,
	PSENDCMDOUTPARAMS pSCOP,
	BYTE btIDCmd,
	BYTE btDriveNum,
	PDWORD pdwBytesReturned)
{
	pSCIP->cBufferSize = IDENTIFY_BUFFER_SIZE;
	pSCIP->irDriveRegs.bFeaturesReg = 0;
	pSCIP->irDriveRegs.bSectorCountReg = 1;
	pSCIP->irDriveRegs.bSectorNumberReg = 1;
	pSCIP->irDriveRegs.bCylLowReg = 0;
	pSCIP->irDriveRegs.bCylHighReg = 0;

	pSCIP->irDriveRegs.bDriveHeadReg = (btDriveNum & 1) ? 0xB0 : 0xA0;
	pSCIP->irDriveRegs.bCommandReg = btIDCmd;
	pSCIP->bDriveNumber = btDriveNum;
	pSCIP->cBufferSize = IDENTIFY_BUFFER_SIZE;

	return DeviceIoControl(hPhysicalDriveIOCTL,
		SMART_RCV_DRIVE_DATA,
		(LPVOID)pSCIP,
		sizeof(SENDCMDINPARAMS)-1,
		(LPVOID)pSCOP,
		sizeof(SENDCMDOUTPARAMS)+IDENTIFY_BUFFER_SIZE - 1,
		pdwBytesReturned, NULL);
}
#endif

int get_hd_serial(char sn[SN_MAX_LEN])
{
#if defined(_MSC_VER) // MSVC
	const WORD IDE_ATAPI_IDENTIFY = 0xA1;   // 读取ATAPI设备的命令
	const WORD IDE_ATA_IDENTIFY = 0xEC;		// 读取ATA设备的命令 

	char szPath[MAX_PATH];
	sprintf_s(szPath, MAX_PATH, "\\\\.\\PHYSICALDRIVE%d", 0);

	HANDLE hFile = INVALID_HANDLE_VALUE;
	hFile = ::CreateFileA(szPath,
		GENERIC_READ | GENERIC_WRITE,
		FILE_SHARE_READ | FILE_SHARE_WRITE,
		NULL, OPEN_EXISTING,
		0, NULL);
	if (hFile == INVALID_HANDLE_VALUE)  return -1;

	DWORD dwBytesReturned;
	GETVERSIONINPARAMS gvopVersionParams;
	DeviceIoControl(hFile, 
		SMART_GET_VERSION,
		NULL,
		0,
		&gvopVersionParams,
		sizeof(gvopVersionParams),
		&dwBytesReturned, NULL);

	if(gvopVersionParams.bIDEDeviceMap <= 0) return -2;

	// IDE or ATAPI IDENTIFY cmd
	int btIDCmd = 0;
	SENDCMDINPARAMS InParams;
	int nDrive = 0;
	btIDCmd = (gvopVersionParams.bIDEDeviceMap >> nDrive & 0x10) ? IDE_ATAPI_IDENTIFY : IDE_ATA_IDENTIFY;


	// 输出参数
	BYTE btIDOutCmd[sizeof(SENDCMDOUTPARAMS)+IDENTIFY_BUFFER_SIZE - 1];

	if (DoIdentify(hFile,
		&InParams,
		(PSENDCMDOUTPARAMS)btIDOutCmd,
		(BYTE)btIDCmd, 
		(BYTE)nDrive, &dwBytesReturned) == FALSE)   return -3;
	::CloseHandle(hFile);

	DWORD dwDiskData[256];
	USHORT *pIDSector; // 对应结构IDSECTOR，见头文件

	pIDSector = (USHORT*)((SENDCMDOUTPARAMS*)btIDOutCmd)->bBuffer;
	for (int i = 0; i < 256; i++)   dwDiskData[i] = pIDSector[i];

	// 取系列号
	ZeroMemory(sn, SN_MAX_LEN);
	sprintf_s(sn, SN_MAX_LEN, ConvertToString(dwDiskData, 10, 19));

	// 取模型号
	//ZeroMemory(szModelNumber, sizeof(szModelNumber));
	//strcpy(szModelNumber, ConvertToString(dwDiskData, 27, 46));

	return (int)strlen(sn);
#endif
}

int get_mac_address( char sn[SN_MAX_LEN] )
{
	ZeroMemory(sn, SN_MAX_LEN);

	IP_ADAPTER_INFO AdapterInfo[16];       // Allocate information
	// for up to 16 NICs
	DWORD dwBufLen = sizeof(AdapterInfo);  // Save memory size of buffer

	DWORD dwStatus = GetAdaptersInfo(		// Call GetAdapterInfo
		AdapterInfo,						// [out] buffer to receive data
		&dwBufLen);							// [in] size of receive data buffer
	assert(dwStatus == ERROR_SUCCESS);		// Verify return value is
	// valid, no buffer overflow

	PIP_ADAPTER_INFO pAdapterInfo = AdapterInfo; // Contains pointer to
	// current adapter info
	do {
		if (pAdapterInfo->Address[5] != 0 || pAdapterInfo->Address[4] != 0
			&& pAdapterInfo->Address[3] != 0 && pAdapterInfo->Address[2] != 0)
		{
			sprintf_s(sn, SN_MAX_LEN, "%02x-%02x-%02x-%02x-%02x-%02x",
				pAdapterInfo->Address[0],
				pAdapterInfo->Address[1],
				pAdapterInfo->Address[2],
				pAdapterInfo->Address[3],
				pAdapterInfo->Address[4],
				pAdapterInfo->Address[5]
				);
			break;
		}
		pAdapterInfo = pAdapterInfo->Next;    // Progress through linked list
	} while (pAdapterInfo);                    // Terminate if last adapter

	return strlen(sn);
}
