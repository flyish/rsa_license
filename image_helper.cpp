#include "stdafx.h"
#include "image_helper.h"
#include <windows.h>

bool image_find_section_pointer(void* pModuleBase, const char* lpszSectionName, void** ppPos, size_t* lpSize)
{
	IMAGE_DOS_HEADER *pDosHead;
	IMAGE_FILE_HEADER *pPEHead;
	IMAGE_SECTION_HEADER *pSection;

	*ppPos = NULL;
	*lpSize = 0;

	if (::IsBadReadPtr(pModuleBase, sizeof(IMAGE_DOS_HEADER)) || ::IsBadReadPtr(lpszSectionName, 8))
		return false;

	if (strlen(lpszSectionName) >= 16)
		return false;

	char szSecName[16];
	memset(szSecName, 0, 16);
	strncpy(szSecName, lpszSectionName, IMAGE_SIZEOF_SHORT_NAME);

	unsigned char *pszModuleBase = (unsigned char *)pModuleBase;
	pDosHead = (IMAGE_DOS_HEADER *)pszModuleBase;
	//跳过DOS头不和DOS stub代码，定位到PE标志位置
	DWORD Signature = *(DWORD *)(pszModuleBase + pDosHead->e_lfanew);
	if (Signature != IMAGE_NT_SIGNATURE) //"PE/0/0"
		return false;

	//定位到PE header
	pPEHead = (IMAGE_FILE_HEADER *)(pszModuleBase + pDosHead->e_lfanew + sizeof(DWORD));
	int nSizeofOptionHeader;
	if (pPEHead->SizeOfOptionalHeader == 0)
		nSizeofOptionHeader = sizeof(IMAGE_OPTIONAL_HEADER);
	else
		nSizeofOptionHeader = pPEHead->SizeOfOptionalHeader;

	bool bFind = false;
	//跳过PE header和Option Header，定位到Section表位置
	pSection = (IMAGE_SECTION_HEADER *)((unsigned char *)pPEHead + sizeof(IMAGE_FILE_HEADER)+nSizeofOptionHeader);
	for (int i = 0; i < pPEHead->NumberOfSections; i++)
	{
		if (!strncmp(szSecName, (const char*)pSection[i].Name, IMAGE_SIZEOF_SHORT_NAME)) //比较段名称
		{
			*ppPos = (void *)(pszModuleBase + pSection[i].VirtualAddress);	//计算实际虚地址
			*lpSize = pSection[i].Misc.VirtualSize;							//实际大小
			bFind = true;
			break;
		}
	}

	return bFind;
}

int image_va_to_file_offset(void* pModuleBase, void* pVA)
{
	IMAGE_DOS_HEADER *pDosHead;
	IMAGE_FILE_HEADER *pPEHead;
	IMAGE_SECTION_HEADER *pSection;

	if (::IsBadReadPtr(pModuleBase, sizeof(IMAGE_DOS_HEADER)) || ::IsBadReadPtr(pVA, 4))
		return -1;

	unsigned char *pszModuleBase = (unsigned char *)pModuleBase;
	pDosHead = (IMAGE_DOS_HEADER *)pszModuleBase;
	//跳过DOS头不和DOS stub代码，定位到PE标志位置
	DWORD Signature = *(DWORD *)(pszModuleBase + pDosHead->e_lfanew);
	if (Signature != IMAGE_NT_SIGNATURE) //"PE/0/0"
		return -1;

	unsigned char *pszVA = (unsigned char *)pVA;
	int nFileOffset = -1;

	//定位到PE header
	pPEHead = (IMAGE_FILE_HEADER *)(pszModuleBase + pDosHead->e_lfanew + sizeof(DWORD));
	int nSizeofOptionHeader;
	if (pPEHead->SizeOfOptionalHeader == 0)
		nSizeofOptionHeader = sizeof(IMAGE_OPTIONAL_HEADER);
	else
		nSizeofOptionHeader = pPEHead->SizeOfOptionalHeader;

	//跳过PE header和Option Header，定位到Section表位置
	pSection = (IMAGE_SECTION_HEADER *)((unsigned char *)pPEHead + sizeof(IMAGE_FILE_HEADER)+nSizeofOptionHeader);
	for (int i = 0; i < pPEHead->NumberOfSections; i++)
	{
		if (!strncmp(".text", (const char*)pSection[i].Name, 5)) //比较段名称
		{
			//代码文件偏移量 = 代码内存虚拟地址 - (代码段内存虚拟地址 - 代码段的文件偏移)
			nFileOffset = (int)( pszVA - (pszModuleBase + pSection[i].VirtualAddress - pSection[i].PointerToRawData) );
			break;
		}
	}

	return nFileOffset;
}

int image_find_code_tag(void *pStartAddr, unsigned long *pTagLoc, unsigned long lTagValue, int nSerachLength)
{
	int nPos = -1;
	int i = 0;
	unsigned char *pAddr = (unsigned char *)pStartAddr;
	while (i < nSerachLength)
	{
		if ((*pAddr == 0xC7) && (*(pAddr + 1) == 0x05))//查找mov指令
		{
			unsigned long *Loc = (unsigned long *)((unsigned char*)pAddr + 2);
			if (*Loc == (unsigned long)pTagLoc)//此处的数据*Loc就是全局静态变量的地址
			{
				unsigned long *Val = (unsigned long *)((unsigned char*)pAddr + 6);
				if (*Val == lTagValue)//此处的数据*Val就是常数lTagValue值
				{
					nPos = i;
					break;//find tag
				}
			}
		}
		pAddr++;
		i++;
	}

	return nPos;
}
