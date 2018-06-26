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
	//����DOSͷ����DOS stub���룬��λ��PE��־λ��
	DWORD Signature = *(DWORD *)(pszModuleBase + pDosHead->e_lfanew);
	if (Signature != IMAGE_NT_SIGNATURE) //"PE/0/0"
		return false;

	//��λ��PE header
	pPEHead = (IMAGE_FILE_HEADER *)(pszModuleBase + pDosHead->e_lfanew + sizeof(DWORD));
	int nSizeofOptionHeader;
	if (pPEHead->SizeOfOptionalHeader == 0)
		nSizeofOptionHeader = sizeof(IMAGE_OPTIONAL_HEADER);
	else
		nSizeofOptionHeader = pPEHead->SizeOfOptionalHeader;

	bool bFind = false;
	//����PE header��Option Header����λ��Section��λ��
	pSection = (IMAGE_SECTION_HEADER *)((unsigned char *)pPEHead + sizeof(IMAGE_FILE_HEADER)+nSizeofOptionHeader);
	for (int i = 0; i < pPEHead->NumberOfSections; i++)
	{
		if (!strncmp(szSecName, (const char*)pSection[i].Name, IMAGE_SIZEOF_SHORT_NAME)) //�Ƚ϶�����
		{
			*ppPos = (void *)(pszModuleBase + pSection[i].VirtualAddress);	//����ʵ�����ַ
			*lpSize = pSection[i].Misc.VirtualSize;							//ʵ�ʴ�С
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
	//����DOSͷ����DOS stub���룬��λ��PE��־λ��
	DWORD Signature = *(DWORD *)(pszModuleBase + pDosHead->e_lfanew);
	if (Signature != IMAGE_NT_SIGNATURE) //"PE/0/0"
		return -1;

	unsigned char *pszVA = (unsigned char *)pVA;
	int nFileOffset = -1;

	//��λ��PE header
	pPEHead = (IMAGE_FILE_HEADER *)(pszModuleBase + pDosHead->e_lfanew + sizeof(DWORD));
	int nSizeofOptionHeader;
	if (pPEHead->SizeOfOptionalHeader == 0)
		nSizeofOptionHeader = sizeof(IMAGE_OPTIONAL_HEADER);
	else
		nSizeofOptionHeader = pPEHead->SizeOfOptionalHeader;

	//����PE header��Option Header����λ��Section��λ��
	pSection = (IMAGE_SECTION_HEADER *)((unsigned char *)pPEHead + sizeof(IMAGE_FILE_HEADER)+nSizeofOptionHeader);
	for (int i = 0; i < pPEHead->NumberOfSections; i++)
	{
		if (!strncmp(".text", (const char*)pSection[i].Name, 5)) //�Ƚ϶�����
		{
			//�����ļ�ƫ���� = �����ڴ������ַ - (������ڴ������ַ - ����ε��ļ�ƫ��)
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
		if ((*pAddr == 0xC7) && (*(pAddr + 1) == 0x05))//����movָ��
		{
			unsigned long *Loc = (unsigned long *)((unsigned char*)pAddr + 2);
			if (*Loc == (unsigned long)pTagLoc)//�˴�������*Loc����ȫ�־�̬�����ĵ�ַ
			{
				unsigned long *Val = (unsigned long *)((unsigned char*)pAddr + 6);
				if (*Val == lTagValue)//�˴�������*Val���ǳ���lTagValueֵ
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
