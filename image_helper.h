//--------------------------------------------------------------------
// �ļ���:      image_helper.h
// ��  ��:      ӳ���ļ���������
// ˵  ��:
// ��������:    2018��06��05��
// ������:      lihl
//--------------------------------------------------------------------
#ifndef __IMAGE_HELPER_H__
#define __IMAGE_HELPER_H__

// https://blog.csdn.net/iiprogram/article/details/2298850

// ���ҳ������Ϣ�� ����λ�úͶδ�С
/*
#pragma code_seg(".scode")
void some_function(){}
#pragma code_seg()
#pragma comment(linker, "/SECTION:.scode,ERW")

Windows�ṩ��һ��API���ڻ��Ӧ�ó���Ļ���ַ�����API����GetModuleHandle()�����ĺ���ԭ���ǣ�
HMODULE GetModuleHandle(LPCTSTR lpModuleName);
try
{
bool bFind = GetSectionPointer((void *)hImageBase,".scode",&pSecAddr,&dwSecSize);
if(!bFind || !pSecAddr)
throw "Not find special section!";

//ע�⣬���ܺͼ��ܺ���Ҳ����Ҫ�ĺ����������������ĵ�����÷��ھ���CalcRegCode()��������
//Զһ���λ�ã����ⱻ����
DecryptBlock(pSecAddr,dwSecSize,0x5A);//���Ƚ��ܴ����

CalcRegCode("system",szBuff,128);//����ע������㺯��

EncryptBlock(pSecAddr,dwSecSize,0x5A);//���ú���ܴ����
}
....//�쳣����
*/
bool image_find_section_pointer( void* pModuleBase, const char* lpszSectionName, void** ppPos, size_t* lpSize );

// �����ַת���ļ�ƫ�Ƶ�ַ
/*
�����ڴ������ַ - ������ڴ������ַ = �����ļ�ƫ���� - ����ε��ļ�ƫ��
ת�������ʽ�Ϳ��Եõ��ļ�ƫ�Ƶļ��㹫ʽ��
�����ļ�ƫ���� = �����ڴ������ַ - (������ڴ������ַ - ����ε��ļ�ƫ��)
*/
int image_va_to_file_offset(void* pModuleBase, void* pVA);

// ����ָ�������д����ʶ
/*
C/C++�����н�������ֵ��ĳ�������ļ򵥸�ֵ��䣬ͨ�����Ա������һ���򵥵Ļ����룬�������C/C++����Ϊ����
DWORD dwSignVar = 0;//����һ��ȫ�ֱ���
dwSignVar = 0x5A5A5A5A;
������ֵ�����ɻ����������ǣ�
mov DWORD PTR [AAAAAAAAH], 5A5A5A5AH
�������ɵĻ�������ǣ�C7 05 AA AA AA AA 5A 5A 5A 5A��C7 05��movָ��Ļ����룬���������ĸ��ֽ���movָ��ĵ�һ����������
���Ǳ�����dwSignVar�ĵ�ַAAAAAAAA���ٺ�����ĸ��ֽ���movָ��ĵڶ�����������Ҳ���ǳ���0x5A5A5A5A��
void SomeFunction()
{
......
dwSignVar = 0x5A5A5A5A;
......//�ؼ������
dwSignVar2 = 0x61616161;
}
��ô�Ϳ��������ҵ����Ŀ�ʼλ�ã�
int nStartPos = FindCodeTag((void *)SomeFunction,&dwSignVar,0x5A5A5A5A,1000);//1000�Ǹ����¹��Ƶ�ֵ
nStartPos += 10;//10 �������������У�Ҳ����movָ��ĳ���
����ֵֻ�������������еĿ�ʼλ�ã���Ҫ���ƫ��10���ֽڣ�����movָ��ĳ��ȣ����Ǵ�����������ʼλ�ã��������������1000ֻ��һ������ֵ
�����Եõ���һ�������������еĿ�ʼλ�ã�Ҳ���ǹؼ������Ľ���λ�ã���
int nEndPos = FindCodeTag((void *)SomeFunction,&dwSignVar2,0x61616161,1000);
*/
int image_find_code_tag(void *pStartAddr, unsigned long *pTagLoc, unsigned long lTagValue, int nSerachLength);
#endif