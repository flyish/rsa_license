//--------------------------------------------------------------------
// 文件名:      image_helper.h
// 内  容:      映像文件辅助函数
// 说  明:
// 创建日期:    2018年06月05日
// 创建人:      lihl
//--------------------------------------------------------------------
#ifndef __IMAGE_HELPER_H__
#define __IMAGE_HELPER_H__

// https://blog.csdn.net/iiprogram/article/details/2298850

// 查找程序段信息， 返回位置和段大小
/*
#pragma code_seg(".scode")
void some_function(){}
#pragma code_seg()
#pragma comment(linker, "/SECTION:.scode,ERW")

Windows提供了一个API用于获得应用程序的基地址，这个API就是GetModuleHandle()，它的函数原型是：
HMODULE GetModuleHandle(LPCTSTR lpModuleName);
try
{
bool bFind = GetSectionPointer((void *)hImageBase,".scode",&pSecAddr,&dwSecSize);
if(!bFind || !pSecAddr)
throw "Not find special section!";

//注意，解密和加密函数也是重要的函数，这两个函数的调用最好放在距离CalcRegCode()函数调用
//远一点的位置，避免被发现
DecryptBlock(pSecAddr,dwSecSize,0x5A);//首先解密代码段

CalcRegCode("system",szBuff,128);//调用注册码计算函数

EncryptBlock(pSecAddr,dwSecSize,0x5A);//调用后加密代码段
}
....//异常处理
*/
bool image_find_section_pointer( void* pModuleBase, const char* lpszSectionName, void** ppPos, size_t* lpSize );

// 虚拟地址转换文件偏移地址
/*
代码内存虚拟地址 - 代码段内存虚拟地址 = 代码文件偏移量 - 代码段的文件偏移
转换这个等式就可以得到文件偏移的计算公式：
代码文件偏移量 = 代码内存虚拟地址 - (代码段内存虚拟地址 - 代码段的文件偏移)
*/
int image_va_to_file_offset(void* pModuleBase, void* pVA);

// 查找指定代码中代码标识
/*
C/C++语言中将常数赋值给某个变量的简单赋值语句，通常可以被翻译成一条简单的汇编代码，以下面的C/C++代码为例：
DWORD dwSignVar = 0;//定义一个全局变量
dwSignVar = 0x5A5A5A5A;
这条赋值语句汇编成机器代码后就是：
mov DWORD PTR [AAAAAAAAH], 5A5A5A5AH
最终生成的机器码就是：C7 05 AA AA AA AA 5A 5A 5A 5A，C7 05是mov指令的机器码，紧跟其后的四个字节是mov指令的第一个操作数，
就是变量的dwSignVar的地址AAAAAAAA，再后面的四个字节是mov指令的第二个操作数，也就是常数0x5A5A5A5A。
void SomeFunction()
{
......
dwSignVar = 0x5A5A5A5A;
......//关键代码块
dwSignVar2 = 0x61616161;
}
那么就可以这样找到它的开始位置：
int nStartPos = FindCodeTag((void *)SomeFunction,&dwSignVar,0x5A5A5A5A,1000);//1000是个大致估计的值
nStartPos += 10;//10 是特征代码序列（也就是mov指令）的长度
返回值只是特征代码序列的开始位置，还要向后偏移10各字节（这条mov指令的长度）才是代码块的真正开始位置，这里的搜索长度1000只是一个估计值
法可以得到另一个特征代码序列的开始位置（也就是关键代码块的结束位置）：
int nEndPos = FindCodeTag((void *)SomeFunction,&dwSignVar2,0x61616161,1000);
*/
int image_find_code_tag(void *pStartAddr, unsigned long *pTagLoc, unsigned long lTagValue, int nSerachLength);
#endif