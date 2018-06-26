//--------------------------------------------------------------------
// 文件名:      hardware.h
// 内  容:      获取硬件信息
// 说  明:
// 创建日期:    2018年06月04日
// 创建人:      lihl
//--------------------------------------------------------------------

#ifndef __HARD_WARE_H_
#define __HARD_WARE_H_

#define CPU_ID_MAX_LEN		36
#define SN_MAX_LEN	256

void get_cupid(unsigned int cpuinfo[4], unsigned int type);

// 获取cpuid 按16进制-返回如: xxxxxxxx-xxxxxxxx-xxxxxxxx-xxxxxxxx + '\0' 总共36个字节
void get_cupid_ex(char cpuid[CPU_ID_MAX_LEN]);

// 获取硬件序号，最长256个， 返回实际长度
int get_hd_serial(char sn[SN_MAX_LEN]);

// 获取mac地址
int get_mac_address(char sn[SN_MAX_LEN]);

#endif