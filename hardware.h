//--------------------------------------------------------------------
// �ļ���:      hardware.h
// ��  ��:      ��ȡӲ����Ϣ
// ˵  ��:
// ��������:    2018��06��04��
// ������:      lihl
//--------------------------------------------------------------------

#ifndef __HARD_WARE_H_
#define __HARD_WARE_H_

#define CPU_ID_MAX_LEN		36
#define SN_MAX_LEN	256

void get_cupid(unsigned int cpuinfo[4], unsigned int type);

// ��ȡcpuid ��16����-������: xxxxxxxx-xxxxxxxx-xxxxxxxx-xxxxxxxx + '\0' �ܹ�36���ֽ�
void get_cupid_ex(char cpuid[CPU_ID_MAX_LEN]);

// ��ȡӲ����ţ��256���� ����ʵ�ʳ���
int get_hd_serial(char sn[SN_MAX_LEN]);

// ��ȡmac��ַ
int get_mac_address(char sn[SN_MAX_LEN]);

#endif