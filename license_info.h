//--------------------------------------------------------------------
// �ļ���:      license_info.h
// ��  ��:      lic��֤��Ϣ����
// ˵  ��:
// ��������:    2018��06��05��
// ������:      lihl
//--------------------------------------------------------------------

#ifndef __LICENSE_IFNO_H__
#define __LICENSE_IFNO_H__

#define PRODUCT_NAME_LEN 256

#pragma pack(push, 1)
struct license_info
{
	unsigned long long  start_time_stamp;
	unsigned long long	expired_time_stamp;

	char product_name[PRODUCT_NAME_LEN];
	unsigned int checksum;
	unsigned int sn_size;
	char		 sn[1];
};
#pragma pack(pop)

#endif