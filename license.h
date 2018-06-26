//--------------------------------------------------------------------
// 文件名:      license.h
// 内  容:      lic验证处理类
// 说  明:
// 创建日期:    2018年06月04日
// 创建人:      lihl
//--------------------------------------------------------------------
#ifndef __LICENSE_H__
#define __LICENSE_H__
#include "license_info.h"

class license
{
public:
	license();
	~license();

	bool Generator( unsigned long long begin, unsigned long long end, const char* pszName );
	bool Check(license_info* info, bool bSN) const;
	bool CheckSum( int nSum ) const;
	int	 GetSum() const;
	license_info* GetLicenseInfo();
	license_info* DetachInfo();
	bool Store(const char* pszLicFile, const char* pszPubFile, const unsigned char* seed, size_t seedLen);
	bool Load(const char* pszLicFile, const char* pszPrivFile, const unsigned char* seed, size_t seedLen);
	unsigned int CalcSN(char* sn) const;

	license_info* m_pInfo;
};


#endif