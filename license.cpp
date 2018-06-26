#include "stdafx.h"
#include "license.h"
#include "hardware.h"
#include <stdio.h>
#include <string.h>
#include <algorithm>
#include "time_utils.h"
#include "image_helper.h"
#include <string>
#include "rsa_helper.h"
#include <fstream>
#include <iostream>
#include <sstream>

license::license() : m_pInfo(NULL)
{
}


license::~license()
{
	if (NULL != m_pInfo)
	{
		free(m_pInfo);
		m_pInfo = NULL;
	}
}

bool license::Generator(unsigned long long begin, unsigned long long end, const char* pszName)
{
	if (NULL != m_pInfo)
	{
		free( m_pInfo );
		m_pInfo = NULL;
	}

	unsigned int snSize = CalcSN(NULL);
	m_pInfo = (license_info*)malloc(sizeof(license_info)+snSize);
	memset(m_pInfo, 0, sizeof(license_info)+snSize);
	m_pInfo->start_time_stamp = begin;
	m_pInfo->expired_time_stamp = end;
	if (NULL != pszName)
	{
		strcpy_s(m_pInfo->product_name, PRODUCT_NAME_LEN, pszName);
	}
	m_pInfo->sn_size = CalcSN(m_pInfo->sn);
	m_pInfo->checksum = GetSum();

	return true;
}

static unsigned long nSignVar1 = 0;
static unsigned long nSignVar2 = 0;
bool check_license(const license* pLic, license_info* info, bool bSN)
{
	nSignVar1 = 0x5A5A5A5A;
	int nStep = 0;
	while (true)
	{
		switch (nStep)
		{
		case 0:
			if (NULL == info)
			{
				nStep += 200;
			}
			++nStep;
			break;
		case 10:
		{
				   int checksum = pLic->GetSum();
				   if (checksum != info->checksum)
				   {
					   nStep += 199;
				   }
		}
			nStep += 3;
			break;
		case 50:
			if (info->sn_size > 0 && bSN)
			{
				char sn[SN_MAX_LEN] = {0};
				unsigned int snSize = pLic->CalcSN(sn);
				if (memcmp(sn, info->sn, std::max(info->sn_size, snSize)))
				{
					nStep += 150;
				}
			}
			nStep += 13;
			break;
		case 199:
			{
				unsigned long long tNow_ = (unsigned long long)time_get_utc_time();
				if (tNow_ >= info->start_time_stamp && tNow_ <= info->expired_time_stamp)
				{
					return true;
				}
			}
			nStep += 111;
			break;
		case 1000:
			throw std::string();
		default:
			break;
		}

		++nStep;
	}
	nSignVar2 = 0x61616161;
	return false;
}

bool license::Check(license_info* info, bool bSN) const
{
	return check_license(this, info, bSN);
}

bool license::CheckSum(int nSum) const
{
	return nSum == GetSum();
}

int license::GetSum() const
{
	int nStartPos = image_find_code_tag((void*)check_license, &nSignVar1, 0x5A5A5A5A, 1024);
	int nEndPos = image_find_code_tag((void*)check_license, &nSignVar2, 0x61616161, 1024);

	if (nStartPos < 0 || nEndPos < 0)
	{
		return 0;
	}

	int nSum = 0;
	unsigned char* pAddr = (unsigned char*)check_license;
	for (int i = nStartPos; i < nEndPos; ++i)
	{
		nSum += *pAddr;
		++pAddr;
	}

	return nSum;
}

license_info* license::GetLicenseInfo()
{
	return m_pInfo;
}

license_info* license::DetachInfo()
{
	license_info* pTemp = m_pInfo;
	m_pInfo = NULL;
	return pTemp;
}

bool license::Store(const char* pszLicFile, const char* pszPubFile, 
				const unsigned char* seed, size_t seedLen)
{
	if (NULL == m_pInfo)
	{
		return false;
	}

	std::string result = RsaBase64().encrypt_data_by_file(pszPubFile,  seed, seedLen,
								(unsigned char*)m_pInfo, sizeof(license_info) + m_pInfo->sn_size );
	std::ofstream output;
	output.open(pszLicFile, std::ios_base::binary);
	if (!output.good())
	{
		output.close();
		return false;
	}

	output.write( result.c_str(), result.size() );
	output.close();
	return true;
}

bool license::Load(const char* pszLicFile, const char* pszPrivFile, const unsigned char* seed, size_t seedLen)
{
	std::ifstream input;
	input.open(pszLicFile, std::ios_base::binary);
	if (!input.good())
	{
		return false;
	}

	/*
	std::stringstream buffer;
	buffer << input.rdbuf();
	input.close();
	*/
	input.seekg(0, std::ios::end);
	size_t nLength = (size_t)input.tellg();
	input.seekg(0, std::ios::beg);
	char* enc_data = new char[nLength];
	input.read(enc_data, nLength);
	input.close();

	if (NULL != m_pInfo)
	{
		free( m_pInfo );
		m_pInfo = NULL;
	}

	std::string result = RsaBase64().decrypt_data_by_file(pszPrivFile, seed, seedLen, 
											(unsigned char*)enc_data, nLength );
	delete enc_data;

	if (result.size() < sizeof(license_info))
	{
		return false;
	}

	m_pInfo = (license_info*)malloc(result.size());
	memcpy(m_pInfo, result.c_str(), result.size());
	return true;
}

unsigned int license::CalcSN( char* sn ) const
{
	/*
	if (NULL == sn)
	{
		// 计算长度
		return CPU_ID_MAX_LEN;
	}


	get_cupid_ex(sn);
	return CPU_ID_MAX_LEN;
	*/
	if (NULL == sn)
	{
		// 计算长度
		return SN_MAX_LEN;
	}

	return get_mac_address(sn);
}
