//--------------------------------------------------------------------
// �ļ���:      time_utils.h
// ��  ��:      ʱ����صĸ�������
// ˵  ��:
// ��������:    2018��06��05��
// ������:      lihl
//--------------------------------------------------------------------
#ifndef __TIME_UTILS_H__
#define __TIME_UTILS_H__

#include <stdint.h>

#define	TIME_ONE_DAY_SECONDS	86400
#define	TIME_ONE_HOUR_SECONDS	3600

#define STR_TIME_ONLY_DATE		1
#define STR_TIME_FULL_DATE		0

// ��ȡ��ǰutcʱ��(s)
time_t time_get_utc_time();

// ��ȡ��ǰutcʱ��(ms)
time_t time_get_utc_time_ex();

//��ȡ�������ʱ���(����ʱ��)
int64_t time_get_current_zero_unix_timestamp(int nTimezone = 8);

//��ȡָ��ʱ������ʱ���(����ʱ��)
int64_t time_get_zero_unix_timestamp(int64_t nTimestamp, int nTimezone = 8);

// ȡ����ʱ���������� ��������
int time_get_date(int* year, int* month, int* day);
// ȡȡ����ָ��������(ʱ���s) ��������
int time_get_date_ex(time_t timestamp, int* year, int* month, int* day);

// ȡȡ����ʱ��ʱ���� ��������
int time_get_time(int* hour, int* minute, int* second);
int time_get_time_ex(time_t timestamp, int* hour, int* minute, int* second);

// ȡ����ʱ���������� ʱ���� ��������
int time_get_date_time(int* year, int* month, int* day, int* hour, int* minute, int* second);
int time_get_date_time_ex(time_t timestamp, int* year, int* month, int* day, int* hour, int* minute, int* second);

// ������ת��s
time_t time_make_time(int year, int month, int day, int hour, int minute, int second);
// ������ת��ms
time_t time_make_time_ex(int year, int month, int day, int hour, int minute, int second, int millseconds);
// ��ʽ������ʱ���ַ���ת��utcʱ��(s) �����Ǳ�׼��yyyy-mm-dd hour:min:sec �� yyyy-mm-dd  
// nFlag: STR_TIME_ONLY_DATE || STR_TIME_FULL_DATE
time_t time_make_time_string(const char* strtime, int flag);

// ��ʽ��Ϊ����ʱ��yyyy-mm-dd hour:min:sec [timestamp ��λs)
void time_format_local_date_time(time_t timestamp, char* strtime, int size);
// ��ʽ��Ϊ����ʱ��yyyy-mm-dd [timestamp ��λs)
void time_format_local_date(time_t timestamp, char* strtime, int size);
// ��ʽ������ʱ��Ϊhour:min:sec [timestamp ��λs)
void time_format_local_time(time_t timestamp, char* strtime, int size);

// �ж��Ƿ�Ϊ����
bool time_is_leap_year(int year);
// ��ȡ��ǰ�µ�����
int time_get_days_of_month(int year, int month);
// ��ȡ���������
int time_get_days_of_year(int year);

// �������������time1-time2 ��λ(s)
int time_subtract_days(time_t time1, time_t time2);
#endif