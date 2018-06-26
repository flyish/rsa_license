#include "stdafx.h"
#include "time_utils.h"
#include <time.h>
#include <stdio.h>
#include <wchar.h>
#include <sys\timeb.h>
#include <string.h>

time_t time_get_utc_time()
{
	return time(NULL);
}

time_t time_get_utc_time_ex()
{
	struct timeb tb;
	ftime(&tb);

	int64_t nMilliTime = tb.time * 1000 + tb.millitm;
	return nMilliTime;
}

int64_t time_get_current_zero_unix_timestamp(int nTimezone /*= 8*/)
{
	time_t nCurTime = ::time(NULL);
	return time_get_zero_unix_timestamp(nCurTime, nTimezone);
}

int64_t time_get_zero_unix_timestamp(int64_t nTimestamp, int nTimezone /*= 8*/)
{
	return nTimestamp - (nTimestamp % TIME_ONE_DAY_SECONDS + nTimezone * TIME_ONE_HOUR_SECONDS) % TIME_ONE_DAY_SECONDS;
}

int time_get_date(int* year, int* month, int* day)
{
	return time_get_date_ex(time(NULL), year, month, day);
}

int time_get_date_ex(time_t timestamp, int* year, int* month, int* day)
{
	time_t tNow = time(NULL);
	struct tm* tmp = localtime(&tNow);

	*year = tmp->tm_year + 1900;
	*month = tmp->tm_mon + 1;
	*day = tmp->tm_mday;

	return tmp->tm_wday;
}


int time_get_time(int* hour, int* minute, int* second)
{
	time_t tNow = time(NULL);
	return time_get_time_ex(tNow, hour, minute, second);
}

int time_get_time_ex(time_t timestamp, int* hour, int* minute, int* second)
{
	struct tm* tmp = localtime(&timestamp);

	*hour = tmp->tm_hour;
	*minute = tmp->tm_min;
	*second = tmp->tm_sec;

	return tmp->tm_wday;
}

int time_get_date_time(int* year, int* month, int* day, int* hour, int* minute, int* second)
{
	time_t tNow = time(NULL);
	return time_get_date_time_ex(tNow, year, month, day, hour, minute, second);
}

int time_get_date_time_ex(time_t timestamp, int* year, int* month, int* day, int* hour, int* minute, int* second)
{
	struct tm* tmp = localtime(&timestamp);

	*year = tmp->tm_year + 1900;
	*month = tmp->tm_mon + 1;
	*day = tmp->tm_mday;

	*hour = tmp->tm_hour;
	*minute = tmp->tm_min;
	*second = tmp->tm_sec;

	return tmp->tm_wday;
}

time_t time_make_time(int year, int month, int day, int hour, int minute, int second)
{
	struct tm tm = { 0 };
	tm.tm_year = year - 1900;
	tm.tm_mon = month - 1;
	tm.tm_mday = day;
	tm.tm_hour = hour;
	tm.tm_min = minute;
	tm.tm_sec = second;

	return mktime(&tm);
}

time_t time_make_time_ex(int year, int month, int day, int hour, int minute, int second, int millseconds)
{
	return time_make_time(year, month, day, hour, minute, second) * 1000 + millseconds;
}

time_t time_make_time_string(const char* strtime, int flag)
{
	int year = 0, month = 0, day = 0, hour = 0, min = 0, sec = 0;

	if (strtime != NULL && strlen(strtime) > 6)
	{
		if (flag == STR_TIME_ONLY_DATE)
		{
			sscanf(strtime, "%d-%02d-%02d", &year, &month, &day);
		}
		else
		{
			sscanf(strtime, "%d-%02d-%02d %02d:%02d:%02d", &year, &month, &day, &hour, &min, &sec);
		}
	}
	return time_make_time(year, month, day, hour, min, sec);
}

void time_format_local_date_time(time_t timestamp, char* strtime, int size)
{
	int year = 0, month = 0, day = 0, hour = 0, min = 0, sec = 0;
	time_get_date_time_ex( timestamp, &year, &month, &day, &hour, &min, &sec);
	sprintf_s(strtime, size, "%d-%02d-%02d %02d:%02d:%02d", year, month, day, hour, min, sec);
}

void time_format_local_date(time_t timestamp, char* strtime, int size)
{
	int year = 0, month = 0, day = 0;
	time_get_date(&year, &month, &day);
	sprintf_s(strtime, size, "%d-%02d-%02d", year, month, day);
}

void time_format_local_time(time_t timestamp, char* strtime, int size)
{
	int hour = 0, min = 0, sec = 0;
	time_get_time( &hour, &min, &sec);
	sprintf_s(strtime, size, "%02d:%02d:%02d", hour, min, sec);
}

bool time_is_leap_year(int year)
{
	if (year % 4 != 0)
		return false;
	if (year % 400 == 0)
		return true;
	if (year % 100 == 0)
		return false;
	return true;
}

int time_get_days_of_month(int year, int month)
{
	const int days_in_months[12] = { 31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31 };
	int days = days_in_months[month];
	// 润年的2月29天
	if (month == 1 && time_is_leap_year(year))
		days += 1;
	return days;
}

int time_get_days_of_year(int year)
{
	if (time_is_leap_year(year))
	{
		return 366;
	}
	else
	{
		return 365;
	}
}

int time_subtract_days(time_t time1, time_t time2)
{
	const int INVALID_DAY_CNT = 2147483648;
	const int LOCAL_TIME_BEGIN_YEAR = 1900; // 本地时间起始年份

	if (time1 == time2)
	{
		return 0;
	}
	if (time1 == 0 || time2 == 0)
	{
		return INVALID_DAY_CNT;
	}
	tm t1;
	if (::localtime_s(&t1, &time1) != 0)
	{
		return INVALID_DAY_CNT;
	}

	tm t2;
	if (::localtime_s(&t2, &time2) != 0)
	{
		return INVALID_DAY_CNT;
	}

	if (t1.tm_year == t2.tm_year)
	{
		return (t1.tm_yday - t2.tm_yday);
	}
	else if (t1.tm_year < t2.tm_year)
	{
		int nDays = t1.tm_yday - t2.tm_yday;

		for (int i = t1.tm_year; i < t2.tm_year; ++i)
		{
			nDays -= time_get_days_of_year(i + LOCAL_TIME_BEGIN_YEAR);
		}

		return nDays;
	}
	else
	{
		int nDays = t1.tm_yday - t2.tm_yday;

		for (int i = t2.tm_year; i < t1.tm_year; ++i)
		{
			nDays += time_get_days_of_year(i + LOCAL_TIME_BEGIN_YEAR);
		}

		return nDays;
	}
}

