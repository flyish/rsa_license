//--------------------------------------------------------------------
// 文件名:      time_utils.h
// 内  容:      时间相关的辅助函数
// 说  明:
// 创建日期:    2018年06月05日
// 创建人:      lihl
//--------------------------------------------------------------------
#ifndef __TIME_UTILS_H__
#define __TIME_UTILS_H__

#include <stdint.h>

#define	TIME_ONE_DAY_SECONDS	86400
#define	TIME_ONE_HOUR_SECONDS	3600

#define STR_TIME_ONLY_DATE		1
#define STR_TIME_FULL_DATE		0

// 获取当前utc时间(s)
time_t time_get_utc_time();

// 获取当前utc时间(ms)
time_t time_get_utc_time_ex();

//获取当天零点时间戳(北京时间)
int64_t time_get_current_zero_unix_timestamp(int nTimezone = 8);

//获取指定时间戳零点时间戳(北京时间)
int64_t time_get_zero_unix_timestamp(int64_t nTimestamp, int nTimezone = 8);

// 取本地时间周年月日 返回星期
int time_get_date(int* year, int* month, int* day);
// 取取本地指定年月日(时间戳s) 返回星期
int time_get_date_ex(time_t timestamp, int* year, int* month, int* day);

// 取取本地时间时分秒 返回星期
int time_get_time(int* hour, int* minute, int* second);
int time_get_time_ex(time_t timestamp, int* hour, int* minute, int* second);

// 取本地时间周年月日 时分秒 返回星期
int time_get_date_time(int* year, int* month, int* day, int* hour, int* minute, int* second);
int time_get_date_time_ex(time_t timestamp, int* year, int* month, int* day, int* hour, int* minute, int* second);

// 年月日转成s
time_t time_make_time(int year, int month, int day, int hour, int minute, int second);
// 年月日转成ms
time_t time_make_time_ex(int year, int month, int day, int hour, int minute, int second, int millseconds);
// 格式化本地时间字符串转成utc时间(s) 必须是标准的yyyy-mm-dd hour:min:sec 或 yyyy-mm-dd  
// nFlag: STR_TIME_ONLY_DATE || STR_TIME_FULL_DATE
time_t time_make_time_string(const char* strtime, int flag);

// 格式化为本地时间yyyy-mm-dd hour:min:sec [timestamp 单位s)
void time_format_local_date_time(time_t timestamp, char* strtime, int size);
// 格式化为本地时间yyyy-mm-dd [timestamp 单位s)
void time_format_local_date(time_t timestamp, char* strtime, int size);
// 格式化本地时间为hour:min:sec [timestamp 单位s)
void time_format_local_time(time_t timestamp, char* strtime, int size);

// 判断是否为闰年
bool time_is_leap_year(int year);
// 获取当前月的天数
int time_get_days_of_month(int year, int month);
// 获取当年的天数
int time_get_days_of_year(int year);

// 计算相隔天数，time1-time2 单位(s)
int time_subtract_days(time_t time1, time_t time2);
#endif