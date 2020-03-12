/* $Id$ */
#if !defined(__log_h__)
#define __log_h__

#include "internal.h"

#define UNSHIELD_LOG_LEVEL_LOWEST    0

#define UNSHIELD_LOG_LEVEL_ERROR     1
#define UNSHIELD_LOG_LEVEL_WARNING   2
#define UNSHIELD_LOG_LEVEL_TRACE     3

#define UNSHIELD_LOG_LEVEL_HIGHEST   4

#ifdef __cplusplus
extern "C"
{
#endif

void _unshield_log(int level, const wchar_t* file, int line, const wchar_t* format, ...);

#define STRINGIFY2(m) #m
#define MEXPAND(m) m
#define STRINGIFY(m) STRINGIFY2(m)
#define WIDE(m) L ## m

#if 1

#define unshield_trace(format, ...) \
	_unshield_log(UNSHIELD_LOG_LEVEL_TRACE,__FUNCTIONW__, __LINE__, format, ##__VA_ARGS__)

#define unshield_warning(format, ...) \
	_unshield_log(UNSHIELD_LOG_LEVEL_WARNING,__FUNCTIONW__, __LINE__, format, ##__VA_ARGS__)

#define unshield_error(format, ...) \
	_unshield_log(UNSHIELD_LOG_LEVEL_ERROR,__FUNCTIONW__, __LINE__, format, ##__VA_ARGS__)

#else

#define unshield_trace(format, ...) 
//	_unshield_log(UNSHIELD_LOG_LEVEL_TRACE,__PRETTY_FUNCTION__, __LINE__, format, __VA_ARGS__)

#define unshield_warning(format, ...) 
//	_unshield_log(UNSHIELD_LOG_LEVEL_WARNING,__PRETTY_FUNCTION__, __LINE__, format, __VA_ARGS__)

#define unshield_warning_unless(cond, format, ...) 
//	if (!(cond)) \
//	_unshield_log(UNSHIELD_LOG_LEVEL_WARNING,__PRETTY_FUNCTION__, __LINE__, format, __VA_ARGS__)

#define unshield_error(format, ...) 
//	_unshield_log(UNSHIELD_LOG_LEVEL_ERROR,__PRETTY_FUNCTION__, __LINE__, format, __VA_ARGS__)

#endif

#ifdef __cplusplus
}
#endif


#endif

