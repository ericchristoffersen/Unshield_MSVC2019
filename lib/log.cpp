/* $Id */
#include "log.h"
#include <stdarg.h>
#include <stdio.h>

/* evil static data */
static int current_log_level = UNSHIELD_LOG_LEVEL_HIGHEST;

void unshield_set_log_level(int level)
{
	current_log_level = level;
}

void Unshield_log(int level, const wchar_t* file, int line, const wchar_t* format, ...)
{
	va_list ap;

	if (level > current_log_level)
		return;

	fwprintf(stderr, L"[%s:%i] ", file, line);
	
	va_start(ap, format);
	vfwprintf(stderr, format, ap);
	va_end(ap);
	
	fwprintf(stderr, L"\n");
}

