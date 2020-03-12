
#define _CRT_SECURE_NO_WARNINGS

#define _SILENCE_CXX17_CODECVT_HEADER_DEPRECATION_WARNING

#define _BSD_SOURCE 1
#include "internal.h"
#include "log.h"
#include "ConvertUTF.h"
#include <sys/types.h>
#include "dirent.h"
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <string>


#include <locale>
#include <codecvt>

#define VERBOSE 0

// Case insensitive string compare
template <typename T>
bool iequals(T& a, T& b)
{
	return std::equal(a.begin(), a.end(),
		b.begin(), b.end(),
		[](wchar_t a, wchar_t b) {
			return std::tolower(a) == std::tolower(b);
		});
}

FILE* unshield_fopen_for_reading(Unshield* unshield, int index, const char* suffix)
{
	FILE* result = NULL;

	if (unshield && !unshield->filename_path.empty())
	{
		std::wstring_convert<std::codecvt_utf8_utf16<wchar_t>> converter;

		// Construct directory from path.
		std::filesystem::path dirpath = unshield->filename_path;
		dirpath.remove_filename();
		if (dirpath.empty()) dirpath.append(".");

		// Construct filename from path and index and suffix.
		std::filesystem::path filepath = unshield->filename_path.filename();
		std::wstring filename = filepath.c_str() + std::to_wstring(index) + L"." + converter.from_bytes(suffix);

		std::filesystem::path filenamepath;

		_WDIR* sourcedir = _wopendir(dirpath.make_preferred().c_str());

		if (sourcedir)
		{
			struct _wdirent* dent = NULL;

			for (dent = _wreaddir(sourcedir); dent; dent = _wreaddir(sourcedir))
			{
                std::wstring d_name_string(dent->d_name);
				if (iequals(d_name_string, filename))
				{
					/*unshield_trace(L"Found match %s\n",converter.to_bytes(dent->d_name));*/
					break;
				}
			}

			if (dent == NULL)
			{
				unshield_trace(L"File %s not found even case insensitive\n", converter.to_bytes(filename.c_str()));
				goto exit;
			}
			else {
				filenamepath = dirpath.append(dent->d_name);
			}
		}
		else
			unshield_trace(L"Could not open directory %s error %s\n", converter.to_bytes(dirpath.c_str()), strerror(errno));

		if (!filenamepath.empty())
		{
#if VERBOSE
			unshield_trace(L"Opening file '%s'", converter.to_bytes(filenamepath.c_str()));
#endif
			result = _wfopen(filenamepath.c_str(), L"rb");
		}

	exit:
		if (sourcedir)
			_wclosedir(sourcedir);
	}

	return result;
}

long unshield_fsize(FILE* file)
{
  long result;
  long previous = ftell(file);
  fseek(file, 0L, SEEK_END);
  result = ftell(file);
  fseek(file, previous, SEEK_SET);
  return result;
}

bool unshield_read_common_header(uint8_t** buffer, CommonHeader* common)
{
  uint8_t* p = *buffer;
  common->signature              = READ_UINT32(p); p += 4;

  if (CAB_SIGNATURE != common->signature)
  {
    unshield_error(L"Invalid file signature");

    if (MSCF_SIGNATURE == common->signature)
      unshield_warning(L"Found Microsoft Cabinet header. Use cabextract (http://www.kyz.uklinux.net/cabextract.php) to unpack this file.");

    return false;
  }

  common->version                = READ_UINT32(p); p += 4;
  common->volume_info            = READ_UINT32(p); p += 4;
  common->cab_descriptor_offset  = READ_UINT32(p); p += 4;
  common->cab_descriptor_size    = READ_UINT32(p); p += 4;

#if VERBOSE
  unshield_trace(L"Common header: %08x %08x %08x %08x",
      common->version, 
      common->volume_info, 
      common->cab_descriptor_offset, 
      common->cab_descriptor_size);
#endif

  *buffer = p;
  return true;
}

/**
  Get pointer at cab descriptor + offset
  */
uint8_t* unshield_header_get_buffer(Header* header, uint32_t offset)
{
  if (offset)
    return 
      header->data +
      header->common.cab_descriptor_offset +
      offset;
  else
    return NULL;
}


static int unshield_strlen_utf16(const uint16_t* utf16)
{
  const uint16_t* current = utf16;
  while (*current++)
    ;
  return (int)(current - utf16);
}


static StringBuffer* unshield_add_string_buffer(Header* header)
{
  StringBuffer* result = NEW1(StringBuffer);
  if (!result) {
      return NULL;
  }
  result->next = header->string_buffer;
  return header->string_buffer = result;
}


static const char* unshield_utf16_to_utf8(Header* header, const uint16_t* utf16)
{
  StringBuffer* string_buffer = unshield_add_string_buffer(header); 
  if (!string_buffer)
      return NULL;

  int length = unshield_strlen_utf16(utf16);
  int buffer_size = 2 * length + 1;
  char* target = string_buffer->string = NEW(char, buffer_size);
  ConversionResult result = ConvertUTF16toUTF8(
      (const UTF16**)&utf16, utf16 + length + 1, 
      (UTF8**)&target, (UTF8*)(target + buffer_size), lenientConversion);
  if (result != conversionOK)
  {
    /* fail fast */
    abort();
  }
  return string_buffer->string;
}

const char* unshield_get_utf8_string(Header* header, const void* buffer)
{
  if (header->major_version >= 17 && buffer != NULL)
  {
    return unshield_utf16_to_utf8(header, (const uint16_t*)buffer);
  }
  else
  {
    return (const char*)buffer;
  }
}

/**
  Get string at cab descriptor offset + string offset
 */
const char* unshield_header_get_string(Header* header, uint32_t offset)
{
  return unshield_get_utf8_string(header, unshield_header_get_buffer(header, offset));
}


