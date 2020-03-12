/* $Id$ */
#ifndef __internal_h__
#define __internal_h__

#include "libunshield.h"
#include "unshield_config.h"

#if HAVE_STDINT_H
#include <stdint.h>
#elif HAVE_INTTYPES_H
#include <inttypes.h>
#endif

#include <stdbool.h>
#include <stdio.h>  /* for FILE */

#include <filesystem>

#include "cabfile.h"

typedef struct _StringBuffer StringBuffer;

struct _StringBuffer
{
  StringBuffer* next;
  char* string;

  _StringBuffer();
  ~_StringBuffer();
};

typedef struct _Header Header;

struct _Header
{
  Header*   next;
  int       index;
  uint8_t*  data;
  size_t    size;
  int       major_version;

  /* shortcuts */
  CommonHeader    common;
  CabDescriptor   cab;

  std::vector<uint32_t>           file_table;

  std::vector<FileDescriptor*>    file_descriptors;

  std::vector<UnshieldComponent*> components;

  std::vector<UnshieldFileGroup*> file_groups;

  StringBuffer* string_buffer;

  _Header();
  ~_Header();

  StringBuffer* add_string_buffer();
  void          free_string_buffers();

};


struct _Unshield
{
  Header* header_list;
  std::filesystem::path filename_path;

  size_t             unshield_component_count() const;
  const char*        unshield_component_name(size_t index) const;
  bool               list_components() const;

  /*
     File group functions
  */
  size_t             unshield_file_group_count() const;
  UnshieldFileGroup* unshield_file_group_get(size_t index);
  UnshieldFileGroup* unshield_file_group_find(const char* name);
  const char*        unshield_file_group_name(size_t index) const;
  bool               list_file_groups() const;


  /*
     Directory functions
   */

  int                unshield_directory_count() const;
  const char*        unshield_directory_name(int index);
  int                unshield_file_directory(size_t index);

  /*
     File functions
   */

  int                unshield_file_count() const;
  const char*        unshield_file_name(size_t index);
  bool               unshield_file_is_valid(size_t index);
  size_t             unshield_file_size(size_t index);
  int                list_files_helper(const char* prefix, int first, int last);
  bool               should_process_file(int index);

  bool               unshield_file_save(size_t index, const std::filesystem::path& filenamepath);

  /** For investigation of compressed data */
  bool               unshield_file_save_raw(size_t index, const std::filesystem::path& filenamepath);

  /** Maybe it's just gzip without size? */
  bool               unshield_file_save_old(size_t index, const std::filesystem::path& filenamepath);

  /*
     File decriptor functions
   */
  FileDescriptor*    unshield_get_file_descriptor(size_t index);
  FileDescriptor*    unshield_read_file_descriptor(size_t index);

  bool               extract_file(const char* prefix, int index);
  bool               test_file(int index);

  // Actions
  int                extract_helper(const char* prefix, int first, int last);
  int                test_helper   (const char* prefix, int first, int last);

  typedef int (_Unshield::*ActionHelper)(const char* prefix, int first, int last);
  bool        do_action(ActionHelper helper);
};

/*
   Helpers
 */

FILE* unshield_fopen_for_reading(Unshield* unshield, int index, const char* suffix);
long unshield_fsize(FILE* file);
bool unshield_read_common_header(uint8_t** buffer, CommonHeader* common);

const char* unshield_get_utf8_string(Header* header, const void* buffer);
const char* unshield_header_get_string(Header* header, uint32_t offset);
uint8_t* unshield_header_get_buffer(Header* header, uint32_t offset);


/*
   Constants
 */

#define HEADER_SUFFIX   "hdr"
#define CABINET_SUFFIX  "cab"

/*
   Macros for safer development
 */

#define FCLOSE(file)    if (file) { fclose(file); file = NULL; }
#define STREQ(s1,s2)    (0 == strcmp(s1,s2))

#if WORDS_BIGENDIAN

#if HAVE_BYTESWAP_H
#include <byteswap.h>
#elif HAVE_SYS_BYTESWAP_H
#include <sys/byteswap.h>
#else

/* use our own functions */
#define IMPLEMENT_BSWAP_XX 1
#define bswap_16 unshield_bswap_16
#define bswap_32 unshield_bswap_32

uint16_t bswap_16(uint16_t x);
uint32_t bswap_32(uint32_t x);
#endif

#define letoh16(x)    bswap_16(x)
#define letoh32(x)    bswap_32(x)

#else
#define letoh32(x) (x)
#define letoh16(x) (x)
#endif

static inline uint16_t get_unaligned_le16(const uint8_t *p)
{
    return p[0] | p[1] << 8;
}

static inline uint32_t get_unaligned_le32(const uint8_t *p)
{
    return p[0] | p[1] << 8 | p[2] << 16 | p[3] << 24;
}

#define READ_UINT16(p)   get_unaligned_le16(p)
#define READ_UINT32(p)   get_unaligned_le32(p)

#define READ_INT16(p)   ((int16_t)READ_UINT16(p))
#define READ_INT32(p)   ((int32_t)READ_UINT32(p))


#endif 

