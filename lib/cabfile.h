/* $Id$ */
#ifndef __cabfile_h__
#define __cabfile_h__

#include "internal.h"

#define OFFSET_COUNT 0x47
#define CAB_SIGNATURE 0x28635349

#define MSCF_SIGNATURE 0x4643534d

#define COMMON_HEADER_SIZE      20
#define VOLUME_HEADER_SIZE_V5   40
#define VOLUME_HEADER_SIZE_V6   64

#define MAX_FILE_GROUP_COUNT    71
#define MAX_COMPONENT_COUNT     71

struct CommonHeader
{
  uint32_t signature;               /* 00 */
  uint32_t version;
  uint32_t volume_info;
  uint32_t cab_descriptor_offset;
  uint32_t cab_descriptor_size;     /* 10 */

  CommonHeader() :
      signature(0),
      version(0),
      volume_info(0),
      cab_descriptor_offset(0),
      cab_descriptor_size(0)
  {}
};


struct VolumeHeader
{
  uint32_t data_offset;
  uint32_t data_offset_high;
  uint32_t first_file_index;
  uint32_t last_file_index;
  uint32_t first_file_offset;
  uint32_t first_file_offset_high;
  uint32_t first_file_size_expanded;
  uint32_t first_file_size_expanded_high;
  uint32_t first_file_size_compressed;
  uint32_t first_file_size_compressed_high;
  uint32_t last_file_offset;
  uint32_t last_file_offset_high;
  uint32_t last_file_size_expanded;
  uint32_t last_file_size_expanded_high;
  uint32_t last_file_size_compressed;
  uint32_t last_file_size_compressed_high;

  VolumeHeader() :
      data_offset(0),
      data_offset_high(0),
      first_file_index(0),
      last_file_index(0),
      first_file_offset(0),
      first_file_offset_high(0),
      first_file_size_expanded(0),
      first_file_size_expanded_high(0),
      first_file_size_compressed(0),
      first_file_size_compressed_high(0),
      last_file_offset(0),
      last_file_offset_high(0),
      last_file_size_expanded(0),
      last_file_size_expanded_high(0),
      last_file_size_compressed(0),
      last_file_size_compressed_high(0)
  {}

};


struct CabDescriptor
{
  uint32_t file_table_offset;             /* c */
  uint32_t file_table_size;               /* 14 */
  uint32_t file_table_size2;              /* 18 */
  uint32_t directory_count;               /* 1c */
  uint32_t file_count;                    /* 28 */
  uint32_t file_table_offset2;  /* 2c */

  uint32_t file_group_offsets[MAX_FILE_GROUP_COUNT];  /* 0x3e  */
  uint32_t component_offsets [MAX_COMPONENT_COUNT];   /* 0x15a */

  CabDescriptor() :
      file_table_offset(0),
      file_table_size(0),
      file_table_size2(0),
      directory_count(0),
      file_count(0),
      file_table_offset2(0)
  {
      memset(file_group_offsets, 0, sizeof(file_group_offsets));
      memset(component_offsets, 0, sizeof(component_offsets));
  }
};

#define FILE_SPLIT			  1
#define FILE_OBFUSCATED   2
#define FILE_COMPRESSED		4
#define FILE_INVALID		  8

#define LINK_NONE	0
#define LINK_PREV	1
#define LINK_NEXT	2
#define LINK_BOTH	3

struct FileDescriptor
{
  uint32_t name_offset;
  uint32_t directory_index;
  uint16_t flags;
  uint32_t expanded_size;
  uint32_t compressed_size;
  uint32_t data_offset;
  uint8_t  md5[16];
  uint16_t volume;
  uint32_t link_previous;
  uint32_t link_next;
  uint8_t  link_flags;

  FileDescriptor() :
      name_offset(0),
      directory_index(0),
      flags(0),
      expanded_size(0),
      compressed_size(0),
      data_offset(0),
      volume(0),
      link_previous(0),
      link_next(0),
      link_flags(0)
  {
      memset(md5, 0, sizeof(md5));
  }

};

struct OffsetList
{
  uint32_t name_offset;
  uint32_t descriptor_offset;
  uint32_t next_offset;

  OffsetList() :
      name_offset(0),
      descriptor_offset(0),
      next_offset(0)
  {}

};

#endif

