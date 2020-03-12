
#define _CRT_SECURE_NO_WARNINGS

/*
 $Id$ */
#include "internal.h"
#if USE_OUR_OWN_MD5
#include "md5/global.h"
#include "md5/md5.h"
#else
#include <openssl/md5.h>
#define MD5Init MD5_Init
#define MD5Update MD5_Update
#define MD5Final MD5_Final
#endif
#include "cabfile.h"
#include "log.h"
#include <assert.h>
#include <stdlib.h>
#include <string.h>

#include <zlib.h>

#include <algorithm>
#include <filesystem>

#define VERBOSE 3

#define ror8(x,n)   (((x) >> ((int)(n))) | ((x) << (8 - (int)(n))))
#define rol8(x,n)   (((x) << ((int)(n))) | ((x) >> (8 - (int)(n))))

#include <string>


#include <string_view>

#if defined(WIN32) || defined(_WIN32) || defined(__WIN32__) || defined(__NT__)
FILE* UnshieldFileOpen(
    const std::filesystem::path& filenamepath,
    const wchar_t* mode) {

    return _wfopen(filenamepath.c_str(), mode);
}
#else
FILE* UnshieldFileOpen(
    const std::filesystem::path& filenamepath,
    const char* mode) {

    return fopen(filenamepath.c_str(), mode);
}
#endif

FileDescriptor* Unshield::unshield_read_file_descriptor(size_t index)
{
  /* XXX: multi-volume support... */
  Header* header = this->header_list;
  uint8_t* p = NULL;
  uint8_t* saved_p = NULL;
  FileDescriptor* fd = new FileDescriptor;

  switch (header->major_version)
  {
    case 0:
    case 5:
      saved_p = p = header->data +
          header->common.cab_descriptor_offset +
          header->cab.file_table_offset +
          header->file_table[header->cab.directory_count + index];

#if VERBOSE
      unshield_trace(L"File descriptor offset %lld: %08x", index, p - header->data);
#endif
 
      fd->volume            = header->index;

      fd->name_offset       = READ_UINT32(p); p += 4;
      fd->directory_index   = READ_UINT32(p); p += 4;

      fd->flags             = READ_UINT16(p); p += 2;

      fd->expanded_size     = READ_UINT32(p); p += 4;
      fd->compressed_size   = READ_UINT32(p); p += 4;
      p += 0x14;
      fd->data_offset       = READ_UINT32(p); p += 4;
      
#if VERBOSE >= 2
      unshield_trace(L"Name offset:      %08x", fd->name_offset);
      unshield_trace(L"Directory index:  %08x", fd->directory_index);
      unshield_trace(L"Flags:            %04x", fd->flags);
      unshield_trace(L"Expanded size:    %08x", fd->expanded_size);
      unshield_trace(L"Compressed size:  %08x", fd->compressed_size);
      unshield_trace(L"Data offset:      %08x", fd->data_offset);
#endif

      if (header->major_version == 5)
      {
        memcpy(fd->md5, p, 0x10); p += 0x10;
        assert((p - saved_p) == 0x3a);
      }

      break;

    case 6:
    case 7:
    case 8:
    case 9:
    case 10:
    case 11:
    case 12:
    case 13:
    default:
      saved_p = p = header->data +
          header->common.cab_descriptor_offset +
          header->cab.file_table_offset +
          header->cab.file_table_offset2 +
          ((size_t)index) * 0x57;
      
#if VERBOSE
      unshield_trace(L"File descriptor offset: 0x%llx", p - header->data);
#endif
      fd->flags             = READ_UINT16(p); p += 2;
      fd->expanded_size     = READ_UINT32(p); p += 4;
      p += 4;
      fd->compressed_size   = READ_UINT32(p); p += 4;
      p += 4;
      fd->data_offset       = READ_UINT32(p); p += 4;
      p += 4;
      memcpy(fd->md5, p, 0x10); p += 0x10;
      p += 0x10;
      fd->name_offset       = READ_UINT32(p); p += 4;
      fd->directory_index   = READ_UINT16(p); p += 2;

      assert((p - saved_p) == 0x40);
      
      p += 0xc;
      fd->link_previous     = READ_UINT32(p); p += 4;
      fd->link_next         = READ_UINT32(p); p += 4;
      fd->link_flags        = *p; p ++;

#if VERBOSE
      if (fd->link_flags != LINK_NONE)
      {
        unshield_trace(L"Link: previous=%i, next=%i, flags=%i",
            fd->link_previous, fd->link_next, fd->link_flags);
      }
#endif
      
      fd->volume            = READ_UINT16(p); p += 2;

      assert((p - saved_p) == 0x57);
      break;
  }

  if (!(fd->flags & FILE_COMPRESSED) &&
      fd->compressed_size != fd->expanded_size)
  {
    unshield_warning(L"File is not compressed but compressed size is %08x and expanded size is %08x",
        fd->compressed_size, fd->expanded_size);
  }

  return fd;
}

FileDescriptor* Unshield::unshield_get_file_descriptor(size_t index)
{
  /* XXX: multi-volume support... */
  Header* header = this->header_list;

  if (index < 0 || index >= header->cab.file_count)
  {
    unshield_error((L"Invalid index"));
    return NULL;
  }

  header->file_descriptors.resize(header->cab.file_count);

  if (!header->file_descriptors[index])
    header->file_descriptors[index] = this->unshield_read_file_descriptor(index);

  return header->file_descriptors[index];
}

int Unshield::unshield_file_count () const
{
    /* XXX: multi-volume support... */
    Header* header = this->header_list;

    return header->cab.file_count;
}/*}}}*/

const char* Unshield::unshield_file_name (size_t index)/*{{{*/
{
  FileDescriptor* fd = this->unshield_get_file_descriptor(index);

  if (fd)
  {
    /* XXX: multi-volume support... */
    Header* header = this->header_list;

    return unshield_get_utf8_string(header, 
        header->data +
        header->common.cab_descriptor_offset +
        header->cab.file_table_offset +
        fd->name_offset);
  }
    
  unshield_warning(L"Failed to get file descriptor %i", index);
  return NULL;
}/*}}}*/

bool Unshield::unshield_file_is_valid(size_t index)
{
  bool is_valid = false;
  FileDescriptor* fd;

  if (index < 0 || index >= (size_t)this->unshield_file_count())
    goto exit;

  if (!(fd = this->unshield_get_file_descriptor(index)))
    goto exit;

  if (fd->flags & FILE_INVALID)
    goto exit;

  if (!fd->name_offset)
    goto exit;

  if (!fd->data_offset)
    goto exit;

  is_valid = true;
  
exit:
  return is_valid;
}


int unshield_uncompress (Byte *dest, uLong* destLen, Byte *source, uLong *sourceLen)/*{{{*/
{
    z_stream stream;
    int err;

    stream.next_in = source;
    stream.avail_in = (uInt)*sourceLen;

    stream.next_out = dest;
    stream.avail_out = (uInt)*destLen;

    stream.zalloc = (alloc_func)0;
    stream.zfree = (free_func)0;

    /* make second parameter negative to disable checksum verification */
    err = inflateInit2(&stream, -MAX_WBITS);
    if (err != Z_OK) return err;

    err = inflate(&stream, Z_FINISH);
    if (err != Z_STREAM_END) {
        inflateEnd(&stream);
        return err;
    }

    *destLen = stream.total_out;
    *sourceLen = stream.total_in;

    err = inflateEnd(&stream);
    return err;
}/*}}}*/

static int unshield_uncompress_old(Byte *dest, uLong *destLen, Byte *source, uLong *sourceLen)/*{{{*/
{
    z_stream stream;
    int err;

    stream.next_in = source;
    stream.avail_in = (uInt)*sourceLen;

    stream.next_out = dest;
    stream.avail_out = (uInt)*destLen;

    stream.zalloc = (alloc_func)0;
    stream.zfree = (free_func)0;

    *destLen = 0;
    *sourceLen = 0;

    /* make second parameter negative to disable checksum verification */
    err = inflateInit2(&stream, -MAX_WBITS);
    if (err != Z_OK) 
      return err;

    while (stream.avail_in > 1)
    {
        err = inflate(&stream, Z_BLOCK);
        if (err != Z_OK)
        {
            inflateEnd(&stream);
            return err;
        }
    }

    *destLen = stream.total_out;
    *sourceLen = stream.total_in;

    err = inflateEnd(&stream);
    return err;
}/*}}}*/

struct UnshieldReader
{
  Unshield*         unshield;
  size_t            index;
  FileDescriptor*   file_descriptor;
  int               volume;
  FILE*             volume_file;
  VolumeHeader      volume_header;
  size_t            volume_bytes_left;
  unsigned          obfuscation_offset;

  bool unshield_reader_open_volume(int volume);
  void unshield_reader_deobfuscate(uint8_t* buffer, size_t size);
  bool unshield_reader_read(void* buffer, size_t size);

  bool unshield_reader_create(Unshield* unshield, size_t index, FileDescriptor* file_descriptor);
  void unshield_reader_destroy();

  UnshieldReader(Unshield* unshield, size_t index, FileDescriptor* file_descriptor) :
      unshield(NULL), index(0), file_descriptor(NULL), volume(0), volume_file(NULL), volume_bytes_left(0), obfuscation_offset(0)
  {
      unshield_reader_create(unshield, index, file_descriptor);
  }

  ~UnshieldReader() {
      unshield_reader_destroy();
  }

};

bool UnshieldReader::unshield_reader_open_volume(int volume)
{
  bool success = false;
  unsigned data_offset = 0;
  unsigned volume_bytes_left_compressed;
  unsigned volume_bytes_left_expanded;
  CommonHeader common_header;

#if VERBOSE >= 2
  unshield_trace(L"Open volume %i", volume);
#endif
  
  FCLOSE(this->volume_file);

  this->volume_file = unshield_fopen_for_reading(this->unshield, volume, CABINET_SUFFIX);
  if (!this->volume_file)
  {
    unshield_error(L"Failed to open input cabinet file %i", volume);
    goto exit;
  }

  {
    uint8_t tmp[COMMON_HEADER_SIZE];
    uint8_t* p = tmp;

    if (COMMON_HEADER_SIZE != 
        fread(&tmp, 1, COMMON_HEADER_SIZE, this->volume_file))
      goto exit;

    if (!unshield_read_common_header(&p, &common_header))
      goto exit;
  }
 
  memset(&this->volume_header, 0, sizeof(VolumeHeader));

  switch (this->unshield->header_list->major_version)
  {
    case 0:
    case 5:
      {
        uint8_t five_header[VOLUME_HEADER_SIZE_V5];
        uint8_t* p = five_header;

        if (VOLUME_HEADER_SIZE_V5 != 
            fread(&five_header, 1, VOLUME_HEADER_SIZE_V5, this->volume_file))
          goto exit;

        this->volume_header.data_offset                 = READ_UINT32(p); p += 4;
#if VERBOSE
        if (READ_UINT32(p))
          unshield_trace(L"Unknown = %08x", READ_UINT32(p));
#endif
        /* unknown */                                                    p += 4;
        this->volume_header.first_file_index           = READ_UINT32(p); p += 4;
        this->volume_header.last_file_index            = READ_UINT32(p); p += 4;
        this->volume_header.first_file_offset          = READ_UINT32(p); p += 4;
        this->volume_header.first_file_size_expanded   = READ_UINT32(p); p += 4;
        this->volume_header.first_file_size_compressed = READ_UINT32(p); p += 4;
        this->volume_header.last_file_offset           = READ_UINT32(p); p += 4;
        this->volume_header.last_file_size_expanded    = READ_UINT32(p); p += 4;
        this->volume_header.last_file_size_compressed  = READ_UINT32(p); p += 4;

        if (this->volume_header.last_file_offset == 0)
          this->volume_header.last_file_offset = INT32_MAX;
      }
      break;

    case 6:
    case 7:
    case 8:
    case 9:
    case 10:
    case 11:
    case 12:
    case 13:
    default:
      {
        uint8_t six_header[VOLUME_HEADER_SIZE_V6];
        uint8_t* p = six_header;

        if (VOLUME_HEADER_SIZE_V6 != 
            fread(&six_header, 1, VOLUME_HEADER_SIZE_V6, this->volume_file))
          goto exit;

        this->volume_header.data_offset                       = READ_UINT32(p); p += 4;
        this->volume_header.data_offset_high                  = READ_UINT32(p); p += 4;
        this->volume_header.first_file_index                  = READ_UINT32(p); p += 4;
        this->volume_header.last_file_index                   = READ_UINT32(p); p += 4;
        this->volume_header.first_file_offset                 = READ_UINT32(p); p += 4;
        this->volume_header.first_file_offset_high            = READ_UINT32(p); p += 4;
        this->volume_header.first_file_size_expanded          = READ_UINT32(p); p += 4;
        this->volume_header.first_file_size_expanded_high     = READ_UINT32(p); p += 4;
        this->volume_header.first_file_size_compressed        = READ_UINT32(p); p += 4;
        this->volume_header.first_file_size_compressed_high   = READ_UINT32(p); p += 4;
        this->volume_header.last_file_offset                  = READ_UINT32(p); p += 4;
        this->volume_header.last_file_offset_high             = READ_UINT32(p); p += 4;
        this->volume_header.last_file_size_expanded           = READ_UINT32(p); p += 4;
        this->volume_header.last_file_size_expanded_high      = READ_UINT32(p); p += 4;
        this->volume_header.last_file_size_compressed         = READ_UINT32(p); p += 4;
        this->volume_header.last_file_size_compressed_high    = READ_UINT32(p); p += 4;
      }
      break;
  }
  
#if VERBOSE >= 2
  unshield_trace(L"First file index = %i, last file index = %i",
      this->volume_header.first_file_index, this->volume_header.last_file_index);
  unshield_trace(L"First file offset = %08x, last file offset = %08x",
      this->volume_header.first_file_offset, this->volume_header.last_file_offset);
#endif

  /* enable support for split archives for IS5 */
  if (this->unshield->header_list->major_version == 5)
  {
    if (this->index < (this->unshield->header_list->cab.file_count - 1) &&
        this->index == this->volume_header.last_file_index && 
        this->volume_header.last_file_size_compressed != this->file_descriptor->compressed_size)
    {
      unshield_trace(L"IS5 split file last in volume");
      this->file_descriptor->flags |= FILE_SPLIT;
    }
    else if (this->index > 0 &&
        this->index == this->volume_header.first_file_index && 
        this->volume_header.first_file_size_compressed != this->file_descriptor->compressed_size)
    {
      unshield_trace(L"IS5 split file first in volume");
      this->file_descriptor->flags |= FILE_SPLIT;
    }
  }

  if (this->file_descriptor->flags & FILE_SPLIT)
  {   
#if VERBOSE
    unshield_trace(/*"Total bytes left = 0x08%x, "*/L"previous data offset = 0x08%x",
        /*total_bytes_left, */data_offset); 
#endif

    if (this->index == this->volume_header.last_file_index && this->volume_header.last_file_offset != 0x7FFFFFFF)
    {
      /* can be first file too... */
#if VERBOSE
      unshield_trace(L"Index %lld is last file in cabinet file %i",
          this->index, volume);
#endif

      data_offset                   = this->volume_header.last_file_offset;
      volume_bytes_left_expanded    = this->volume_header.last_file_size_expanded;
      volume_bytes_left_compressed  = this->volume_header.last_file_size_compressed;
    }
    else if (this->index == this->volume_header.first_file_index)
    {
#if VERBOSE
      unshield_trace(L"Index %lld is first file in cabinet file %i",
          this->index, volume);
#endif

      data_offset                   = this->volume_header.first_file_offset;
      volume_bytes_left_expanded    = this->volume_header.first_file_size_expanded;
      volume_bytes_left_compressed  = this->volume_header.first_file_size_compressed;
    }
    else
    {
      success = true;
      goto exit;
    }

#if VERBOSE
    unshield_trace(L"Will read 0x%08x bytes from offset 0x%08x",
        volume_bytes_left_compressed, data_offset);
#endif
  }
  else
  {
    data_offset                  = this->file_descriptor->data_offset;
    volume_bytes_left_expanded   = this->file_descriptor->expanded_size;
    volume_bytes_left_compressed = this->file_descriptor->compressed_size;
  }

  if (this->file_descriptor->flags & FILE_COMPRESSED)
    this->volume_bytes_left = volume_bytes_left_compressed;
  else
    this->volume_bytes_left = volume_bytes_left_expanded;

  fseek(this->volume_file, data_offset, SEEK_SET);

  this->volume = volume;
  success = true;

exit:
  return success;
}/*}}}*/

void unshield_deobfuscate(unsigned char* buffer, size_t size, unsigned* seed)
{
  unsigned tmp_seed = *seed;
  
  for (; size > 0; size--, buffer++, tmp_seed++)
  {
    *buffer = ror8(*buffer ^ 0xd5, 2) - (tmp_seed % 0x47);
  }

  *seed = tmp_seed;
}

void UnshieldReader::unshield_reader_deobfuscate(uint8_t* buffer, size_t size)
{
  unshield_deobfuscate(buffer, size, &this->obfuscation_offset);
}

bool UnshieldReader::unshield_reader_read(void* buffer, size_t size)
{
  bool success = false;
  uint8_t* p = (uint8_t*)buffer;
  size_t bytes_left = size;

#if VERBOSE >= 3
    unshield_trace(L"unshield_reader_read start: bytes_left = 0x%llx, volume_bytes_left = 0x%llx", 
        bytes_left, this->volume_bytes_left);
#endif

  for (;;)
  {
    /* 
       Read as much as possible from this volume
     */
    size_t bytes_to_read = std::min<size_t>(bytes_left, this->volume_bytes_left);

#if VERBOSE >= 3
    unshield_trace(L"Trying to read 0x%llx bytes from offset %08x in volume %i", 
        bytes_to_read, ftell(this->volume_file), this->volume);
#endif
    if (bytes_to_read == 0)
    {
        unshield_error(L"bytes_to_read can't be zero");
        goto exit;
    }

    if (bytes_to_read != fread(p, 1, bytes_to_read, this->volume_file))
    {
      unshield_error(L"Failed to read 0x%08llx bytes of file %lld (%s) from volume %i. Current offset = 0x%08x",
          bytes_to_read, this->index, 
          this->unshield->unshield_file_name(this->index), this->volume,
          ftell(this->volume_file));
      goto exit;
    }

    bytes_left -= bytes_to_read;
    this->volume_bytes_left -= bytes_to_read;

#if VERBOSE >= 3
    unshield_trace(L"bytes_left = %lld, volume_bytes_left = %lld", 
        bytes_left, this->volume_bytes_left);
#endif

    if (!bytes_left)
      break;

    p += bytes_to_read;

    /*
       Open next volume
     */

    if (!this->unshield_reader_open_volume(this->volume + 1))
    {
      unshield_error(L"Failed to open volume %i to read %i more bytes",
          this->volume + 1, bytes_to_read);
      goto exit;
    }
  }

  if (this->file_descriptor->flags & FILE_OBFUSCATED)
    this->unshield_reader_deobfuscate((uint8_t*)buffer, size);

  success = true;

exit:
  return success;
}/*}}}*/

bool UnshieldReader::unshield_reader_create(
    Unshield* unshield, 
    size_t index,
    FileDescriptor* file_descriptor)
{
  bool success = false;
  
  this->unshield          = unshield;
  this->index             = index;
  this->file_descriptor   = file_descriptor;

  for (;;)
  {
    if (!this->unshield_reader_open_volume(file_descriptor->volume))
    {
      unshield_error(L"Failed to open volume %i",
          file_descriptor->volume);
      goto exit;
    }

    /* Start with the correct volume for IS5 cabinets */
    if (this->unshield->header_list->major_version <= 5 &&
        index > this->volume_header.last_file_index)
    {
      unshield_trace(L"Trying next volume...");
      file_descriptor->volume++;
      continue;
    }
      
    break;  
  };

  success = true;

exit:

  return success;
}

void UnshieldReader::unshield_reader_destroy()
{
    FCLOSE(this->volume_file);
}

#define BUFFER_SIZE (64*1024)

/*
 * If filename is NULL, just throw away the result
 */
bool Unshield::unshield_file_save (size_t index, const std::filesystem::path &filenamepath)/*{{{*/
{
  bool success = false;
  FILE* output = NULL;
  unsigned char* input_buffer   = new unsigned char[BUFFER_SIZE+1];
  unsigned char* output_buffer  = new unsigned char [BUFFER_SIZE];

  unsigned int bytes_left;
  uLong total_written = 0;
  UnshieldReader* reader = NULL;
  FileDescriptor* file_descriptor;
  MD5_CTX md5;

  MD5Init(&md5);

  if (!input_buffer || !output_buffer)
    goto exit;

  if (!(file_descriptor = this->unshield_get_file_descriptor(index)))
  {
    unshield_error(L"Failed to get file descriptor for file %i", index);
    goto exit;
  }

  if ((file_descriptor->flags & FILE_INVALID) || 0 == file_descriptor->data_offset)
  {
    /* invalid file */
    goto exit;
  }

  if (file_descriptor->link_flags & LINK_PREV)
  {
    success = this->unshield_file_save(file_descriptor->link_previous, filenamepath);
    goto exit;
  }

  reader = new UnshieldReader(this, index, file_descriptor);
  if (!reader)
  {
    unshield_error(L"Failed to create data reader for file %i", index);
    goto exit;
  }

  if (unshield_fsize(reader->volume_file) == (long)file_descriptor->data_offset)
  {
    unshield_error(L"File %i is not inside the cabinet.", index);
    goto exit;
  }

  if (!filenamepath.empty()) 
  {
    output = fopen(filenamepath.string().c_str(), "wb");
    if (!output)
    {
      unshield_error(L"Failed to open output file '%s'", filenamepath.string().c_str());
      goto exit;
    }
  }

  if (file_descriptor->flags & FILE_COMPRESSED)
    bytes_left = file_descriptor->compressed_size;
  else
    bytes_left = file_descriptor->expanded_size;

  /*unshield_trace(L"Bytes to read: %i", bytes_left);*/

  while (bytes_left > 0)
  {
    uLong bytes_to_write = BUFFER_SIZE;
    int result;

    if (file_descriptor->flags & FILE_COMPRESSED)
    {
      uLong read_bytes;
      uint16_t bytes_to_read = 0;

      if (!reader->unshield_reader_read(&bytes_to_read, sizeof(bytes_to_read)))
      {
        unshield_error(L"Failed to read %i bytes of file %i (%s) from input cabinet file %i", 
            sizeof(bytes_to_read), index, this->unshield_file_name(index), file_descriptor->volume);
        goto exit;
      }

      bytes_to_read = letoh16(bytes_to_read);
      if (bytes_to_read == 0)
      {
          unshield_error(L"bytes_to_read can't be zero");
          unshield_error(L"HINT: Try unshield_file_save_old() or -O command line parameter!");
          goto exit;
      }

      if (!reader->unshield_reader_read(input_buffer, bytes_to_read))
      {
#if VERBOSE
        unshield_error(L"Failed to read %i bytes of file %i (%s) from input cabinet file %i", 
            bytes_to_read, index, this->unshield_file_name(index), file_descriptor->volume);
#endif
        goto exit;
      }

      /* add a null byte to make inflate happy */
      input_buffer[bytes_to_read] = 0;
      read_bytes = bytes_to_read+1;
      result = unshield_uncompress(output_buffer, &bytes_to_write, input_buffer, &read_bytes);

      if (Z_OK != result)
      {
        unshield_error(L"Decompression failed with code %i. bytes_to_read=%i, volume_bytes_left=%i, volume=%i, read_bytes=%i", 
            result, bytes_to_read, reader->volume_bytes_left, file_descriptor->volume, read_bytes);
        if (result == Z_DATA_ERROR)
        {
            unshield_error(L"HINT: Try unshield_file_save_old() or -O command line parameter!");
        }
        goto exit;
      }

#if VERBOSE >= 3
    unshield_trace(L"read_bytes = %i", 
        read_bytes);
#endif

      bytes_left -= 2;
      bytes_left -= bytes_to_read;
    }
    else
    {
      bytes_to_write = (uLong)std::min<size_t>(bytes_left, BUFFER_SIZE);

      if (!reader->unshield_reader_read(output_buffer, bytes_to_write))
      {
#if VERBOSE
        unshield_error(L"Failed to read %i bytes from input cabinet file %i", 
            bytes_to_write, file_descriptor->volume);
#endif
        goto exit;
      }

      bytes_left -= bytes_to_write;
    }

    MD5Update(&md5, output_buffer, bytes_to_write);

    if (output)
    {
      if (bytes_to_write != fwrite(output_buffer, 1, bytes_to_write, output))
      {
        unshield_error(L"Failed to write %i bytes to file '%s'", bytes_to_write, filenamepath.string());
        goto exit;
      }
    }

    total_written += bytes_to_write;
  }

  if (file_descriptor->expanded_size != total_written)
  {
    unshield_error(L"Expanded size expected to be %i, but was %i", 
        file_descriptor->expanded_size, total_written);
    goto exit;
  }

  if (this->header_list->major_version >= 6)
  {
    unsigned char md5result[16];
    MD5Final(md5result, &md5);

    if (0 != memcmp(md5result, file_descriptor->md5, 16))
    {
      unshield_error(L"MD5 checksum failure for file %i (%s)", 
          index, this->unshield_file_name(index));
      goto exit;
    }
  }

  success = true;
  
exit:
  delete reader;
  FCLOSE(output);
  delete [] input_buffer;
  delete [] output_buffer;
  return success;
}

int Unshield::unshield_file_directory(size_t index)/*{{{*/
{
  FileDescriptor* fd = this->unshield_get_file_descriptor(index);
  if (fd)
  {
    return fd->directory_index;
  }
  else
    return -1;
}/*}}}*/

size_t Unshield::unshield_file_size(size_t index)
{
  FileDescriptor* fd = this->unshield_get_file_descriptor(index);
  if (fd)
  {
    return fd->expanded_size;
  }
  else
    return 0;
}/*}}}*/

bool Unshield::unshield_file_save_raw(size_t index, const std::filesystem::path& filenamepath)
{
  /* XXX: Thou Shalt Not Cut & Paste... */
  bool success = false;
  FILE* output = NULL;
  unsigned char* input_buffer   = new unsigned char[BUFFER_SIZE];
  unsigned char* output_buffer  = new unsigned char[BUFFER_SIZE];

  unsigned int bytes_left;
  UnshieldReader* reader = NULL;
  FileDescriptor* file_descriptor;

  if (!input_buffer) goto exit;
  if (!output_buffer) goto exit;

  if (!(file_descriptor = this->unshield_get_file_descriptor(index)))
  {
    unshield_error(L"Failed to get file descriptor for file %i", index);
    goto exit;
  }

  if ((file_descriptor->flags & FILE_INVALID) || 0 == file_descriptor->data_offset)
  {
    /* invalid file */
    goto exit;
  }

  if (file_descriptor->link_flags & LINK_PREV)
  {
    success = this->unshield_file_save_raw(file_descriptor->link_previous, filenamepath);
    goto exit;
  }

  reader = new UnshieldReader(this, index, file_descriptor);
  if (!reader)
  {
    unshield_error(L"Failed to create data reader for file %i", index);
    goto exit;
  }

  if (unshield_fsize(reader->volume_file) == (long)file_descriptor->data_offset)
  {
    unshield_error(L"File %i is not inside the cabinet.", index);
    goto exit;
  }

  if (filenamepath.empty()) {
      unshield_error(L"No file.");
      goto exit;
  }

  output = UnshieldFileOpen(filenamepath, L"wb");
  if (!output)
  {
	  unshield_error(L"Failed to open output file '%s'", filenamepath.c_str());
	  goto exit;
  }

  if (file_descriptor->flags & FILE_COMPRESSED)
    bytes_left = file_descriptor->compressed_size;
  else
    bytes_left = file_descriptor->expanded_size;

  /*unshield_trace(L"Bytes to read: %i", bytes_left);*/

  while (bytes_left > 0)
  {
    uLong bytes_to_write = (uLong)std::min<size_t>(bytes_left, BUFFER_SIZE);

    if (!reader->unshield_reader_read(output_buffer, bytes_to_write))
    {
#if VERBOSE
      unshield_error(L"Failed to read %i bytes from input cabinet file %i", 
          bytes_to_write, file_descriptor->volume);
#endif
      goto exit;
    }

    bytes_left -= bytes_to_write;

    if (bytes_to_write != fwrite(output_buffer, 1, bytes_to_write, output))
    {
      unshield_error(L"Failed to write %i bytes to file '%s'", bytes_to_write, filenamepath);
      goto exit;
    }
  }

  success = true;
  
exit:
  delete reader;

  if (output)
      FCLOSE(output);

  delete[] input_buffer;
  delete[] output_buffer;

  return success;
}

static uint8_t* find_bytes(
    const uint8_t* buffer, size_t bufferSize, 
    const uint8_t* pattern, size_t patternSize)
{
  const unsigned char *p = buffer;
  size_t buffer_left = bufferSize;
  while ((p = (const unsigned char*)memchr(p, pattern[0], buffer_left)) != NULL)
  {
    if (patternSize > buffer_left)
      break;

    if (memcmp(p, pattern, patternSize) == 0)
      return (uint8_t*)p;

    ++p;
    --buffer_left;
  }

  return NULL;
}

bool Unshield::unshield_file_save_old(size_t index, const std::filesystem::path& filenamepath)/*{{{*/
{
  /* XXX: Thou Shalt Not Cut & Paste... */
  bool success = false;
  FILE* output = NULL;
  size_t input_buffer_size = BUFFER_SIZE;

  std::vector<unsigned char> input_buffer;
  input_buffer.resize(BUFFER_SIZE);

  std::vector<unsigned char> output_buffer;
  output_buffer.resize(BUFFER_SIZE);

  unsigned int bytes_left;
  uLong total_written = 0;
  UnshieldReader* reader = NULL;
  FileDescriptor* file_descriptor;

  if (!(file_descriptor = this->unshield_get_file_descriptor(index)))
  {
    unshield_error(L"Failed to get file descriptor for file %i", index);
    goto exit;
  }

  if ((file_descriptor->flags & FILE_INVALID) || 0 == file_descriptor->data_offset)
  {
    /* invalid file */
    goto exit;
  }

  if (file_descriptor->link_flags & LINK_PREV)
  {
    success = this->unshield_file_save(file_descriptor->link_previous, filenamepath);
    goto exit;
  }

  reader = new UnshieldReader(this, index, file_descriptor);
  if (!reader)
  {
    unshield_error(L"Failed to create data reader for file %i", index);
    goto exit;
  }

  if (unshield_fsize(reader->volume_file) == (long)file_descriptor->data_offset)
  {
    unshield_error(L"File %i is not inside the cabinet.", index);
    goto exit;
  }

  if (!filenamepath.empty()) 
  {
    output = _wfopen(filenamepath.c_str(), L"wb");
    if (!output)
    {
      unshield_error(L"Failed to open output file '%s'", filenamepath.c_str());
      goto exit;
    }
  }

  if (file_descriptor->flags & FILE_COMPRESSED)
    bytes_left = file_descriptor->compressed_size;
  else
    bytes_left = file_descriptor->expanded_size;

  /*unshield_trace(L"Bytes to read: %i", bytes_left);*/

  while (bytes_left > 0)
  {
    uLong bytes_to_write = 0;
    int result;

    if (reader->volume_bytes_left == 0 && !reader->unshield_reader_open_volume(reader->volume + 1))
    {
        unshield_error(L"Failed to open volume %i to read %i more bytes",
            reader->volume + 1, bytes_left);
        goto exit;
    }

    if (file_descriptor->flags & FILE_COMPRESSED)
    {
      static const uint8_t END_OF_CHUNK[4] = { 0x00, 0x00, 0xff, 0xff };
      uLong read_bytes;
      size_t input_size = reader->volume_bytes_left;
      uint8_t* chunk_buffer;

      while (input_size > input_buffer.size()) 
      {
#if VERBOSE >= 3
        unshield_trace(L"increased input_buffer_size to 0x%llx", input_buffer_size);
#endif

        input_buffer.resize(input_buffer.size() * 2);
      }

      if (!reader->unshield_reader_read(input_buffer.data(), input_size))
      {
#if VERBOSE
        unshield_error(L"Failed to read 0x%x bytes of file %i (%s) from input cabinet file %i", 
            input_size, index, this->unshield_file_name(index), file_descriptor->volume);
#endif
        goto exit;
      }

      bytes_left -= (unsigned)input_size;

      for (chunk_buffer = input_buffer.data(); input_size; )
      {
        size_t chunk_size;
        uint8_t* match = find_bytes(chunk_buffer, input_size, END_OF_CHUNK, sizeof(END_OF_CHUNK));
        if (!match)
        {
          unshield_error(L"Could not find end of chunk for file %i (%s) from input cabinet file %i", 
              index, this->unshield_file_name(index), file_descriptor->volume);
          goto exit;
        }

        chunk_size = match - chunk_buffer;

        /*
           Detect when the chunk actually contains the end of chunk marker.

           Needed by Qtime.smk from "The Feeble Files - spanish version".

           The first bit of a compressed block is always zero, so we apply this
           workaround if it's a one.

           A possibly more proper fix for this would be to have
           unshield_uncompress_old eat compressed data and discard chunk
           markers inbetween.
           */
        while ((chunk_size + sizeof(END_OF_CHUNK)) < input_size &&
            chunk_buffer[chunk_size + sizeof(END_OF_CHUNK)] & 1)
        {
            unshield_warning(L"It seems like we have an end of chunk marker inside of a chunk.");
            chunk_size += sizeof(END_OF_CHUNK);
            match = find_bytes(chunk_buffer + chunk_size, input_size - chunk_size, END_OF_CHUNK, sizeof(END_OF_CHUNK));
            if (!match)
            {
                unshield_error(L"Could not find end of chunk for file %i (%s) from input cabinet file %i",
                    index, this->unshield_file_name(index), file_descriptor->volume);
                goto exit;
            }
            chunk_size = match - chunk_buffer;
        }

#if VERBOSE >= 3
        unshield_trace(L"chunk_size = 0x%llx", chunk_size);
#endif

        /* add a null byte to make inflate happy */
        chunk_buffer[chunk_size] = 0;

        bytes_to_write = BUFFER_SIZE;
        read_bytes = (uLong)chunk_size;
        result = unshield_uncompress_old(output_buffer.data(), &bytes_to_write, chunk_buffer, &read_bytes);

        if (Z_OK != result)
        {
          unshield_error(L"Decompression failed with code %i. input_size=%i, volume_bytes_left=%i, volume=%i, read_bytes=%i", 
              result, input_size, reader->volume_bytes_left, file_descriptor->volume, read_bytes);
          goto exit;
        }

#if VERBOSE >= 3
        unshield_trace(L"read_bytes = 0x%x", read_bytes);
#endif

        chunk_buffer += chunk_size;
        chunk_buffer += sizeof(END_OF_CHUNK);

        input_size -= chunk_size;
        input_size -= sizeof(END_OF_CHUNK);

        if (output)
          if (bytes_to_write != fwrite(output_buffer.data(), 1, bytes_to_write, output))
          {
            unshield_error(L"Failed to write %i bytes to file '%s'", bytes_to_write, filenamepath.c_str());
            goto exit;
          }

        total_written += bytes_to_write;
      }
    }
    else
    {
      bytes_to_write = (uLong)std::min<size_t>(bytes_left, BUFFER_SIZE);

      if (!reader->unshield_reader_read(output_buffer.data(), bytes_to_write))
      {
#if VERBOSE
        unshield_error(L"Failed to read %i bytes from input cabinet file %i", 
            bytes_to_write, file_descriptor->volume);
#endif
        goto exit;
      }

      bytes_left -= bytes_to_write;

      if (output)
        if (bytes_to_write != fwrite(output_buffer.data(), 1, bytes_to_write, output))
        {
          unshield_error(L"Failed to write %i bytes to file '%s'", bytes_to_write, filenamepath.c_str());
          goto exit;
        }

      total_written += bytes_to_write;
    }
  }

  if (file_descriptor->expanded_size != total_written)
  {
    unshield_error(L"Expanded size expected to be %i, but was %i", 
        file_descriptor->expanded_size, total_written);
    goto exit;
  }

  success = true;
  
exit:
  delete reader;
  FCLOSE(output);
  return success;
}/*}}}*/


