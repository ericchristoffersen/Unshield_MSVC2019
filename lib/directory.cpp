/* $Id$ */
#include "internal.h"
#include "log.h"

int Unshield::unshield_directory_count() const
{
    /* XXX: multi-volume support... */
    Header* header = this->header_list;

    return header->cab.directory_count;
}

const char* Unshield::unshield_directory_name(int index)
{
  if (index >= 0)
  {
    /* XXX: multi-volume support... */
    Header* header = this->header_list;

    if (index < (int)header->cab.directory_count)
      return unshield_get_utf8_string(header, 
          header->data +
          header->common.cab_descriptor_offset +
          header->cab.file_table_offset +
          header->file_table[index]);
  }

  unshield_warning(L"Failed to get directory name %i", index);
  return NULL;
}

