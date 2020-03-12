/* $Id$ */
#include "internal.h"
#include "log.h"
#include <stdlib.h>
#include <string.h>

size_t Unshield::unshield_component_count() const
{
  Header* header = this->header_list;
  return header->components.size();
}

const char* Unshield::unshield_component_name(size_t index) const
{
  Header* header = this->header_list;

  if (index >= 0 && index < header->components.size())
    return header->components[index]->name;
  else
    return NULL;
}

UnshieldComponent::UnshieldComponent(Header* header, uint32_t offset)
{
  uint8_t* p = unshield_header_get_buffer(header, offset);
  uint32_t file_group_table_offset;
  unsigned i;

  this->name = unshield_header_get_string(header, READ_UINT32(p)); p += 4;

  switch (header->major_version)
  {
    case 0:
    case 5:
      p += 0x6c;
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
      p += 0x6b;
      break;
  }

  this->file_group_count = READ_UINT16(p); p += 2;
  if (this->file_group_count > MAX_FILE_GROUP_COUNT)
    abort();

  this->file_group_names = new const char* [this->file_group_count];

  file_group_table_offset = READ_UINT32(p); p += 4;

  p = unshield_header_get_buffer(header, file_group_table_offset);

  for (i = 0; i < this->file_group_count; i++)
  {
    this->file_group_names[i] = unshield_header_get_string(header, READ_UINT32(p)); 
    p += 4;
  }
}

UnshieldComponent::~UnshieldComponent()
{
	delete[] this->file_group_names;
}


