/* $Id$ */
#include "internal.h"
#include "log.h"
#include <stdlib.h>
#include <string.h>

#define VERBOSE 1

StringBuffer::StringBuffer() : next(NULL), string(NULL) {}

StringBuffer::~StringBuffer()
{
    delete [] string;
}

Header::Header() : next(NULL), index(0), data(NULL), size(0), major_version(0), string_buffer(NULL) {}

void Header::free_string_buffers()
{
    StringBuffer* current = this->string_buffer;
    this->string_buffer = NULL;

    while (current != NULL)
    {
        StringBuffer* next = current->next;
        delete current;
        current = next;
    }
}

Header::~Header()
{
    this->free_string_buffers();

    for (size_t i = 0; i < this->components.size(); i++)
        delete this->components[i];

    for (size_t i = 0; i < this->file_groups.size(); i++)
        delete this->file_groups[i];

    for (size_t i = 0; i < this->file_descriptors.size(); i++)
        delete this->file_descriptors[i];

    delete [] this->data;
}

UnshieldFileGroup::UnshieldFileGroup(Header* header, uint32_t offset)
{
  uint8_t* p = unshield_header_get_buffer(header, offset);

#if VERBOSE
  unshield_trace(L"File group descriptor offset: %08x", offset);
#endif

  this->name = unshield_header_get_string(header, READ_UINT32(p)); p += 4;

  if (header->major_version <= 5)
    p += 0x48;
  else
    p += 0x12;

  this->first_file = READ_UINT32(p); p += 4;
  this->last_file  = READ_UINT32(p); p += 4;

#if VERBOSE
  unshield_trace(L"File group %08x first file = %i, last file = %i", 
      offset, this->first_file, this->last_file);
#endif

}

size_t Unshield::unshield_file_group_count() const
{
  Header* header = this->header_list;
  return header->file_groups.size();
}

UnshieldFileGroup* Unshield::unshield_file_group_get(size_t index)
{
  Header* header = this->header_list;

  if (index >= 0 && index < header->file_groups.size())
    return header->file_groups[index];
  else
    return NULL;
}

UnshieldFileGroup* Unshield::unshield_file_group_find(const char* name)
{
  Header* header = this->header_list;

  for (size_t i = 0; i < header->file_groups.size(); i++)
  {
    if (STREQ(header->file_groups[i]->name, name))
      return header->file_groups[i];
  }

  return NULL;
}

const char* Unshield::unshield_file_group_name(size_t index) const
{
  Header* header = this->header_list;

  if (index >= 0 && index < header->file_groups.size())
    return header->file_groups[index]->name;
  else
    return NULL;
}

