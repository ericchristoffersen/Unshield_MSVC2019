
#define _CRT_SECURE_NO_DEPRECATE

/* $Id$ */
#define _BSD_SOURCE 1
#include "internal.h"
#include "log.h"
#include <assert.h>
#include <ctype.h>
#include <stdlib.h>
#include <string.h>

#include <regex>
#include <iostream>

/**
  Create filenamepath used by unshield_fopen_for_reading()
 */
static bool unshield_create_filename_path(Unshield* unshield, const char* filename)/*{{{*/
{
	if (unshield && filename)
	{
		const std::regex base_regex("(.*\\D+)\\d*.cab$");
		std::smatch base_match;
		std::string filenamestring(filename);

		if (std::regex_search(filenamestring, base_match, base_regex)) {
			if (base_match.size() == 2) {
				std::ssub_match base_sub_match = base_match[1];
				std::string base = base_sub_match.str();

				unshield->filename_path.append(base);
			}

			return true;
		}
	}

	return false;
}

static bool unshield_get_common_header(Header* header)
{
	uint8_t* p = header->data;
	return unshield_read_common_header(&p, &header->common);
}

static bool unshield_get_cab_descriptor(Header* header)
{
	if (header->common.cab_descriptor_size)
	{
		uint8_t* p = header->data + header->common.cab_descriptor_offset;
		int i;

		p += 0xc;
		header->cab.file_table_offset = READ_UINT32(p); p += 4;
		p += 4;
		header->cab.file_table_size = READ_UINT32(p); p += 4;
		header->cab.file_table_size2 = READ_UINT32(p); p += 4;
		header->cab.directory_count = READ_UINT32(p); p += 4;
		p += 8;
		header->cab.file_count = READ_UINT32(p); p += 4;
		header->cab.file_table_offset2 = READ_UINT32(p); p += 4;

		assert((p - (header->data + header->common.cab_descriptor_offset)) == 0x30);

		if (header->cab.file_table_size != header->cab.file_table_size2)
			unshield_warning(L"File table sizes do not match");

		unshield_trace(L"Cabinet descriptor: %08x %08x %08x %08x",
			header->cab.file_table_offset,
			header->cab.file_table_size,
			header->cab.file_table_size2,
			header->cab.file_table_offset2
		);

		unshield_trace(L"Directory count: %i", header->cab.directory_count);
		unshield_trace(L"File count: %i", header->cab.file_count);

		p += 0xe;

		for (i = 0; i < MAX_FILE_GROUP_COUNT; i++)
		{
			header->cab.file_group_offsets[i] = READ_UINT32(p); p += 4;
		}

		for (i = 0; i < MAX_COMPONENT_COUNT; i++)
		{
			header->cab.component_offsets[i] = READ_UINT32(p); p += 4;
		}

		return true;
	}
	else
	{
		unshield_error(L"No CAB descriptor available!");
		return false;
	}
}

static bool unshield_get_file_table(Header* header)
{
	uint8_t* p = header->data +
		header->common.cab_descriptor_offset +
		header->cab.file_table_offset;
	int count = header->cab.directory_count + header->cab.file_count;
	int i;

	header->file_table.resize(count);

	for (i = 0; i < count; i++)
	{
		header->file_table[i] = READ_UINT32(p); p += 4;
	}

	return true;
}

static bool unshield_header_get_components(Header* header)
{
	int count = 0;
	int i;
	int available = 16;

	header->components.resize(available);

	for (i = 0; i < MAX_COMPONENT_COUNT; i++)
	{
		if (header->cab.component_offsets[i])
		{
			OffsetList list;

			list.next_offset = header->cab.component_offsets[i];

			while (list.next_offset)
			{
				uint8_t* p = unshield_header_get_buffer(header, list.next_offset);

				list.name_offset = READ_UINT32(p); p += 4;
				list.descriptor_offset = READ_UINT32(p); p += 4;
				list.next_offset = READ_UINT32(p); p += 4;

				if (count == available)
				{
					available <<= 1;
					header->components.resize(available);
				}

				header->components[count++] = new UnshieldComponent(header, list.descriptor_offset);
			}
		}
	}

	return true;
}

static bool unshield_header_get_file_groups(Header* header)/*{{{*/
{
	int count = 0;
	int i;
	int available = 16;

	header->file_groups.resize(available);

	for (i = 0; i < MAX_FILE_GROUP_COUNT; i++)
	{
		if (header->cab.file_group_offsets[i])
		{
			OffsetList list;

			list.next_offset = header->cab.file_group_offsets[i];

			while (list.next_offset)
			{
				uint8_t* p = unshield_header_get_buffer(header, list.next_offset);

				list.name_offset = READ_UINT32(p); p += 4;
				list.descriptor_offset = READ_UINT32(p); p += 4;
				list.next_offset = READ_UINT32(p); p += 4;

				if (count == available)
				{
					available <<= 1;

					header->file_groups.resize(available);
				}

				header->file_groups[count++] = new UnshieldFileGroup(header, list.descriptor_offset);
			}
		}
	}

	return true;
}  /*}}}*/

#include "zconf.h"
int unshield_uncompress(Byte* dest, uLong* destLen, Byte* source, uLong* sourceLen);

/**
  Read all header files
 */
static bool unshield_readHeaders(Unshield* unshield, int version)/*{{{*/
{
	int i;
	bool iterate = true;
	Header* previous = NULL;

	if (unshield->header_list)
	{
		unshield_warning(L"Already have a header list");
		return true;
	}

	for (i = 1; iterate; i++)
	{
		FILE* file = unshield_fopen_for_reading(unshield, i, HEADER_SUFFIX);

		if (file)
		{
			unshield_trace(L"Reading header from .hdr file %i.", i);
			iterate = false;
		}
		else
		{
			unshield_trace(L"Could not open .hdr file %i. Reading header from .cab file %i instead.",
				i, i);
			file = unshield_fopen_for_reading(unshield, i, CABINET_SUFFIX);
		}

		if (file)
		{
			size_t bytes_read;
			Header* header = new Header();
			header->index = i;

			header->size = unshield_fsize(file);
			if (header->size < 4)
			{
				unshield_error(L"Header file %i too small", i);
				goto error;
			}

			header->data = new uint8_t[header->size];

			bytes_read = fread(header->data, 1, header->size, file);
			FCLOSE(file);

			if (bytes_read != header->size)
			{
#if 0
				char* p = (char*)malloc(header->size);
				memcpy(p, header->data, bytes_read);

				unsigned hsize = 0;

				void unshield_deobfuscate(unsigned char* buffer, size_t size, unsigned* seed)

					unshield_deobfuscate(header->data, &hsize, p, &bytes_read);
				header->size = hsize;
#endif

				unshield_error(L"Failed to read from header file %i. Expected = %i, read = %i",
					i, header->size, bytes_read);
				//goto error;
			}

			if (!unshield_get_common_header(header))
			{
				unshield_error(L"Failed to read common header from header file %i", i);
				goto error;
			}

			if (version != -1)
			{
				header->major_version = version;
			}
			else if (header->common.version >> 24 == 1)
			{
				header->major_version = (header->common.version >> 12) & 0xf;
			}
			else if (header->common.version >> 24 == 2
				|| header->common.version >> 24 == 4)
			{
				header->major_version = (header->common.version & 0xffff);
				if (header->major_version != 0)
					header->major_version = header->major_version / 100;
			}

#if 0
			if (header->major_version < 5)
				header->major_version = 5;
#endif

			unshield_trace(L"Version 0x%08x handled as major version %i",
				header->common.version,
				header->major_version);

			if (!unshield_get_cab_descriptor(header))
			{
				unshield_error(L"Failed to read CAB descriptor from header file %i", i);
				goto error;
			}

			if (!unshield_get_file_table(header))
			{
				unshield_error(L"Failed to read file table from header file %i", i);
				goto error;
			}

			if (!unshield_header_get_components(header))
			{
				unshield_error(L"Failed to read components from header file %i", i);
				goto error;
			}

			if (!unshield_header_get_file_groups(header))
			{
				unshield_error(L"Failed to read file groups from header file %i", i);
				goto error;
			}

			if (previous)
				previous->next = header;
			else
				previous = unshield->header_list = header;

			continue;

		error:
			delete header;
			iterate = false;
		}
		else
			iterate = false;
	}

	return (unshield->header_list != NULL);
}/*}}}*/

Unshield* unshield_open(const char* filename)/*{{{*/
{
	return unshield_open_force_version(filename, -1);
}/*}}}*/

Unshield* unshield_open_force_version(const char* filename, int version)/*{{{*/
{
	Unshield* unshield = new Unshield;

	if (!unshield_create_filename_path(unshield, filename))
	{
		unshield_error(L"Failed to create filename path");
		goto error;
	}

	if (!unshield_readHeaders(unshield, version))
	{
		unshield_error(L"Failed to read header files");
		goto error;
	}

	return unshield;

error:
	unshield_close(unshield);
	return NULL;
}/*}}}*/

void unshield_close(Unshield* unshield)/*{{{*/
{
	delete unshield;
}


