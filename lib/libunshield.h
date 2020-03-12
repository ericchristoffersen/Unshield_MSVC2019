/* $Id$ */
#ifndef __unshield_h__
#define __unshield_h__

#include <filesystem>
#include <stdbool.h>
#include <stddef.h>

#define UNSHIELD_LOG_LEVEL_LOWEST    0

#define UNSHIELD_LOG_LEVEL_ERROR     1
#define UNSHIELD_LOG_LEVEL_WARNING   2
#define UNSHIELD_LOG_LEVEL_TRACE     3

#define UNSHIELD_LOG_LEVEL_HIGHEST   4


typedef struct _Unshield Unshield;


/*
   Logging
 */

void unshield_set_log_level(int level);


/*
   Open/close functions
 */

Unshield* unshield_open(const char* filename);
Unshield* unshield_open_force_version(const char* filename, int version);
void unshield_close(Unshield* unshield);

/*
   Component functions
 */

typedef struct _Header Header;
struct _Header;

struct UnshieldComponent
{
  const char* name;
  unsigned file_group_count;
  const char** file_group_names;

  UnshieldComponent(Header* header, uint32_t offset);
  ~UnshieldComponent();
};

/*
   File group functions
 */

struct UnshieldFileGroup
{
  const char* name;
  unsigned first_file;
  unsigned last_file;

  UnshieldFileGroup(Header* header, uint32_t offset);
};


/** Deobfuscate a buffer. Seed is 0 at file start */
void unshield_deobfuscate(unsigned char* buffer, size_t size, unsigned* seed);

/** Is the archive Unicode-capable? */
bool unshield_is_unicode(Unshield* unshield);

#endif

