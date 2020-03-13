#define _CRT_SECURE_NO_DEPRECATE
#define _CRT_SECURE_NO_WARNINGS

/* $Id$ */
#ifdef __linux__
#define _BSD_SOURCE 1
#define _POSIX_C_SOURCE 2
#endif
#include <ctype.h>
#include <locale.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
//#include <unistd.h>
#include "../lib/libunshield.h"
#include <io.h>
#ifdef HAVE_CONFIG_H
#include "../lib/unshield_config.h"
#endif
#if HAVE_FNMATCH
#include <fnmatch.h>
#endif

#include <direct.h>
#include <iostream>

#include "../lib/internal.h"

#ifndef VERSION
#define VERSION "Unknown"
#endif

#include <stdio.h>
#include <string.h>

int opterr = 1,     /* if error message should be printed */
    optind = 1,     /* index into parent argv vector */
    optopt,         /* character checked for validity */
    optreset;       /* reset getopt */
const char *optarg; /* argument associated with option */

#define BADCH (int)'?'
#define BADARG (int)':'
#define EMSG ""

/*
 * getopt --
 *      Parse argc/argv argument vector.
 */
int getopt(int nargc, char *const nargv[], const char *ostr) {
  static const char *place = EMSG; /* option letter processing */
  const char *oli;                 /* option letter list index */

  if (optreset || !*place) { /* update scanning pointer */
    optreset = 0;
    if (optind >= nargc || *(place = nargv[optind]) != '-') {
      place = EMSG;
      return (-1);
    }
    if (place[1] && *++place == '-') { /* found "--" */
      ++optind;
      place = EMSG;
      return (-1);
    }
  } /* option letter okay? */
  if ((optopt = (int)*place++) == (int)':' || !(oli = strchr(ostr, optopt))) {
    /*
     * if the user didn't specify '-' as an option,
     * assume it means -1.
     */
    if (optopt == (int)'-')
      return (-1);
    if (!*place)
      ++optind;
    if (opterr && *ostr != ':')
      (void)printf("illegal option -- %c\n", optopt);
    return (BADCH);
  }
  if (*++oli != ':') { /* don't need argument */
    optarg = NULL;
    if (!*place)
      ++optind;
  } else {      /* need an argument */
    if (*place) /* no white space */
      optarg = place;
    else if (nargc <= ++optind) { /* no arg */
      place = EMSG;
      if (*ostr == ':')
        return (BADARG);
      if (opterr)
        (void)printf("option requires an argument -- %c\n", optopt);
      return (BADCH);
    } else /* white space */
      optarg = nargv[optind];
    place = EMSG;
    ++optind;
  }
  return (optopt); /* dump back option letter */
}

enum class OVERWRITE {
  OVERWRITE_ASK,
  OVERWRITE_NEVER,
  OVERWRITE_ALWAYS,
};

enum class ACTION {
  ACTION_EXTRACT,
  ACTION_LIST_COMPONENTS,
  ACTION_LIST_FILE_GROUPS,
  ACTION_LIST_FILES,
  ACTION_TEST
};

enum class FORMAT { FORMAT_NEW, FORMAT_OLD, FORMAT_RAW };

#define DEFAULT_OUTPUT_DIRECTORY "."

static const char *output_directory = DEFAULT_OUTPUT_DIRECTORY;
static const char *file_group_name = NULL;
static const char *component_name = NULL;
static bool junk_paths = false;
static bool make_lowercase = false;
static bool verbose = false;
static ACTION action = ACTION::ACTION_EXTRACT;
static OVERWRITE overwrite = OVERWRITE::OVERWRITE_ASK;
static int log_level = UNSHIELD_LOG_LEVEL_LOWEST;
static int exit_status = 0;
static FORMAT format = FORMAT::FORMAT_NEW;
static int is_version = -1;
static const char *cab_file_name = NULL;
static char *const *path_names = NULL;
static int path_name_count = 0;

static void show_usage(const char *name) {
  fprintf(
      stderr,
      "Syntax:\n"
      "\n"
      "\t%s [-c COMPONENT] [-d DIRECTORY] [-D LEVEL] [-g GROUP] [-i VERSION] "
      "[-GhlOrV] c|g|l|t|x CABFILE [FILENAME...]\n"
      "\n"
      "Options:\n"
      "\t-c COMPONENT  Only list/extract this component\n"
      "\t-d DIRECTORY  Extract files to DIRECTORY\n"
      "\t-D LEVEL      Set debug log level\n"
      "\t                0 - No logging (default)\n"
      "\t                1 - Errors only\n"
      "\t                2 - Errors and warnings\n"
      "\t                3 - Errors, warnings and debug messages\n"
      "\t-g GROUP      Only list/extract this file group\n"
      "\t-h            Show this help message\n"
      "\t-i VERSION    Force InstallShield version number (don't autodetect)\n"
      "\t-j            Junk paths (do not make directories)\n"
      "\t-L            Make file and directory names lowercase\n"
      "\t-O            Use old compression\n"
      "\t-r            Save raw data (do not decompress)\n"
      "\t-V            Print copyright and version information\n"
      "\n"
      "Commands:\n"
      "\tc             List components\n"
      "\tg             List file groups\n"
      "\tl             List files\n"
      "\tt             Test files\n"
      "\tx             Extract files\n"
      "\n"
      "Other:\n"
      "\tCABFILE       The file to list or extract contents of\n"
      "\tFILENAME...   Optionally specify names of specific files to extract"
#if HAVE_FNMATCH
      " (wildcards are supported)"
#endif
      "\n",
      name);

#if 0
      "\t-n            Never overwrite files\n"
      "\t-o            Overwrite files WITHOUT prompting\n"
      "\t-v            Verbose output\n"
#endif
}

static bool handle_parameters(int argc, char *const argv[]) {
  int c;

  while ((c = getopt(argc, argv, "c:d:D:g:hi:jLnoOrV")) != -1) {
    switch (c) {
    case 'c':
      component_name = optarg;
      break;

    case 'd':
      output_directory = optarg;
      break;

    case 'D':
      log_level = atoi(optarg);
      break;

    case 'g':
      file_group_name = optarg;
      break;

    case 'i':
      is_version = atoi(optarg);
      break;

    case 'j':
      junk_paths = true;
      break;

    case 'L':
      make_lowercase = true;
      break;

    case 'n':
      overwrite = OVERWRITE::OVERWRITE_NEVER;
      break;

    case 'o':
      overwrite = OVERWRITE::OVERWRITE_ALWAYS;
      break;

    case 'O':
      format = FORMAT::FORMAT_OLD;
      break;

    case 'r':
      format = FORMAT::FORMAT_RAW;
      break;

    case 'v':
      verbose = true;
      break;

    case 'V':
      printf("Unshield version " VERSION
             ". Copyright (C) 2003-2013 David Eriksson.\n");
      exit(0);
      break;

    case 'h':
    default:
      show_usage(argv[0]);
      return false;
    }
  }

  unshield_set_log_level(log_level);

  if (optind == argc || !argv[optind]) {
    fprintf(stderr, "No action provided on command line.\n\n");
    show_usage(argv[0]);
    return false;
  }

  char action_char = argv[optind++][0];
  switch (action_char) {
  case 'c':
    action = ACTION::ACTION_LIST_COMPONENTS;
    break;

  case 'g':
    action = ACTION::ACTION_LIST_FILE_GROUPS;
    break;

  case 'l':
    action = ACTION::ACTION_LIST_FILES;
    break;

  case 't':
    action = ACTION::ACTION_TEST;
    break;

  case 'x':
    action = ACTION::ACTION_EXTRACT;
    break;

  default:
    fprintf(stderr, "Unknown action '%c' on command line.\n\n", action_char);
    show_usage(argv[0]);
    return false;
  }

  cab_file_name = argv[optind++];

  if (cab_file_name == NULL) {
    fprintf(stderr,
            "No InstallShield Cabinet File name provided on command line.\n\n");
    show_usage(argv[0]);
    return false;
  }

  path_name_count = argc - optind;
  path_names = &argv[optind];

  return true;
}

// Perform cleanup of name and characters in path. No idea
// why this is needed.
void cleanup_path(std::filesystem::path &pa, bool make_lowercase) {
  std::string pathString = pa.generic_string();
  for (char &c : pathString) {
    switch (c) {
    case ' ':
    case '<':
    case '>':
    case '[':
    case ']':
      c = '_';
      break;
    default:
      if (!isprint(c))
        c = '_';
      else if (make_lowercase)
        c = tolower(c);
      break;
      ;
    }
  }
  pa.assign(std::filesystem::path(pathString).make_preferred());
}

bool Unshield::extract_file(const char *prefix, int index) {
  bool success = false;

  int directory = this->unshield_file_directory(index);

  std::filesystem::path dirpath = output_directory;

  if (prefix && prefix[0]) {
    dirpath.append(prefix);
  }

  if (!junk_paths && directory >= 0) {
    const char *tmp = this->unshield_directory_name(directory);
    if (tmp && tmp[0]) {
      dirpath.append(tmp);
    }
  }

  cleanup_path(dirpath, make_lowercase);

  bool createsuccess = std::filesystem::create_directories(dirpath);

  std::filesystem::path filenamepath = dirpath;

  filenamepath.append(this->unshield_file_name(index));

  cleanup_path(filenamepath, make_lowercase);

  std::cout << "  extracting: " << filenamepath << std::endl;
  switch (format) {
  case FORMAT::FORMAT_NEW:
    success = this->unshield_file_save(index, filenamepath);
    break;
  case FORMAT::FORMAT_OLD:
    success = this->unshield_file_save_old(index, filenamepath);
    break;
  case FORMAT::FORMAT_RAW:
    success = this->unshield_file_save_raw(index, filenamepath);
    break;
  }

  if (!success) {
    fprintf(stderr, "Failed to extract file '%s'.%s\n",
            this->unshield_file_name(index),
            (log_level < 3)
                ? "Run unshield again with -D 3 for more information."
                : "");
    exit_status = 1;
  }

  return success;
}

bool Unshield::should_process_file(int index) {
  int i;

  if (path_name_count == 0)
    return true;

  for (i = 0; i < path_name_count; i++) {
#if HAVE_FNMATCH
    if (fnmatch(path_names[i], unshield_file_name(unshield, index), 0) == 0)
      return true;
#else
    if (strcmp(path_names[i], this->unshield_file_name(index)) == 0)
      return true;
#endif
  }

  return false;
}

int Unshield::extract_helper(const char *prefix, int first, int last) /*{{{*/
{
  int i;
  int count = 0;

  for (i = first; i <= last; i++) {
    if (this->unshield_file_is_valid(i) && this->should_process_file(i) &&
        this->extract_file(prefix, i))
      count++;
  }

  return count;
} /*}}}*/

bool Unshield::test_file(int index) {
  printf("  testing: %s\n", this->unshield_file_name(index));

  std::filesystem::path nope;
  bool success = this->unshield_file_save(index, nope);
  if (!success) {
    fprintf(stderr, "Failed to extract file '%s'.%s\n",
            this->unshield_file_name(index),
            (log_level < 3)
                ? "Run unshield again with -D 3 for more information."
                : "");
    exit_status = 1;
  }

  return success;
}

int Unshield::test_helper(const char *prefix, int first, int last) /*{{{*/
{
  int i;
  int count = 0;

  for (i = first; i <= last; i++) {
    if (this->unshield_file_is_valid(i) && this->test_file(i))
      count++;
  }

  return count;
} /*}}}*/

bool Unshield::list_components() const {
  size_t count = this->unshield_component_count();

  if (count < 0)
    return false;

  for (size_t i = 0; i < count; i++) {
    printf("%s\n", this->unshield_component_name(i));
  }

  printf("-------\n%zd components\n", count);

  return true;
}

bool Unshield::list_file_groups() const {
  size_t count = this->unshield_file_group_count();

  if (count < 0)
    return false;

  for (size_t i = 0; i < count; i++) {
    printf("%s\n", this->unshield_file_group_name(i));
  }

  printf("-------\n%zd file groups\n", count);

  return true;
}

int Unshield::list_files_helper(const char *prefix, int first, int last) /*{{{*/
{
  int i;
  int valid_count = 0;

  for (i = first; i <= last; i++) {
    if (this->unshield_file_is_valid(i) && this->should_process_file(i)) {
      valid_count++;

      std::filesystem::path dirpath;

      if (prefix && prefix[0]) {
        dirpath.append(prefix);
      }

      dirpath.append(
          this->unshield_directory_name(this->unshield_file_directory(i)));

      printf(" %8zi  %s%s\n", this->unshield_file_size(i),
             dirpath.make_preferred().generic_string().c_str(),
             this->unshield_file_name(i));
    }
  }

  return valid_count;
} /*}}}*/

bool Unshield::do_action(ActionHelper helper) {
  int count = 0;

  if (component_name) {
    abort();
  } else if (file_group_name) {
    UnshieldFileGroup *file_group =
        this->unshield_file_group_find(file_group_name);
    printf("File group: %s\n", file_group_name);
    if (file_group)
      count = (this->*helper)(file_group_name, file_group->first_file,
                              file_group->last_file);
  } else {
    for (size_t i = 0; i < this->unshield_file_group_count(); i++) {
      UnshieldFileGroup *file_group = this->unshield_file_group_get(i);
      if (file_group)
        count += (this->*helper)(file_group->name, file_group->first_file,
                                 file_group->last_file);
    }
  }

  printf(" --------  -------\n          %i files\n", count);

  return true;
}

int main(int argc, char *const argv[]) {
  bool success = false;
  Unshield *unshield = NULL;

  setlocale(LC_ALL, "");

  if (!handle_parameters(argc, argv))
    goto exit;

  unshield = unshield_open_force_version(cab_file_name, is_version);
  if (!unshield) {
    fprintf(stderr, "Failed to open %s as an InstallShield Cabinet File\n",
            cab_file_name);
    goto exit;
  }

  printf("Cabinet: %s\n", cab_file_name);

  switch (action) {
  case ACTION::ACTION_EXTRACT:
    success = unshield->do_action(&Unshield::extract_helper);
    break;

  case ACTION::ACTION_LIST_COMPONENTS:
    success = unshield->list_components();
    break;

  case ACTION::ACTION_LIST_FILE_GROUPS:
    success = unshield->list_file_groups();
    break;

  case ACTION::ACTION_LIST_FILES:
    success = unshield->do_action(&Unshield::list_files_helper);
    break;

  case ACTION::ACTION_TEST:
    if (strcmp(output_directory, DEFAULT_OUTPUT_DIRECTORY) != 0)
      fprintf(stderr, "Output directory (-d) option has no effect with test "
                      "(t) command.\n");
    if (make_lowercase)
      fprintf(
          stderr,
          "Make lowercase (-L) option has no effect with test (t) command.\n");
    success = unshield->do_action(&Unshield::test_helper);
    break;
  }

exit:
  unshield_close(unshield);
  if (!success)
    exit_status = 1;
  return exit_status;
}

bool unshield_is_unicode(Unshield *unshield) {
  if (unshield) {
    Header *header = unshield->header_list;

    return header->major_version >= 17;
  } else
    return false;
}
