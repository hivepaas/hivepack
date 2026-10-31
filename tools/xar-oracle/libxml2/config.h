/*
 * The configuration of the libxml2 2.15.4 sources that tools/xar-oracle is
 * built with, in place of the config.h libxml2's CMake, meson or configure
 * script writes: what its parser, reader and writer need, on Linux or
 * macOS. Only what those sources ask for is here.
 */

/* The hash tables' seeds come from the time instead of getentropy, which
 * changes nothing that is parsed. */
#define HAVE_DECL_GETENTROPY 0
#define HAVE_DECL_GLOB 0
#define HAVE_DECL_MMAP 0
#define HAVE_FUNC_ATTRIBUTE_DESTRUCTOR 1
#define HAVE_STDINT_H 1
#define XML_THREAD_LOCAL _Thread_local
