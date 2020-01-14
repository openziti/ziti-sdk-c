/*
Copyright 2019-2020 Netfoundry, Inc.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

https://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

#ifndef ZITI_SDK_ENDIAN_INTERNAL_H
#define ZITI_SDK_ENDIAN_INTERNAL_H

#if (defined(_WIN16) || defined(_WIN32) || defined(_WIN64)) && !defined(__WINDOWS__)
#	define __WINDOWS__
#endif


#if defined(__linux__)
#  include <endian.h>
#elif defined (__APPLE__)
#  include <libkern/OSByteOrder.h>
#  define htole32(x) OSSwapHostToLittleInt32(x)
#  define le32toh(x) OSSwapLittleToHostInt32(x)
#elif defined(__WINDOWS__)
// thanks to https://gist.github.com/PkmX/63dd23f28ba885be53a5
#	include <windows.h>
#	if BYTE_ORDER == LITTLE_ENDIAN
#     if defined(_MSC_VER)
#		include <stdlib.h>
#		define htobe16(x) _byteswap_ushort(x)
#		define htole16(x) (x)
#		define be16toh(x) _byteswap_ushort(x)
#		define le16toh(x) (x)
#		define htobe32(x) _byteswap_ulong(x)
#		define htole32(x) (x)
#		define be32toh(x) _byteswap_ulong(x)
#		define le32toh(x) (x)
#		define htobe64(x) _byteswap_uint64(x)
#		define htole64(x) (x)
#		define be64toh(x) _byteswap_uint64(x)
#		define le64toh(x) (x)
#     elif defined(__GNUC__) || defined(__clang__)
#		define htobe16(x) __builtin_bswap16(x)
#		define htole16(x) (x)
#		define be16toh(x) __builtin_bswap16(x)
#		define le16toh(x) (x)
#		define htobe32(x) __builtin_bswap32(x)
#		define htole32(x) (x)
#		define be32toh(x) __builtin_bswap32(x)
#		define le32toh(x) (x)
#		define htobe64(x) __builtin_bswap64(x)
#		define htole64(x) (x)
#		define be64toh(x) __builtin_bswap64(x)
#		define le64toh(x) (x)
#     else
#       error platform not supported
#     endif
#	else
#		error byte order not supported
#	endif
#	define __BYTE_ORDER    BYTE_ORDER
#	define __BIG_ENDIAN    BIG_ENDIAN
#	define __LITTLE_ENDIAN LITTLE_ENDIAN
#	define __PDP_ENDIAN    PDP_ENDIAN

#else // other
#  error Please port endian macros!
#endif

#endif //ZITI_SDK_ENDIAN_INTERNAL_H
