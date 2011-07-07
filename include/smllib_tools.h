/**
 * File name: smllib_tools.h
 *
 * @author Christian Reimann <cybernico@gmx.de>
 * @author Tobias Jeske <tobias.jeske@tu-harburg.de>
 * @remark Supported by the Institute for Security in Distributed Applications (http://www.sva.tu-harburg.de)
 * @see The GNU Public License (GPL)
 */
/*
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
 * or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License
 * for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, see <http://www.gnu.org/licenses/>.
 */
#ifndef SMLLIB_TOOLS_H_
#define SMLLIB_TOOLS_H_

#include <stdlib.h>

uint16_t crc16_ccitt(const unsigned char* data, uint32_t length);

SML_Boolean bigendian_check(void);

void endian_swap16(uint16_t* x);

void endian_swap32(uint32_t* x);

void endian_swap64(uint64_t* x);

int memcmp(const void *s1, const void *s2, size_t n);

void* memcpy(void *dst, const void *src, size_t len);

void* memmove(void *dst, const void *src, size_t len);

char* strcpy(char *dest, const char *src);

size_t strlen(const char *str);

void printBinaryResult(const char* field, SML_Encode_Binary_Result* result);

#endif /* SMLLIB_TOOLS_H_ */
