/**
 * File name: smllib_tools.c
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

#include "smllib_types.h"
#include "smllib_tools.h"

#include <stdlib.h>

#ifdef SMLLIB_DEBUG
	#include <stdio.h>
#endif

uint16_t crc16_ccitt(const unsigned char* data, uint32_t length) {
	uint16_t crc;
	uint32_t c;
	uint8_t i;

	uint8_t byte;
	uint8_t crcbit;
	uint8_t databit;

	crc = 0xFFFF;
	for (c = 0; c < length; c++) {
		byte = data[c];
		for (i = 0; i < 8; i++) {
			crcbit = (crc & 0x8000) ? 1 : 0;
			databit = (byte & 0x80) ? 1 : 0;
			crc = (uint16_t)(crc << 1);
			byte = (uint8_t)(byte << 1);
			if (crcbit != databit) {
				crc = crc ^ 0x1021;
			}
		}
	}

	return crc;
}

SML_Boolean bigendian_check(void) {
	int no = 1;
	char *chk = (char*)&no;
	return (chk[0] == 1 ? FALSE : TRUE);
}

void endian_swap16(uint16_t* x) {
    *x = (uint16_t)(((*x)>>8) | ((*x)<<8));
}

void endian_swap32(uint32_t* x) {
	*x = (uint32_t)(((*x)>>24) |
        (((*x)<<8) & 0x00FF0000) |
        (((*x)>>8) & 0x0000FF00) |
        ((*x)<<24));
}

void endian_swap64(uint64_t* x) {
	*x = (uint64_t)(((*x)>>56) |
        (((*x)<<40) & 0x00FF000000000000) |
        (((*x)<<24) & 0x0000FF0000000000) |
        (((*x)<<8)  & 0x000000FF00000000) |
        (((*x)>>8)  & 0x00000000FF000000) |
        (((*x)>>24) & 0x0000000000FF0000) |
        (((*x)>>40) & 0x000000000000FF00) |
        ((*x)<<56));
}

int memcmp(const void *s1, const void *s2, size_t n) {
    const unsigned char*  p1   = s1;
    const unsigned char*  end1 = p1 + n;
    const unsigned char*  p2   = s2;
    int                   d = 0;

    for (;;) {
        if (d || p1 >= end1) break;
        d = (int)*p1++ - (int)*p2++;

        if (d || p1 >= end1) break;
        d = (int)*p1++ - (int)*p2++;

        if (d || p1 >= end1) break;
        d = (int)*p1++ - (int)*p2++;

        if (d || p1 >= end1) break;
        d = (int)*p1++ - (int)*p2++;
    }
    return d;
}

void* memcpy(void *dst, const void *src, size_t len) {
	size_t i;
	if ((uintptr_t)dst % sizeof(long) == 0 &&
		(uintptr_t)src % sizeof(long) == 0 &&
		len % sizeof(long) == 0) {
			long *d = dst;
			const long *s = src;
			for (i=0; i<len/sizeof(long); i++) {
				d[i] = s[i];
			}
	}
	else {
		char *d = dst;
		const char *s = src;
		for (i=0; i<len; i++) {
			d[i] = s[i];
		}
	}
	return dst;
}

void* memmove(void *dst, const void *src, size_t len) {
	size_t i;
	if ((uintptr_t)dst < (uintptr_t)src) {
		return memcpy(dst, src, len);
	}
	if ((uintptr_t)dst % sizeof(long) == 0 &&
			(uintptr_t)src % sizeof(long) == 0 &&
			len % sizeof(long) == 0) {
		long *d = dst;
		const long *s = src;
		for (i=len/sizeof(long); i>0; i--) {
			d[i-1] = s[i-1];
		}
	}
	else {
		char *d = dst;
		const char *s = src;
		for (i=len; i>0; i--) {
			d[i-1] = s[i-1];
		}
	}
	return dst;
}

char* strcpy(char *dest, const char *src) {
	size_t i;
	for (i=0; src[i]; i++) {
		dest[i] = src[i];
	}
	dest[i] = 0;
	return dest;
}

size_t strlen(const char *str) {
	const char *s;
	for(s = str; *s; ++s);
	return (size_t)(s - str);
}

void printBinaryResult(const char* field, SML_Encode_Binary_Result* result) {
	#ifdef SMLLIB_DEBUG
		uint32_t i;

		printf(result->length > 50 ? "%s:\n\t" : "%s: ", field);
		for(i=0; i<result->length; i++) {
			if(i % 50 == 0 && i > 0) {
				printf("%s", "\n\t");
			}
			printf("%02X", result->resultBinary[i]);
			printf("%s", " ");
		}
		printf("%s", "\n");
	#endif
}


