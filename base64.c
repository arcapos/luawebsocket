/*
 * Copyright (c) 2014 by Micro Systems Marc Balmer, CH-5073 Gipf-Oberfrick
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *     * Redistributions of source code must retain the above copyright
 *       notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above copyright
 *       notice, this list of conditions and the following disclaimer in the
 *       documentation and/or other materials provided with the distribution.
 *     * Neither the name of Micro Systems Marc Balmer nor the
 *       names of its contributors may be used to endorse or promote products
 *       derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL <COPYRIGHT HOLDER> BE LIABLE FOR ANY
 * DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

/* base64 encoding for the Lua websockets module*/

/*
 * Based on:
 *
 * lbase64.c
 * base64 encoding and decoding for Lua 5.1
 * Luiz Henrique de Figueiredo <lhf@tecgraf.puc-rio.br>
 * 23 Mar 2010 22:22:38
 * This code is hereby placed in the public domain.
 */

#include <stdlib.h>
#include <string.h>

#include "base64.h"

static const char code[]=
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

static void
encode(char *b, unsigned int c1, unsigned int c2, unsigned int c3, int n)
{
	unsigned long tuple = c3 + 256UL * (c2 + 256UL * c1);
	int i;
	char s[5];

	for (i = 0; i < 4; i++) {
		s[3 - i] = code[tuple % 64];
		tuple /= 64;
	}
	for (i = n + 1; i < 4; i++)
		s[i] = '=';
	s[4] = '\0';
	strcat(b, s);
}

char *
base64(unsigned char *s, size_t l)
{
	char *b;
	int n;

	b = calloc(l * 2, 1);
	if (b) {
		for (n = l / 3; n--; s += 3)
			encode(b, s[0], s[1], s[2], 3);
		switch (l % 3) {
		case 1:
			encode(b, s[0], 0, 0, 1);
			break;
		case 2:
			encode(b, s[0], s[1], 0, 2);
			break;
		}
	}
	return b;
}
