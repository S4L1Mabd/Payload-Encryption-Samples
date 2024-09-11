#pragma once

/* Notice :  the struct and the function algorithm is from maldev accademy */

typedef struct
{
	unsigned int i;
	unsigned int j;
	unsigned char s[256];
} Rc4Context;

void rc4init(Rc4Context* context, const unsigned char* rc4key, size_t leng);

void rc4cipher(Rc4Context* context, const unsigned char* input, unsigned char* output, size_t leng);
