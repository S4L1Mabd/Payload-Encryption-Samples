#include<windows.h>
#include"rc4.h"

/* Notice :  the struct and the function algorithm of rc4init and rc4cipher  is from maldev accademy */

void rc4init(Rc4Context* context, const unsigned char* key, size_t length)
{
	unsigned int i;
	unsigned int j;
	unsigned char temp;
	// Check parameters
	if (context == NULL || key == NULL)
		return ERROR_INVALID_PARAMETER;
	// Clear context
	context->i = 0;
	context->j = 0;
	// Initialize the S array with identity permutation
	for (i = 0; i < 256; i++)

	{
		context->s[i] = i;
	}
	// S is then processed for 256 iterations
	for (i = 0, j = 0; i < 256; i++)
	{
		//Randomize the permutations using the supplied key
		unsigned int keyIndex = i % length;  // Calculate the index for the key
		unsigned int sum = j + context->s[i] + key[keyIndex];  // Add j, S[i], and key value
		j = sum % 256;  // Apply modulo 256

		//Swap the values of S[i] and S[j]
		temp = context->s[i];
		context->s[i] = context->s[j];
		context->s[j] = temp;
	}
}

void rc4cipher(Rc4Context* context, const unsigned char* input, unsigned char* output, size_t length) {
	unsigned char temp;
	// Restore context
	unsigned int i = context->i;
	unsigned int j = context->j;
	unsigned char* s = context->s;
	// Encryption loop
	while (length > 0)
	{
		// Adjust indices
		i = (i + 1) % 256;
		j = (j + s[i]) % 256;
		// Swap the values of S[i] and S[j]
		temp = s[i];
		s[i] = s[j];
		s[j] = temp;
		// Valid input and output?
		if (input != NULL && output != NULL)
		{
			//XOR the input data with the RC4 stream
			
				* output = *input ^ s[(s[i] + s[j]) % 256];
			//Increment data pointers
			input++;
			output++;
		}
		// Remaining bytes to process
		length--;
	}
	// Save context
	context->i = i;
	context->j = j;
}