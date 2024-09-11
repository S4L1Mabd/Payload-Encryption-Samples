#pragma once
#include <windows.h>
#include<bcrypt.h>
#include <ntstatus.h>

/* Notice :  the structs and the functions algorithm of AES Encryption  is from maldev accademy */


#define IVSIZE 16
#define KEYSIZE 32
#define NT_SUCCESS(Status) (((NTSTATUS)(Status) >= 0))


typedef struct _AES {
	PBYTE pPlainText; // base address of the plain text data 
	DWORD dwPlainSize; // size of the plain text data
	PBYTE pCipherText; // base address of the encrypted data
	DWORD dwCipherSize; // size of it (this can change from dwPlainSize in case there was padding)
	PBYTE pKey; // the 32 byte key
	PBYTE pIv; // the 16 byte iv
} AES, * PAES;

void GenerateRandomBytes(unsigned char* buffer, size_t length);
BOOL SimpleEncryption(IN PVOID pPlainTextData, IN DWORD sPlainTextSize, IN PBYTE pKey, IN PBYTE pIv, OUT PVOID* pCipherTextData, OUT DWORD* sCipherTextSize);
BOOL SimpleDecryption(IN PVOID pCipherTextData, IN DWORD sCipherTextSize, IN PBYTE pKey, IN PBYTE pIv, OUT PVOID* pPlainTextData, OUT DWORD* sPlainTextSize);
VOID PrintHexData(LPCSTR Name, PBYTE Data, SIZE_T Size);
BOOL InstallAesEncryption(PAES pAes);
BOOL InstallAesDecryption(PAES pAes);




