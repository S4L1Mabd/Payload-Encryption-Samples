#include <windows.h>
#include<bcrypt.h>
#include <stdio.h>
#include <time.h>
#include <ntstatus.h>
#include"Aes.h"

/* Notice :  the structs and the functions algorithm of AES Encryption  is from maldev accademy */

void GenerateRandomBytes(unsigned char* buffer, size_t length) {
    // Seed the random number generator
    srand((unsigned int)time(NULL));

    for (size_t i = 0; i < length; i++) {
        buffer[i] = (unsigned char)(rand() % 256);
    }
}

BOOL SimpleEncryption(IN PVOID pPlainTextData, IN DWORD sPlainTextSize, IN PBYTE pKey, IN PBYTE pIv, OUT PVOID* pCipherTextData, OUT DWORD* sCipherTextSize) {
    if (pPlainTextData == NULL || sPlainTextSize == NULL || pKey == NULL
        || pIv == NULL)
        return FALSE;
    // Intializing the struct
    AES Aes = {
    .pKey = pKey,
    .pIv = pIv,
    .pPlainText = pPlainTextData,
    .dwPlainSize = sPlainTextSize
    };
    if (!InstallAesEncryption(&Aes)) {
        return FALSE;
    }
    // Saving output
    *pCipherTextData = Aes.pCipherText;
    *sCipherTextSize = Aes.dwCipherSize;
    return TRUE;
}

BOOL SimpleDecryption(IN PVOID pCipherTextData, IN DWORD sCipherTextSize, IN PBYTE pKey, IN PBYTE pIv, OUT PVOID* pPlainTextData, OUT DWORD* sPlainTextSize) {

    if (pCipherTextData == NULL || sCipherTextSize == NULL || pKey ==NULL || pIv == NULL){
        return FALSE;
    }
    // Intializing the struct
    AES Aes = {
    .pKey = pKey,
    .pIv = pIv,
    .pCipherText = pCipherTextData,
    .dwCipherSize = sCipherTextSize
    };
    if (!InstallAesDecryption(&Aes)) {
        return FALSE;
    }
    // Saving output
    *pPlainTextData = Aes.pPlainText;
    *sPlainTextSize = Aes.dwPlainSize;
    return TRUE;
}

/*Helper function roujiii */
VOID PrintHexData(LPCSTR Name, PBYTE Data, SIZE_T Size) {

    printf("unsigned char %s[] = {", Name);
    for (int i = 0; i < Size; i++) {
        if (i % 16 == 0)
            printf("\n\t");

        if (i < Size - 1) {
            printf("0x%0.2X, ", Data[i]);
        }
        else {
            printf("0x%0.2X ", Data[i]);
        }
        printf("};\t");

    }
}

BOOL InstallAesEncryption(PAES pAes) {
    BOOL bSTATE = TRUE;
    BCRYPT_ALG_HANDLE hAlgorithm = NULL;
    BCRYPT_KEY_HANDLE hKeyHandle = NULL;
    ULONG cbResult = NULL;
    DWORD dwBlockSize = NULL;

    DWORD cbKeyObject = NULL;
    PBYTE pbKeyObject = NULL;
    PBYTE pbCipherText = NULL;
    DWORD cbCipherText = NULL;
    NTSTATUS STATUS = NULL;
    // Intializing "hAlgorithm" as AES algorithm Handle
    STATUS = BCryptOpenAlgorithmProvider(&hAlgorithm, BCRYPT_AES_ALGORITHM,
        
        NULL, 0);
    if (!NT_SUCCESS(STATUS)) {
        printf("[!] BCryptOpenAlgorithmProvider Failed With Error: 0x%0.8X \n", STATUS);
            bSTATE = FALSE; goto _EndOfFunc;
    }
    // Getting the size of the key object variable pbKeyObject. This is used by
    
        STATUS = BCryptGetProperty(hAlgorithm, BCRYPT_OBJECT_LENGTH,   (PBYTE)&cbKeyObject, sizeof(DWORD), &cbResult, 0);
    if (!NT_SUCCESS(STATUS)) {
        printf("[!] BCryptGetProperty[1] Failed With Error: 0x%0.8X \n",
            STATUS);
        bSTATE = FALSE; goto _EndOfFunc;
    }
    // Getting the size of the block used in the encryption. Since this is AES it must be 16 bytes.
        STATUS = BCryptGetProperty(hAlgorithm, BCRYPT_BLOCK_LENGTH,
            (PBYTE)&dwBlockSize, sizeof(DWORD), &cbResult, 0);
    if (!NT_SUCCESS(STATUS)) {
        printf("[!] BCryptGetProperty[2] Failed With Error: 0x%0.8X \n",
            STATUS);
        bSTATE = FALSE; goto _EndOfFunc;
    }
    // Checking if block size is 16 bytes
    if (dwBlockSize != 16) {
        bSTATE = FALSE; goto _EndOfFunc;
    }
    // Allocating memory for the key object 
    pbKeyObject = (PBYTE)HeapAlloc(GetProcessHeap(), 0, cbKeyObject);
    if (pbKeyObject == NULL) {
        bSTATE = FALSE; goto _EndOfFunc;
    }
    // Setting Block Cipher Mode to CBC. This uses a 32 byte key and a 16 byte IV.
        STATUS = BCryptSetProperty(hAlgorithm, BCRYPT_CHAINING_MODE,
            (PBYTE)BCRYPT_CHAIN_MODE_CBC, sizeof(BCRYPT_CHAIN_MODE_CBC), 0);
    if (!NT_SUCCESS(STATUS)) {
        printf("[!] BCryptSetProperty Failed With Error: 0x%0.8X \n",
            STATUS);
        bSTATE = FALSE; goto _EndOfFunc;
       
    }
    // Generating the key object from the AES key "pAes->pKey". The output will be saved in pbKeyObject and will be of size cbKeyObject
        STATUS = BCryptGenerateSymmetricKey(hAlgorithm, &hKeyHandle, pbKeyObject,
            cbKeyObject, (PBYTE)pAes->pKey, KEYSIZE, 0);
    if (!NT_SUCCESS(STATUS)) {
        printf("[!] BCryptGenerateSymmetricKey Failed With Error: 0x%0.8X    \n", STATUS);
            bSTATE = FALSE; goto _EndOfFunc;
    }
    // Running BCryptEncrypt first time with NULL output parameters to retrieve  the size of the output buffer which is saved in cbCipherText
        STATUS = BCryptEncrypt(hKeyHandle, (PUCHAR)pAes->pPlainText, (ULONG)pAes -> dwPlainSize, NULL, pAes->pIv, IVSIZE, NULL, 0, &cbCipherText,
            BCRYPT_BLOCK_PADDING);
    if (!NT_SUCCESS(STATUS)) {
        printf("[!] BCryptEncrypt[1] Failed With Error: 0x%0.8X \n", STATUS);
        bSTATE = FALSE; goto _EndOfFunc;
    }
    // Allocating enough memory for the output buffer, cbCipherText
    pbCipherText = (PBYTE)HeapAlloc(GetProcessHeap(), 0, cbCipherText);
    if (pbCipherText == NULL) {
        bSTATE = FALSE; goto _EndOfFunc;
    }
    // Running BCryptEncrypt again with pbCipherText as the output buffer
    STATUS = BCryptEncrypt(hKeyHandle, (PUCHAR)pAes->pPlainText, (ULONG)pAes -> dwPlainSize, NULL, pAes->pIv, IVSIZE, pbCipherText, cbCipherText, &cbResult,
        BCRYPT_BLOCK_PADDING);
    if (!NT_SUCCESS(STATUS)) {
        printf("[!] BCryptEncrypt[2] Failed With Error: 0x%0.8X \n", STATUS);
        bSTATE = FALSE; goto _EndOfFunc;
    }
    // Clean up
_EndOfFunc:
    if (hKeyHandle)
        BCryptDestroyKey(hKeyHandle);
    if (hAlgorithm)
        BCryptCloseAlgorithmProvider(hAlgorithm, 0);
    if (pbKeyObject)
        HeapFree(GetProcessHeap(), 0, pbKeyObject);
    
        if (pbCipherText != NULL && bSTATE) {
            // If everything worked, save pbCipherText and cbCipherText 
            pAes->pCipherText = pbCipherText;
            pAes->dwCipherSize = cbCipherText;
        }
    return bSTATE;
}

BOOL InstallAesDecryption(PAES pAes) {
    BOOL bSTATE = TRUE;
    BCRYPT_ALG_HANDLE hAlgorithm = NULL;
    BCRYPT_KEY_HANDLE hKeyHandle = NULL;
    ULONG cbResult = NULL;
    DWORD dwBlockSize = NULL;

    DWORD cbKeyObject = NULL;
    PBYTE pbKeyObject = NULL;
    PBYTE pbPlainText = NULL;
    DWORD cbPlainText = NULL;
    NTSTATUS STATUS = 0;
    // Intializing "hAlgorithm" as AES algorithm Handle
    STATUS = BCryptOpenAlgorithmProvider(&hAlgorithm, BCRYPT_AES_ALGORITHM,NULL, 0);
    if (!NT_SUCCESS(STATUS)) {
        printf("[!] BCryptOpenAlgorithmProvider Failed With Error: 0x%0.8X \n", STATUS);
            bSTATE = FALSE; goto _EndOfFunc;
    }
    8 / 20;
        // Getting the size of the key object variable pbKeyObject. This is used by  the BCryptGenerateSymmetricKey function later
        STATUS = BCryptGetProperty(hAlgorithm, BCRYPT_OBJECT_LENGTH,(PBYTE)&cbKeyObject, sizeof(DWORD), &cbResult, 0);
    if (!NT_SUCCESS(STATUS)) {
        printf("[!] BCryptGetProperty[1] Failed With Error: 0x%0.8X \n",
            STATUS);
        bSTATE = FALSE; goto _EndOfFunc;
    }

    // Getting the size of the block used in the encryption. Since this is AES it should be 16 bytes.
        STATUS = BCryptGetProperty(hAlgorithm, BCRYPT_BLOCK_LENGTH, (PBYTE)&dwBlockSize, sizeof(DWORD), &cbResult, 0);
    if (!NT_SUCCESS(STATUS)) {
        printf("[!] BCryptGetProperty[2] Failed With Error: 0x%0.8X \n",
            STATUS);
        bSTATE = FALSE; goto _EndOfFunc;
    }

    // Checking if block size is 16 bytes
    if (dwBlockSize != 16) {
        bSTATE = FALSE; goto _EndOfFunc;
    }

    // Allocating memory for the key object 
    pbKeyObject = (PBYTE)HeapAlloc(GetProcessHeap(), 0, cbKeyObject);
    if (pbKeyObject == NULL) {
        bSTATE = FALSE; goto _EndOfFunc;
    }

    // Setting Block Cipher Mode to CBC. This uses a 32 byte key and a 16 byte IV.
        STATUS = BCryptSetProperty(hAlgorithm, BCRYPT_CHAINING_MODE,
            (PBYTE)BCRYPT_CHAIN_MODE_CBC, sizeof(BCRYPT_CHAIN_MODE_CBC), 0);
    if (!NT_SUCCESS(STATUS)) {
        printf("[!] BCryptSetProperty Failed With Error: 0x%0.8X \n",
            STATUS);
        bSTATE = FALSE; goto _EndOfFunc;
    }

    // Generating the key object from the AES key "pAes->pKey". The output willbe saved in pbKeyObject of size cbKeyObject
        STATUS = BCryptGenerateSymmetricKey(hAlgorithm, &hKeyHandle, pbKeyObject,
            cbKeyObject, (PBYTE)pAes->pKey, KEYSIZE, 0);
        9 / 20;
        if (!NT_SUCCESS(STATUS)) {
            printf("[!] BCryptGenerateSymmetricKey Failed With Error: 0x%0.8X \n", STATUS);
                bSTATE = FALSE; goto _EndOfFunc;
        }
    // Running BCryptDecrypt first time with NULL output parameters to retrievethe size of the output buffer which is saved in cbPlainText
        STATUS = BCryptDecrypt(hKeyHandle, (PUCHAR)pAes->pCipherText, (ULONG)pAes -> dwCipherSize, NULL, pAes->pIv, IVSIZE, NULL, 0, &cbPlainText,
BCRYPT_BLOCK_PADDING);
    if (!NT_SUCCESS(STATUS)) {
        printf("[!] BCryptDecrypt[1] Failed With Error: 0x%0.8X \n", STATUS);
        bSTATE = FALSE; goto _EndOfFunc;
    }

    // Allocating enough memory for the output buffer, cbPlainText
    pbPlainText = (PBYTE)HeapAlloc(GetProcessHeap(), 0, cbPlainText);
    if (pbPlainText == NULL) {
        bSTATE = FALSE; goto _EndOfFunc;
    }

    // Running BCryptDecrypt again with pbPlainText as the output buffer
    STATUS = BCryptDecrypt(hKeyHandle, (PUCHAR)pAes->pCipherText, (ULONG)pAes -> dwCipherSize, NULL, pAes->pIv, IVSIZE, pbPlainText, cbPlainText, &cbResult,BCRYPT_BLOCK_PADDING);
    if (!NT_SUCCESS(STATUS)) {
        printf("[!] BCryptDecrypt[2] Failed With Error: 0x%0.8X \n", STATUS);
        bSTATE = FALSE; goto _EndOfFunc;
    }
    // Clean up
_EndOfFunc:
    if (hKeyHandle)
        BCryptDestroyKey(hKeyHandle);
    if (hAlgorithm)
        BCryptCloseAlgorithmProvider(hAlgorithm, 0);
    if (pbKeyObject)
        HeapFree(GetProcessHeap(), 0, pbKeyObject);
    if (pbPlainText != NULL && bSTATE) {
        // if everything went well, we save pbPlainText and cbPlainText
        pAes->pPlainText = pbPlainText;
        pAes->dwPlainSize = cbPlainText;
    }
    return bSTATE;
    10 / 20;
}