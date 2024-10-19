#include <openssl/evp.h>
#include <openssl/aes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include "encrdecr.h"

#define BUFFER_SIZE 4096  /**< Размер буфера для чтения/записи данных */

/**
 * @brief Шифрует файл с использованием алгоритма AES-256-CBC.
 * 
 * @param file1_name Имя входного файла.
 * @param file2_name Имя выходного файла.
 * @param key Ключ шифрования.
 * @param initVector Вектор инициализации.
 * @return int Возвращает 1 при успехе, 0 при ошибке.
 */
int encryption(const char *file1_name, const char *file2_name, unsigned char *key, unsigned char *initVector) {
    printf("Encrypting file: %s\n", file1_name);
    FILE *file1 = fopen(file1_name, "rb");
    FILE *file2 = fopen(file2_name, "wb");

    if (!file1) {
        perror("Error reading file1");
        return 0;
    }
    if (!file2) {
	fclose(file1);
        perror("Error reading file2");
        return 0;
    }

    printf("Files opened successfully\n");

    // Инициализация контекста шифрования
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
	fclose(file1);
        fclose(file2);
        fprintf(stderr, "Error initializing cipher context\n");
        return 0;
    }

    // Настройка шифрования с использованием AES-256-CBC
    if (1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, initVector)) {
	fclose(file1);
        fclose(file2);
        fprintf(stderr, "Error initializing encryption\n");
        EVP_CIPHER_CTX_free(ctx);
        return 0;
    }

    unsigned char buffer[BUFFER_SIZE];
    unsigned char ciphertext[BUFFER_SIZE + EVP_CIPHER_block_size(EVP_aes_256_cbc())];
    int len;
    int ciphertext_len;

    printf("Starting encryption process...\n");

    // Чтение входного файла и шифрование блоками
    while ((len = fread(buffer, 1, BUFFER_SIZE, file1)) > 0) {
        if (1 != EVP_EncryptUpdate(ctx, ciphertext, &ciphertext_len, buffer, len)) {
	    fclose(file1);
            fclose(file2);
            fprintf(stderr, "Error during encryption\n");
            EVP_CIPHER_CTX_free(ctx);
            return 0;
        }
        fwrite(ciphertext, 1, ciphertext_len, file2);
    }

    // Проверка на ошибки при чтении файла
    if (ferror(file1)) {
	fclose(file1);
        fclose(file2);
        fprintf(stderr, "Error reading input file\n");
        EVP_CIPHER_CTX_free(ctx);
        return 0;
    }

    // Завершение процесса шифрования
    if (1 != EVP_EncryptFinal_ex(ctx, ciphertext, &ciphertext_len)) {
	fclose(file1);
        fclose(file2);
        fprintf(stderr, "Error finalizing encryption\n");
        EVP_CIPHER_CTX_free(ctx);
        return 0;
    }
    fwrite(ciphertext, 1, ciphertext_len, file2);

    printf("Encryption completed successfully\n");

    EVP_CIPHER_CTX_free(ctx);
    fclose(file1);
    fclose(file2);
    return 1;
}

/**
 * @brief Дешифрует файл, зашифрованный алгоритмом AES-256-CBC.
 * 
 * @param file1_name Имя входного файла.
 * @param file2_name Имя выходного файла.
 * @param key Ключ шифрования.
 * @param initVector Вектор инициализации.
 * @return int Возвращает 1 при успехе, 0 при ошибке.
 */
int decryption(const char *file1_name, const char *file2_name, unsigned char *key, unsigned char *initVector) {
    printf("Decrypting file: %s\n", file1_name);
    FILE *file1 = fopen(file1_name, "rb");
    FILE *file2 = fopen(file2_name, "wb");

    if (!file1) {
        perror("Error reading file1");
        return 0;
    }
    if (!file2) {
	fclose(file1);
        perror("Error reading file2");
        return 0;
    }

    printf("Files opened successfully\n");

    // Инициализация контекста дешифрования
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
	fclose(file1);
        fclose(file2);
        fprintf(stderr, "Error initializing cipher context\n");
        return 0;
    }

    // Настройка дешифрования с использованием AES-256-CBC
    if (1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, initVector)) {
	fclose(file1);
        fclose(file2);
        fprintf(stderr, "Error initializing decryption\n");
        EVP_CIPHER_CTX_free(ctx);
        return 0;
    }

    unsigned char buffer[BUFFER_SIZE];
    unsigned char plaintext[BUFFER_SIZE + EVP_CIPHER_block_size(EVP_aes_256_cbc())];
    int len;
    int plaintext_len;

    printf("Starting decryption process...\n");

    // Чтение зашифрованного файла и дешифрование блоками
    while ((len = fread(buffer, 1, BUFFER_SIZE, file1)) > 0) {
        if (1 != EVP_DecryptUpdate(ctx, plaintext, &plaintext_len, buffer, len)) {
	    fclose(file1);
            fclose(file2);
            fprintf(stderr, "Error during decryption\n");
            EVP_CIPHER_CTX_free(ctx);
            return 0;
        }
        fwrite(plaintext, 1, plaintext_len, file2);
    }

    // Проверка на ошибки при чтении файла
    if (ferror(file1)) {
	fclose(file1);
        fclose(file2);
        fprintf(stderr, "Error reading input file\n");
        EVP_CIPHER_CTX_free(ctx);
        return 0;
    }

    // Завершение процесса дешифрования
    if (1 != EVP_DecryptFinal_ex(ctx, plaintext, &plaintext_len)) {
	fclose(file1);
        fclose(file2);
        fprintf(stderr, "Error finalizing decryption\n");
        EVP_CIPHER_CTX_free(ctx);
        return 0;
    }
    fwrite(plaintext, 1, plaintext_len, file2);

    printf("Decryption completed successfully\n");

    EVP_CIPHER_CTX_free(ctx);
    fclose(file1);
    fclose(file2);
    return 1;
}
