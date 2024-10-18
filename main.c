#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>
#include "encrdecr.h"
#include "keygeneration.h"

/**
 * @brief Точка входа программы.
 * 
 * Обрабатывает аргументы командной строки, производит шифрование или дешифрование файла
 * на основе введенного пароля и входного/выходного файлов.
 * 
 * @param argc Количество аргументов командной строки.
 * @param argv Массив аргументов командной строки.
 * @return int Код возврата (0 при успешном выполнении, иначе ненулевое значение).
 */
int main(int argc, char **argv) {
    int opt;
    int mode = -1; // 0 для шифрования, 1 для дешифрования
    char *password = NULL;
    char *file1 = NULL;
    char *file2 = NULL;

    // Обработка аргументов командной строки
    while ((opt = getopt(argc, argv, "edp:i:o:")) != -1) {
        switch (opt) {
            case 'e':
                mode = 0;
                break;
            case 'd':
                mode = 1;
                break;
            case 'p':
                password = optarg;
                break;
            case 'i':
                file1 = optarg;
                break;
            case 'o':
                file2 = optarg;
                break;
            default:
                printf("Usage: %s [-e|-d] -p <password> -i <file1> -o <file2>\n", argv[0]);
    		printf("    -e  Encrypt the file\n");
    		printf("    -d  Decrypt the file\n");
    		printf("    -p  Password\n");
    		printf("    -i  Input file\n");
    		printf("    -o  Output file\n");
                return EXIT_FAILURE;
        }
    }

    // Проверка на корректность ввода параметров
    if (mode == -1 || !password || !file1 || !file2) {
        printf("Usage: %s [-e|-d] -p <password> -i <file1> -o <file2>\n", argv[0]);
    	printf("    -e  Encrypt the file\n");
    	printf("    -d  Decrypt the file\n");
    	printf("    -p  Password\n");
    	printf("    -i  Input file\n");
    	printf("    -o  Output file\n");
        return EXIT_FAILURE;
    }

    unsigned char key[32]; // 256-битный ключ
    unsigned char initVector[16];  // 128-битный вектор инициализации

    unsigned char full_key[48]; // 32 байта для ключа + 16 байт для вектора инициализации

    // Генерация ключа и вектор инициализации на основе пароля
    if (!derive_key_iv(password, full_key)) {
        fprintf(stderr, "Error deriving key and initialization vector.\n");
        return EXIT_FAILURE;
    }

    // Копирование ключа и вектора инициализации в отдельные буферы
    memcpy(key, full_key, 32);
    memcpy(initVector, full_key + 32, 16);

    // Вывод отладочной информации о ключе и векторе инициализации
    printf("Key: ");
    for (int i = 0; i < 32; i++) printf("%02x", key[i]);
    printf("\ninitVector: ");
    for (int i = 0; i < 16; i++) printf("%02x", initVector[i]);
    printf("\n");

    // Выбор режима (шифрование или расшифрование)
    if (mode == 0) {
        if (!encryption(file1, file2, key, initVector)) {
            fprintf(stderr, "Error encrypting file.\n");
            return EXIT_FAILURE;
        }
    } else {
        if (!decryption(file1, file2, key, initVector)) {
            fprintf(stderr, "Error decrypting file.\n");
            return EXIT_FAILURE;
        }
    }

    printf("Operation completed successfully.\n");
    return EXIT_SUCCESS;
}
