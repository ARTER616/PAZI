#include <openssl/evp.h>
#include <string.h>
#include "keygeneration.h"

/**
 * @brief Генерирует ключ и вектор инициализации на основе пароля с использованием PBKDF2-HMAC-SHA-256.
 * 
 * @details Эта функция использует алгоритм PBKDF2 (Password-Based Key Derivation Function 2)
 * с HMAC-SHA-256 для генерации криптографически стойких ключа и вектора инициализации
 * на основе введенного пользователем пароля. PBKDF2 добавляет соль и многократные итерации,
 * чтобы сделать атаку на ключ значительно сложнее.
 * 
 * @param password_for_key Пароль, введенный пользователем, для генерации ключа.
 * @param full_key Буфер для записи сгенерированного ключа длиной 32 байта (256 бит) и вектора инициализации длиной 16 байт (128 бит).
 * @return int Возвращает 1 при успешной генерации ключа и initVector, иначе возвращает 0 в случае ошибки.
 * 
 * @note Длина ключа фиксирована на 256 бит (32 байта), а initVector — на 128 бит (16 байт).
 * Использование соли в алгоритме PBKDF2 увеличивает сложность подбора пароля.
 */
int derive_key_iv(const char *password_for_key, unsigned char *full_key) {
    // Количество итераций для PBKDF2. Чем больше значение, тем сложнее и медленнее будет атака.
    const int iter = 9999; 

    // Соль для PBKDF2.
    const unsigned char *salt = (unsigned char *)"SOME_SALT_FOR_PBKDF2"; 

    // Использование PBKDF2 для генерации ключа и initVector
    if (1 != PKCS5_PBKDF2_HMAC(password_for_key, strlen(password_for_key), salt, strlen((const char *)salt), iter, EVP_sha256(), 48, full_key)) {
        // Ошибка в случае неудачи в генерации ключа и вектора инициализации
        return 0;
    }

    return 1;  // Успешная генерация
}
