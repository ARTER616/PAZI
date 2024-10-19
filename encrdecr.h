#ifndef ENCRDECR_H
#define ENCRDECR_H

int encryption(const char *file1_name, const char *file2_name, unsigned char *key, unsigned char *initVector);
int decryption(const char *file1_name, const char *file2_name, unsigned char *key, unsigned char *initVector);

#endif
