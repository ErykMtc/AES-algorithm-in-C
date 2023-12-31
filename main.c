#include <stdio.h>
#include <stdlib.h>
#include <omp.h>

#include "aes.h"

// Function for AES encryption
void encrypt_blocks(char* blocks, int num_blocks) {
    uint8_t roundKeys[(Nr + 1) * 4 * 4];

    #pragma omp parallel for shared(blocks, roundKeys)
    for (int i = 0; i < num_blocks; i++) {
        int block_offset = i * BLOCK_SIZE;
        KeyExpansion(roundKeys, secret_key);
        AES_Cipher(&blocks[block_offset], roundKeys);
    }
}

// Function for AES decryption
void decrypt_blocks(char* blocks, int num_blocks) {
    uint8_t roundKeys[(Nr + 1) * 4 * 4];

    #pragma omp parallel for shared(blocks, roundKeys)
    for (int i = 0; i < num_blocks; i++) {
        int block_offset = i * BLOCK_SIZE;
        KeyExpansion(roundKeys, secret_key);
        AES_Inv_Cipher(&blocks[block_offset], roundKeys);
    }
}

int main() {
    uint8_t *content;
    long file_size;

    double start; 
    double end; 
     
    

    // Encryption Phase
    {
        FILE *file;
        const char* file_name = "bible.txt"; // Change this to your input file

        file = fopen(file_name, "rb");
        if (file == NULL) {
            perror("Error opening the input file");
            return 1;
        }

        fseek(file, 0, SEEK_END);
        file_size = ftell(file);
        rewind(file);

        content = (uint8_t *)malloc(file_size);
        fread(content, file_size, 1, file);
        fclose(file);
    }

    start = omp_get_wtime();

    encrypt_blocks((char *)content, file_size / BLOCK_SIZE);

    end = omp_get_wtime(); 
    printf("Encrypted in %f seconds\n", end - start);

    {
        FILE *encrypted_file = fopen("Encrypted_message.txt", "wb");
        if (encrypted_file == NULL) {
            perror("Error opening the encrypted file");
            return 1;
        }
        fwrite(content, file_size, 1, encrypted_file);
        fclose(encrypted_file);

        free(content);
    }

    // Decryption Phase
    {
        FILE *file;
        const char* file_name = "Encrypted_message.txt"; // Change this to your encrypted file

        file = fopen(file_name, "rb");
        if (file == NULL) {
            perror("Error opening the encrypted file");
            return 1;
        }

        fseek(file, 0, SEEK_END);
        file_size = ftell(file);
        rewind(file);

        content = (uint8_t *)malloc(file_size);
        fread(content, file_size, 1, file);
        fclose(file);
    }

    start = omp_get_wtime();

    decrypt_blocks((char *)content, file_size / BLOCK_SIZE);

    end = omp_get_wtime(); 
    printf("Decrypted in %f seconds\n", end - start);

    {
        FILE *dencrypted_file = fopen("Decrypted_message.txt", "wb");
        if (dencrypted_file == NULL) {
            perror("Error opening the encrypted file");
            return 1;
        }
        fwrite(content, file_size, 1, dencrypted_file);
        fclose(dencrypted_file);

        free(content);
    }

    return 0;
}