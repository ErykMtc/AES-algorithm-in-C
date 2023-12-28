#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include "aes.h"
#include <mpi.h>

#define BLOCK_SIZE 16

// Function for AES encryption
void encrypt_blocks(char* blocks, int num_blocks) {
    uint8_t roundKeys[(Nr + 1) * 4 * 4];

    for (int i = 0; i < num_blocks; i++) {
        int block_offset = i * BLOCK_SIZE;
        KeyExpansion(roundKeys, secret_key);
        AES_Cipher(&blocks[block_offset], roundKeys);
    }
}

// Function for AES decryption
void decrypt_blocks(char* blocks, int num_blocks) {
    uint8_t roundKeys[(Nr + 1) * 4 * 4];

    for (int i = 0; i < num_blocks; i++) {
        int block_offset = i * BLOCK_SIZE;
        KeyExpansion(roundKeys, secret_key);
        AES_Inv_Cipher(&blocks[block_offset], roundKeys);
    }
}

int main(int argc, char *argv[]) {
    uint8_t *content;
    long file_size;
    double StartTime = 0.0;

    MPI_Init(&argc, &argv);

    int rank, num_procs;
    MPI_Comm_rank(MPI_COMM_WORLD, &rank);
    MPI_Comm_size(MPI_COMM_WORLD, &num_procs);

    // Encryption Phase
    if (rank == 0) {
        FILE *file;
        const char* file_name = "bible.txt"; // Change this to your input file

        file = fopen(file_name, "rb");
        if (file == NULL) {
            perror("Error opening the input file");
            MPI_Abort(MPI_COMM_WORLD, 1);
        }

        fseek(file, 0, SEEK_END);
        file_size = ftell(file);
        rewind(file);

        content = (uint8_t *)malloc(file_size);
        fread(content, file_size, 1, file);
        fclose(file);
        StartTime = MPI_Wtime();
    }

    encrypt_blocks((char *)content, file_size / BLOCK_SIZE);

    if (rank == 0) {
        printf("Encrypted in %f s\n", MPI_Wtime() - StartTime);
        FILE *encrypted_file = fopen("Encrypted_message.txt", "wb");
        if (encrypted_file == NULL) {
            perror("Error opening the encrypted file");
            MPI_Abort(MPI_COMM_WORLD, 1);
        }
        fwrite(content, file_size, 1, encrypted_file);
        fclose(encrypted_file);

        free(content);
    }

    MPI_Barrier(MPI_COMM_WORLD);

    // Decryption Phase
    if (rank == 0)
    {
        FILE *file;
        const char* file_name = "Encrypted_message.txt"; // Change this to your encrypted file

        file = fopen(file_name, "rb");
        if (file == NULL) {
            perror("Error opening the encrypted file");
            MPI_Abort(MPI_COMM_WORLD, 1);
        }

        fseek(file, 0, SEEK_END);
        file_size = ftell(file);
        rewind(file);

        content = (uint8_t *)malloc(file_size);
        fread(content, file_size, 1, file);
        fclose(file);
        StartTime = MPI_Wtime();
    }

    decrypt_blocks((char *)content, file_size / BLOCK_SIZE);

    if (rank == 0)
    {
        printf("Decrypted in %f s\n", MPI_Wtime() - StartTime);
        FILE *dencrypted_file = fopen("Decrypted_message.txt", "wb");
        if (dencrypted_file == NULL) {
            perror("Error opening the encrypted file");
            MPI_Abort(MPI_COMM_WORLD, 1);
        }
        fwrite(content, file_size, 1, dencrypted_file);
        fclose(dencrypted_file);

        free(content);
    }

    MPI_Finalize();

    return 0;
}