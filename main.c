#include <stdio.h>
#include <stdlib.h>
#include <omp.h>

#include "aes.h"

void create_blocks(char** blocks, int num_blocks, long file_size, uint8_t *file_content){
    // declariation of roundKeys array for KeyExpansion function
    uint8_t roundKeys[(Nr + 1) * 4 * 4];
    int i;

    #pragma omp parallel for shared(blocks, roundKeys) private(i)
    for (i = 0; i < num_blocks; i++) {
        int temp;
        int block_start = i * BLOCK_SIZE;
        int block_end = (i + 1) * BLOCK_SIZE;
        if (block_end > file_size)
            block_end = file_size;

        int block_size = block_end - block_start;

        blocks[i] = (char *)malloc(BLOCK_SIZE + 1);

        for (int j = 0; j < block_size; j++) {
            blocks[i][j] = file_content[block_start + j];
        }

        if(i == num_blocks - 1){
          for (int j = block_size; j < BLOCK_SIZE; j++) {
            blocks[i][j] = (char)(BLOCK_SIZE - block_size);
          }
        }

        blocks[i][BLOCK_SIZE] = '\0';

        // Cipher operations
        KeyExpansion(roundKeys, secret_key);
        AES_Cipher(blocks[i], roundKeys);
    }


}

void create_blocks_decryption(char** blocks, int num_blocks, long file_size, uint8_t *file_content){
    // declariation of roundKeys array for KeyExpansion function
    uint8_t roundKeys[(Nr + 1) * 4 * 4];
    int i;

    #pragma omp parallel for shared(blocks, roundKeys) private(i)
    for (i = 0; i < num_blocks; i++) {
        int block_start = i * BLOCK_SIZE;
        int block_end = (i + 1) * BLOCK_SIZE;
        if (block_end > file_size)
            block_end = file_size;

        int block_size = block_end - block_start;

        for (int j = 0; j < block_size; j++) {
            blocks[i][j] = file_content[block_start + j];
        }

        blocks[i][block_size] = '\0';

        // decryption
        KeyExpansion(roundKeys, secret_key);
        AES_Inv_Cipher(blocks[i], roundKeys);

        // delete padding
        int temp = (int)blocks[num_blocks - 1][15];
        if(i == (num_blocks-1)){
          // DEBUG_PRINT("%s", "temp");
          for (int j = BLOCK_SIZE - 1; j > 0; j--) {
            if((int)blocks[i][j] <= 16 ){
              blocks[i][j] = '\0';
            }
          }
        }
    }
}

int main() {
    FILE *file;
    FILE *file2;
    int index;
    const char* file_name = "pro_sulla.txt";

    file = fopen(file_name, "r");
    if (file == NULL) {
        perror("Error opening the file");
        return 1;
    }

    fseek(file, 0, SEEK_END);
    long file_size = ftell(file);
    rewind(file);

    uint8_t *file_content = (uint8_t *)malloc(file_size + 1);
    if (file_content == NULL) {
        perror("Memory allocation error");
        fclose(file);
        return 1;
    }

    fread(file_content, file_size, 1, file);
    fclose(file);
    file_content[file_size] = '\0';

    //  preparation for division into blocks
    int num_blocks = (file_size + BLOCK_SIZE - 1) / BLOCK_SIZE;
    char **blocks = (char **)malloc(num_blocks * sizeof(char *));
    if (blocks == NULL) {
        perror("Memory allocation error");
        free(file_content);
        return 1;
    }

    create_blocks(blocks, num_blocks, file_size, file_content);

    file = fopen("Encrypted_message.txt", "wb");
    if (file == NULL) {
        perror("Error opening the output file");
        exit(1);
    }

    for (int j = 0; j < num_blocks; j++) {
      for(int i = 0; i< BLOCK_SIZE; i++)
        fprintf(file, "%c", blocks[j][i]);
    }
    fclose(file);

    file = fopen("Encrypted_message.txt", "rb");
    if (file == NULL) {
        perror("Error opening the file");
        return 1;
    }

    fseek(file, 0, SEEK_END);
    file_size = ftell(file);
    rewind(file);

    uint8_t *file_content2 = (uint8_t *)malloc(file_size + 1);
    if (file_content2 == NULL) {
        perror("Memory allocation error");
        fclose(file2);
        return 1;
    }

    fread(file_content2, file_size, 1, file);
    fclose(file);
    file_content2[file_size] = '\0';
    

    create_blocks_decryption(blocks, num_blocks, file_size, file_content2);

    file = fopen("Decrypted_message.txt", "wb");
    if (file == NULL) {
        perror("Error opening the output file");
        exit(1);
    }

    // Write the contents of 'blocks' to the file
    for (int j = 0; j < num_blocks; j++) {
        for(int i = 0; i< BLOCK_SIZE; i++)
          fprintf(file, "%c", blocks[j][i]);
    }
    fclose(file);

    // Clean up
    for (int i = 0; i < num_blocks; i++) {
        free(blocks[i]);
    }
    free(blocks);
    free(file_content);
    free(file_content2);

    return 0;
}