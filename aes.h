#ifndef AES_H
#define AES_H

#include <stdint.h>

#define BLOCK_SIZE 16
#define DEBUG_PRINT printf
// The number of columns comprising a state in AES. This is a constant in AES. Value=4
#define Nb 4

extern const int Nr;
extern const int Nk;

extern uint8_t secret_key[16];

void AES_Cipher(uint8_t *state, const uint8_t* RoundKey);
void AES_Inv_Cipher(uint8_t *state, const uint8_t* RoundKey);

void KeyExpansion(uint8_t* roundKeys, const uint8_t* key);

void SubBytes(uint8_t *state);
void ShiftRows(uint8_t *state);
void MixColumns(uint8_t *state);
void AddRoundKey(uint8_t round, uint8_t *state, const uint8_t* RoundKey);

void InvSubBytes(uint8_t *state);
void InvShiftRows(uint8_t *state);
void InvMixColumns(uint8_t *state);

#endif // AES_H
