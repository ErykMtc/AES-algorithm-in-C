// #include <stdio.h>
// #include <stdlib.h>

#include "aes.h"

// const related to key expansion
const int Nr = 10; // Number of rounds
const int Nk = 4;  // Number of words in the key

uint8_t secret_key[16] = {'k', 'k', 'k', 'k', 'e', 'e', 'e', 'e', 'y', 'y', 'y', 'y', '.', '.', '.', '.'};

static const uint8_t sbox[256] = {
  //0     1    2      3     4    5     6     7      8    9     A      B    C     D     E     F
  0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
  0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
  0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
  0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
  0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
  0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
  0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
  0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
  0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
  0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
  0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
  0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
  0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
  0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
  0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
  0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16 };

static const uint8_t rsbox[256] = {
  0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
  0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
  0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
  0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
  0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
  0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
  0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
  0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
  0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
  0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
  0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
  0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
  0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
  0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
  0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
  0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d };

const uint8_t Rcon[10] = {
  0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36
};

uint8_t getSBoxValue(uint8_t value){
  return sbox[value];
}

uint8_t getSBoxInvert(uint8_t value){
  return rsbox[value];
}

/*****************************************************************************/
/* Encoded blocks section:                                                   */
/*****************************************************************************/

void SubBytes(uint8_t *state){
  int i;
  // substitute all the values from the state with the value in the SBox
  for (i = 0; i < 16; i++)
    state[i] = getSBoxValue(state[i]);
}

void ShiftRows(uint8_t *state){
    uint8_t temp;

    // first row, shift 1 to left
    temp = state[4];
    state[4] = state[5];
    state[5] = state[6];
    state[6] = state[7];
    state[7] = temp;

    // second row, shift 2 to left 
    temp = state[8];
    state[8] = state[10];
    state[10] = temp;
    temp = state[9];
    state[9] = state[11];
    state[11] = temp;

    // third row, shift 3 to left
    temp = state[15];
    state[15] = state[14];
    state[14] = state[13];
    state[13] = state[12];
    state[12] = temp;
}

uint8_t GF_Mult(uint8_t a, uint8_t b) {
  uint8_t result = 0;
  uint8_t shiftGreaterThan255 = 0;

  // Loop through each bit in `b`
  for (uint8_t i = 0; i < 8; i++) {
    // If the LSB is set (i.e. we're not multiplying out by zero for this polynomial term)
    // then we xor the result with `a` (i.e. adding the polynomial terms of a)
    if (b & 1) {
      result ^= a;
    }

    // Double `a`, keeping track of whether that causes `a` to "leave" the field.
    shiftGreaterThan255 = a & 0x80;
    a <<= 1;

    // The next bit we look at in `b` will represent multiplying the terms in `a`
    // by the next power of 2, which is why we can achieve the same result by shifting `a` left.
    // If `a` left the field, we need to modulo with irreducible polynomial term.
    if (shiftGreaterThan255) {
      // Note that we use 0x1b instead of 0x11b. If we weren't taking advantage of
      // u8 overflow (i.e. by using u16, we would use the "real" term)
      a ^= 0x1b;
    }

    // Shift `b` down in order to look at the next LSB (worth twice as much in the multiplication)
    b >>= 1;
  }

  return result;
}

void MixColumns(uint8_t *state){
  int i,j;
  uint8_t column[4];
  uint8_t temp_state[] = { 0, 0, 0, 0 };

  for(i = 0; i < 4; i++){
    for(j=0; j < 4; j++){
      int index = (j*4) + i;
      column[j] = state[index];
    }

    // mix process on single column
    temp_state[0] = GF_Mult(0x02, column[0]) ^ GF_Mult(0x03, column[1]) ^ column[2] ^ column[3];
    temp_state[1] = column[0] ^ GF_Mult(0x02, column[1]) ^ GF_Mult(0x03, column[2]) ^ column[3];
    temp_state[2] = column[0] ^ column[1] ^ GF_Mult(0x02, column[2]) ^ GF_Mult(0x03, column[3]);
    temp_state[3] = GF_Mult(0x03, column[0]) ^ column[1] ^ column[2] ^ GF_Mult(0x02, column[3]);

    for (int j = 0; j < 4; j++) {
      state[(j * 4) + i] = temp_state[j];
    }
  }
}

void AddRoundKey(uint8_t round, uint8_t *state, const uint8_t* RoundKey){
  uint8_t i,j;
  for (i = 0; i < 4; ++i)
  {
    for (j = 0; j < 4; ++j)
    {
      int index = (j*4) + i;
      state[index] ^= RoundKey[(round * Nb * 4) + (i * Nb) + j];
    }
  }
}

/*****************************************************************************/
/* Key initialization section:                                               */
/*****************************************************************************/

// Function to rotate bytes in a word
void RotWord(uint8_t *word) {
    uint8_t temp = word[0];
    word[0] = word[1];
    word[1] = word[2];
    word[2] = word[3];
    word[3] = temp;
}

// Function for basic byte replacement operations
void SubWord(uint8_t *word) {
    for (int i = 0; i < 4; i++) {
        word[i] = getSBoxValue(word[i]);
    }
}

void KeyExpansion(uint8_t* roundKeys, const uint8_t* key){
  uint8_t temp[4];
    
    for (int i = 0; i < Nk; i++) {
        for (int j = 0; j < 4; j++) {
          roundKeys[(i * 4) + j] = key[(i * 4) + j];
        }
    }
    
    for (int i = Nk; i < (Nr + 1) * 4; i++) {
        for (int j = 0; j < 4; j++) {
          temp[j] = roundKeys[(i - 1) * 4 + j];
        }

        if (i % Nk == 0) {
            RotWord(temp);
            SubWord(temp);
            temp[0] ^= Rcon[(i / Nk) - 1];
        } else if (Nk > 6 && i % Nk == 4) {
            SubWord(temp);
        }
        
        for (int j = 0; j < 4; j++) {
            roundKeys[i * 4 + j] = roundKeys[(i - Nk) * 4 + j] ^ temp[j];
        }
    }
}

/*****************************************************************************/
/* Decoded blocks section:                                                   */
/*****************************************************************************/

void InvSubBytes(uint8_t *state){
  int i;
  for (i = 0; i < 16; i++)
    state[i] = getSBoxInvert(state[i]);
}

void InvShiftRows(uint8_t *state){
    uint8_t temp;

    // first row, shift 1 to right
    temp = state[7];
    state[7] = state[6];
    state[6] = state[5];
    state[5] = state[4];
    state[4] = temp;

    // second row, shift 2 to right 
    temp = state[11];
    state[11] = state[9];
    state[9] = temp;
    temp = state[10];
    state[10] = state[8];
    state[8] = temp;

    // third row, shift 3 to right
    temp = state[12];
    state[12] = state[13];
    state[13] = state[14];
    state[14] = state[15];
    state[15] = temp;
}

void InvMixColumns(uint8_t *state){
  int i,j;
  uint8_t column[4];
  uint8_t temp_state[] = { 0, 0, 0, 0 };

  for(i = 0; i < 4; i++){
    for(j=0; j < 4; j++){
      int index = (j*4) + i;
      column[j] = state[index];
    }

    // mix process on single column
    temp_state[0] = GF_Mult(0x0e, column[0]) ^ GF_Mult(0x0b, column[1]) ^ GF_Mult(0x0d, column[2]) ^ GF_Mult(0x09, column[3]);
    temp_state[1] = GF_Mult(0x09, column[0]) ^ GF_Mult(0x0e, column[1]) ^ GF_Mult(0x0b, column[2]) ^ GF_Mult(0x0d, column[3]);
    temp_state[2] = GF_Mult(0x0d, column[0]) ^ GF_Mult(0x09, column[1]) ^ GF_Mult(0x0e, column[2]) ^ GF_Mult(0x0b, column[3]);
    temp_state[3] = GF_Mult(0x0b, column[0]) ^ GF_Mult(0x0d, column[1]) ^ GF_Mult(0x09, column[2]) ^ GF_Mult(0x0e, column[3]);

    for (int j = 0; j < 4; j++) {
      state[(j * 4) + i] = temp_state[j];
    }
  }
}

/*****************************************************************************/
/* Logic section:                                                            */
/*****************************************************************************/

void AES_Cipher(uint8_t *state, const uint8_t* RoundKey){
  uint8_t round = 0;
  uint8_t temp[4*Nb];
	uint8_t i, j;

  // Rotate rows
  for (i = 0; i < 4; i++) {
		for (j = 0; j < Nb; j++) {
			temp[Nb*i+j] = state[i+4*j];
		}
	}

  // Add the First round key to the state before starting the rounds.
  AddRoundKey(0, temp, RoundKey);

  // encryption round
  for (round = 1; ; ++round)
  {
    SubBytes(temp);
    ShiftRows(temp);
    if (round == Nr) {
      break;
    }
    MixColumns(temp);
    AddRoundKey(round, temp, RoundKey);
  }

  // Add round key to last round
  AddRoundKey(Nr, temp, RoundKey);

  for (i = 0; i < 4; i++) {
		for (j = 0; j < Nb; j++) {
			state[i+4*j] = temp[Nb*i+j];
		}
	}

  // for(int i = 0; i <16; i++){
    // DEBUG_PRINT("%02x ", state[i]);
  // }
}

void AES_Inv_Cipher(uint8_t *state, const uint8_t* RoundKey){
  uint8_t round = 0;
  uint8_t temp[4*Nb];
	uint8_t i, j;

  // Rotate rows
  for (i = 0; i < 4; i++) {
		for (j = 0; j < Nb; j++) {
			temp[Nb*i+j] = state[i+4*j];
		}
	}

  AddRoundKey(Nr, temp, RoundKey);

  // decryption round
  for (round = (Nr - 1); ; --round)
  {
    InvShiftRows(temp);
    InvSubBytes(temp);
    AddRoundKey(round, temp, RoundKey);
    if (round == 0) {
      break;
    }
    InvMixColumns(temp);
  }

  for (i = 0; i < 4; i++) {
		for (j = 0; j < Nb; j++) {
			state[i+4*j] = temp[Nb*i+j];
		} 
	}

  // for(int i = 0; i <16; i++){
    // DEBUG_PRINT("%c ", state[i]);
  // }
}