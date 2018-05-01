/*
*	File: des_utils.h
*	Class: CS478
*	Date: 4/13/18
*	Purpose: Contains DES table declarations
*/
#ifndef DES_UTILS_H
#define DES_UTILS_H

/********************************************/
/* Tables for initial and final permutation */
/********************************************/

// initial permutation
extern char IP[64];

// final permutation
extern char FP[64];

/*******************************/
/* Tables for the key schedule */
/*******************************/

// PC-1 table (initial key permutation)
extern int PC1[56];

// PC-2 table (permutation for generating each subkey)
extern int PC2[48];


/*********************************/
/* Tables for the round function */
/*********************************/

// expansion box
extern char E[48];

extern char P[64];

// substitution boxes
// addressable using xxyyyy where xx are the first and last bits, and yyyy are the middle 4 bits
extern char S1[64];

extern char S2[64];

extern char S3[64];

extern char S4[64];

extern char S5[64];

extern char S6[64];

extern char S7[64];

extern char S8[64];
extern const char* SBOXMAP[];

#endif // !DES_UTILS_H
