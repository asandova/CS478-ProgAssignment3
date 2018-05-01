#ifndef ENDECRYPT_H
#define ENDECRYPT_H
#include <openssl\evp.h>
#include <openssl\rsa.h>
#include <openssl\pem.h>
#include <openssl\evp.h>
#include <openssl\bio.h>
#include <openssl\err.h>
#include <string>
/**
FILE: EnDecrypt.h
Author: August B. Sandoval

NOTE:
Used http://hayageek.com/rsa-encryption-decryption-openssl-c/ as tutorial for RSA Encyption & Decryption
*/

using namespace std;

//Part 2 of Project 3
void Encrypt(string& plain, string& keypath,bool pub);

//Part 3 of Project 3
void Decrypt(string& cipher, string& key,bool pub);

string readfile(string& path);

void writefile(unsigned char* data, size_t size, string filename);

unsigned char* ReadKeyPem(string& path);

///Methods for RSA Encryption and Decryption
extern int padding;
RSA * createRSAinstance(unsigned char * key, int pub);
int pub_encrypt(unsigned char * data, int data_len, unsigned char * key, unsigned char *encrypted);
int priv_encrypt(unsigned char * data, int data_len, unsigned char * key, unsigned char *encrypted);
int pub_decrypt(unsigned char * enc_data, int data_len, unsigned char * key, unsigned char *decrypted);
int priv_decrypt(unsigned char * data, int data_len, unsigned char * key, unsigned char *encrypted);
void printLastError(char *msg);

#endif // !ENDECRYPT_H
