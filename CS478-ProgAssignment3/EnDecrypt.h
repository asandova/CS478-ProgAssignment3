#ifndef ENDECRYPT_H
#define ENDECRYPT_H
#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/evp.h>
#include <openssl/crypto.h>
#include <openssl/engine.h>
#include <openssl/rand.h>
#include <string>
/**
FILE: EnDecrypt.h
Author: August B. Sandoval

NOTE:
	I had received help from classmates to get openssl to work
*/

using namespace std;

//Part 2 of Project 3
extern void PARTII(string pub3path, string sessionpath, string privkeypath, string plainpath, string IVpath);

//Part 3 of Project 3
extern void PARTIII(string pubpath, string sessionpath, string cipherpath, string IVpath, string signpath);

void DecryptPub(string cipherpath, string pubkeypath, string outpath);
void sign(string plainpath, string privpath, string outpath);
int verify_sign(string pubkeyPath, string cipherPath, string sign);
string readfile(string& path);
void writefile(const char* data, size_t size, string filename);



#endif // !ENDECRYPT_H
