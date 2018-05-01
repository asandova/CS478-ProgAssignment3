/**
	FILE: EnDecrypt.cpp
	Author: August B. Sandoval

	NOTE:
		Used http://hayageek.com/rsa-encryption-decryption-openssl-c/ as tutorial for RSA Encyption & Decryption
*/

#include <openssl\evp.h>
#include <openssl\rsa.h>
#include <openssl\ssl.h>
#include <openssl\pem.h>
#include <openssl\evp.h>
#include <openssl\bio.h>
#include <openssl\err.h>
#include <stdlib.h>
#include <fstream>
#include <string>
#include <string.h>
#include <iostream>
#include <stdio.h>
#include "EnDecrypt.h"
#include "DES.h"

using namespace std;

//int padding = RSA_PKCS1_PADDING;//default padding
int padding = RSA_NO_PADDING;//default padding
void Encrypt(string& plainpath, string& keypath,bool pub) {
	/**
	takes a two filepaths one for the file with that plaintext
	and one with the key.
	Also takes a boolean value denoting if key is a public or private
	The function will then output its result to the same file with the added extention ".enc.txt"
	*/
	unsigned char* key = ReadKeyPem(keypath);
	RSA* rsa = createRSAinstance(key, pub);
	string temp = readfile(plainpath);
	unsigned char* plain = (unsigned char*)malloc(sizeof(unsigned char*)*temp.size());
	unsigned char* output = (unsigned char*)malloc(sizeof(unsigned char*)*RSA_size(rsa) );
	//const char* cp = temp.c_str();
	strncpy((char*)plain, temp.c_str(), temp.size());
	//copy(temp.begin(), temp.end(), plain);
	int err;
	if (pub) {
		err = pub_encrypt(plain,temp.size(),key,output);
	}
	else {
		err = priv_encrypt(plain, temp.size(), key, output);
	}
	if (err == -1) {
		string m = "Encryption failed\nExiting..";
		char* msg = (char*)malloc(sizeof(char)*m.size());
		const char* tmp = m.c_str();
		strncpy(msg,tmp,m.size());
		//copy(m.begin(), m.end(), msg);
		printLastError(msg);
		exit(0);
	}
	else {
		string outpath = plainpath + ".enc.txt";
		writefile(output,temp.size(),outpath);
	}
}
void Decrypt(string& cipherpath, string& keypath, bool pub) {
	/**
	takes a two filepaths one for the file with that ciphertext
	and one with the key.
	Also takes a boolean value denoting if key is a public or private
	The function will then output its result to the same file with the added extention ".dec.txt"
	*/
	unsigned char* key = ReadKeyPem(keypath);
	RSA* rsa = createRSAinstance(key, pub);
	string temp = readfile(cipherpath);
	unsigned char* plain = (unsigned char*)malloc(sizeof(unsigned char*)*temp.size());
	unsigned char* output = (unsigned char*)malloc(sizeof(unsigned char*)*RSA_size(rsa));
	//const char* cp = temp.c_str();
	strncpy((char*)plain, temp.c_str(), temp.size());
	//copy(temp.begin(), temp.end(), plain);
	int err;
	if (pub) {
		err = pub_decrypt(plain, temp.size(), key, output);
	}
	else {
		err = priv_decrypt(plain, temp.size(), key, output);
	}
	if (err == -1) {
		string m = "Encryption failed\nExiting..";
		char* msg = (char*)malloc(sizeof(char)*m.size());
		const char* tmp = m.c_str();
		strncpy(msg, tmp, m.size());
		//copy(m.begin(), m.end(), msg);
		printLastError(msg);
		exit(0);
	}
	else {
		string outpath = cipherpath + ".dec.txt";
		writefile(output, temp.size(), outpath);
	}
}

string readfile(string& path) {

	string input = "";
	ifstream in;
	//string input = "";
	in.open(path, ifstream::binary | ifstream::in);
	if (in.is_open()) {
		char C;
		while (!in.fail()) {
			C = in.get();
			//input += C;
			input.push_back(C);
		}
		//input = input.substr(0,input.size()-1);
		in.close();
		input = input.substr(0,input.size()-1);
	}
	else {
		cout << "cannot open file: " << path << endl;
	}
	return input;
}
void writefile(unsigned char* data,size_t size,string filename) {
	ofstream out;

	out.open(filename, ifstream::out | ifstream::binary);

	size_t i = 0;
	while (i < size) {
		out.put(data[i]);
		i++;
	}
	out.close();
}

unsigned char * ReadKeyPem(string& path) {
	unsigned char* key = (unsigned char*)malloc(500);
	ifstream keyfile;
	keyfile.open(path, ifstream::in | ifstream::binary);
	if (keyfile.is_open()) {
		string in = "";
		char C;
		while (!keyfile.fail()) {
			keyfile.get(C);
			in += (unsigned char)C;
		}
		keyfile.close();
		const char* tmp = in.c_str();
		strncpy((char*)key,tmp,in.size());
		//copy(in.begin(), in.end(),key);
		return key;
	}
	else {
		cout << "cannot open file: " << path << endl;
		cout << "exiting.." << endl;
		exit(1);
	}
	return NULL;
}

///Methods for RSA Encryption and Decryption
///START
RSA * createRSAinstance(unsigned char * key, int pub) {
	RSA *rsa = NULL;
	BIO *keybio;
	keybio = BIO_new_mem_buf(key, -1);
	if (keybio == NULL) {
		cout << "Failed to create KEY" << endl;
		return 0;
	}
	if (pub) {
		rsa = PEM_read_bio_RSA_PUBKEY(keybio, &rsa,NULL,NULL);
	}
	else {
		rsa = PEM_read_bio_RSAPrivateKey(keybio, &rsa, NULL, NULL);
	}
	if (rsa == NULL) {
		cout << "failed to create RSA instance" << endl;
		return 0;
	}
	return rsa;
}

int pub_encrypt(unsigned char * data, int data_len, unsigned char * key, unsigned char *encrypted){
	RSA * rsa = createRSAinstance(key, 1);
	int result = RSA_public_encrypt(data_len, data, encrypted, rsa, padding);
	return result;
}
int priv_decrypt(unsigned char * enc_data, int data_len, unsigned char * key, unsigned char *decrypted){
	RSA * rsa = createRSAinstance(key, 0);
	int  result = RSA_private_decrypt(data_len, enc_data, decrypted, rsa, padding);
	return result;
}
int priv_encrypt(unsigned char * data, int data_len, unsigned char * key, unsigned char *encrypted){
	RSA * rsa = createRSAinstance(key, 0);
	int result = RSA_private_encrypt(data_len, data, encrypted, rsa, padding);
	return result;
}
int pub_decrypt(unsigned char * enc_data, int data_len, unsigned char * key, unsigned char *decrypted){
	RSA * rsa = createRSAinstance(key, 1);
	int  result = RSA_public_decrypt(data_len, enc_data, decrypted, rsa, padding);
	return result;
}
void printLastError(char *msg) {
	char * err = (char*)malloc(130);
	ERR_load_crypto_strings();
	ERR_error_string(ERR_get_error(), err);
	printf("%s ERROR: %s\n", msg, err);
	free(err);
}

///Methods for RSA Encryption and Decryption
///END