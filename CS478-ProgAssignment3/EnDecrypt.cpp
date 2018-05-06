/**
	FILE: EnDecrypt.cpp
	Author: August B. Sandoval

	NOTE:
		I had received help from classmates to get openssl to work
*/

#include <openssl\rsa.h>
#include <openssl\pem.h>
#include <openssl\evp.h>
#include <openssl\sha.h>
#include <openssl\crypto.h>
#include <openssl\engine.h>
#include <openssl\rand.h>
#include <stdlib.h>
#include <fstream>
#include <string>
#include <string.h>
#include <iostream>
#include <stdio.h>
#include "EnDecrypt.h"
#include "DES.h"

using namespace std;

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
void writefile(const char* data,size_t size,string filename) {
	ofstream out;

	out.open(filename, ifstream::out | ifstream::binary);

	size_t i = 0;
	while (i < size) {
		out.put(data[i]);
		i++;
	}
	out.close();
}

void PARTII(string pub3path, string sessionpath, string privkeypath,string plainpath,string IVpath) {
	string sessionplain = "session.txt";
	string cipherOutPath = "message.enc.txt";
	string signout = "signature.txt";
	DecryptPub(sessionpath, pub3path, sessionplain);
	string sess = readfile(sessionplain);
	string plain = readfile(plainpath);
	string IV = readfile(IVpath);
	if (sess == "" || plain == "" || IV == "") {
		cout << "could not open required file(s):" << endl;
		if (sess == "") {
			cout << "File: \"" << sessionpath << "\" could not be opened" << endl;
			exit(1);
		}
		if (plain == "") {
			cout << "File: \"" << plainpath << "\" could not be opened" << endl;
			exit(1);
		}
		if (IV == "") {
			cout << "File: \"" << IVpath << "\" could not be opened" << endl;
			exit(1);
		}
	}

	string key = BString::TexttoHex(sess.substr(0,8));
	DES des = DES::DES(BString::TexttoHex(IV), key,true);
	string desCipher = des.Encrypt(plain,false);
	writefile(desCipher.c_str(),desCipher.size(), cipherOutPath);
	sign(cipherOutPath,privkeypath, signout);
}
void PARTIII(string pubpath,string sessionpath,string cipherpath,string IVpath,string signpath) {

	string sess = readfile(sessionpath);
	string key = BString::TexttoHex(sess.substr(0,8));
	string cipher = readfile(cipherpath);
	string IV = readfile(IVpath);
	string out = "PARTIII_Output.txt";
	DES des = DES::DES(IV,key,true);

	//verify signature
	if (verify_sign(pubpath, cipherpath, signpath) == 1) {
		cout << "Signature passed verification.\nDecryption message" << endl;
		string plain = des.Decrypt(cipher, false);
		writefile(plain.c_str(), plain.size(), out);
		cout << "Decrypted massage was written to file: " << out << endl;
	}
	else {
		cout << "Signature failed verification.\nWill not decrypt massage." << endl;
	}
}
void DecryptPub(string cipherpath, string pubkeypath,string outpath) {
	/**
		Does OpenSSL RSA decryption with EVP Library
	*/
	EVP_PKEY_CTX *ctx;
	EVP_PKEY *key;
	unsigned char *op, *ip;
	size_t opLen, ipLen;

	FILE *CF, *PubF;
	CF = fopen(cipherpath.c_str(), "r");
	PubF = fopen(pubkeypath.c_str(), "r");

	if (CF == NULL || PubF == NULL) {
		cout << "One or both required files could not be opened" << endl;
		cout << "problem File(s):" << endl;
		if (CF == NULL)
			cout << "Cipher File: \"" << cipherpath << "\"" << endl;
		if (PubF == NULL)
			cout << "Public key File: \"" << pubkeypath << "\"" << endl;
		exit(1);
	}

	fseek(CF, 0, SEEK_END);
	ipLen = ftell(CF);
	fseek(CF, 0, SEEK_SET);
	ip = (unsigned char *)malloc(ipLen);
	fread(ip, 1, ipLen, CF);
	fclose(CF);


	key = PEM_read_PUBKEY(PubF, NULL, NULL, NULL);
	fclose(PubF);
	ctx = EVP_PKEY_CTX_new(key, NULL);
	if (!ctx) {
		cout << "Invalid pkey context" << endl;
		exit(1);
	}
	if (EVP_PKEY_encrypt_init(ctx) <= 0) {
		cout << "Encryption failed to initialize" << endl;
		exit(1);
	}
	if (EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_NO_PADDING) <= 0) {
		cout << "Padding failed" << endl;
		exit(1);
	}
	if (EVP_PKEY_encrypt(ctx, NULL, &opLen, ip, ipLen) <= 0) {
		cout << "Buffer size failed to initialize" << endl;
		exit(1);
	}
	op = (unsigned char*)OPENSSL_malloc(opLen);
	if (!op) {
		cout << "Malloc failed" << endl;
		exit(1);
	}
	if (EVP_PKEY_encrypt(ctx, op, &opLen, ip, ipLen) <= 0) {
		cout << "Decryption failed" << endl;
		exit(-1);
	}

	FILE *plainFile = fopen(outpath.c_str() ,"w");
	if (plainFile == NULL) {
		cout << "Failed to open output file" << endl;
		exit(1);
	}
	fwrite(op, 1, 8, plainFile);
	fclose(plainFile);

	EVP_PKEY_CTX_free(ctx);
	EVP_PKEY_free(key);
	free(ip);
	OPENSSL_free(op);
}

void sign(string plainpath,string privpath,string outpath) {
	EVP_PKEY_CTX *ctx;
	EVP_MD_CTX *mdCTX;
	const EVP_MD *mdptr = EVP_sha256();
	if (!mdptr) {
		cout << "Unknown message digest" << endl;
		exit(1);
	}
	unsigned char *md, *sign, *DESCipher;
	size_t mdlen = 23, signlen, DESlen;
	EVP_PKEY *signkey;
	FILE *DESCipF = fopen(plainpath.c_str(), "r");
	FILE *privkeyF = fopen(privpath.c_str(), "r");

	if (DESCipF == NULL || privkeyF == NULL) {
		exit(1);
	}

	fseek(DESCipF, 0, SEEK_END);
	DESlen = ftell(DESCipF);

	md=(unsigned char *)malloc(mdlen);
    if(!mdptr){
		cout<<"Unknown message digest"<<endl;
		exit(-1);
	}
    mdCTX = EVP_MD_CTX_create();
    if(!mdCTX){
		cout<<"Unable to setup new message digest"<<endl;
		exit(-1);
	}
    if(EVP_DigestInit_ex(mdCTX, mdptr, NULL)==0){
		cout<<"Failed initialize digest"<<endl;
		exit(-1);
	}
    if(EVP_DigestUpdate(mdCTX, DESCipher, DESlen)==0){
		cout<<"Failed to update digest"<<endl;
		exit(-1);}
    if(EVP_DigestFinal_ex(mdCTX, md, NULL)==0){
		cout<<"Failed to finalize hash"<<endl;
		exit(-1);
	}
    EVP_MD_CTX_destroy(mdCTX);
    
    //setup signature
    signkey = PEM_read_PrivateKey(privkeyF, NULL, NULL, NULL);
    ctx = EVP_PKEY_CTX_new(signkey, NULL);
    if(!ctx){
		cout<<"Invalid context"<<endl;
		exit(1);
	}
    if(EVP_PKEY_sign_init(ctx)<=0){
		cout << "Failed to initialize signature" << endl;
		exit(1);
	}
    if(EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_PADDING)<= 0){
		cout<< "Failed to pad" <<endl;
		exit(1);
	}
    if(EVP_PKEY_CTX_set_signature_md(ctx, EVP_sha256())<=0){
		cout << "Failed to hash signature" << endl;
		exit(1);
	}
    if(EVP_PKEY_sign(ctx, NULL, &signlen, md, mdlen)<=0){
		cout << "Buffered failed to initialize" << endl;
		exit(1);
	}
    sign = (unsigned char *)OPENSSL_malloc(signlen);
    if(!sign){
		cout<<"Malloc failed"<<endl;
		exit(1);
	}
    if(EVP_PKEY_sign(ctx, sign, &signlen, md, mdlen)<=0){
		cout<<"Failed to sign"<<endl;
		exit(1);
	}
    
    //output signature to sign.txt
    FILE *sign_out = fopen(outpath.c_str(), "w");
    if(sign_out == NULL){
		cout<< "Unable write signature to \""<< outpath << "\"" << endl;
		exit(1);
	}
    fwrite(sign, 1, signlen, sign_out);
    fclose(sign_out);
    fclose(privkeyF);
    
    //free memory
    EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_free(signkey);
    free(md);
    free(DESCipher);
    OPENSSL_free(sign);
}

int verify_sign(string pubkeyPath, string cipherPath, string sign) {
	EVP_PKEY_CTX *ctx;
	EVP_MD_CTX *mdCTX;
	const EVP_MD *mdptr = EVP_sha256();
	if (!mdptr) {
		cout << "Unknown message digest" << endl;
		exit(-1);
	}
	unsigned char *md, *sig, *DESCipher;
	size_t mdlen = 32, signLen, DESCipherLen;
	EVP_PKEY *verkey;
	FILE *pub_key = fopen(pubkeyPath.c_str(), "r");
	FILE *cipherF = fopen(cipherPath.c_str(), "r");
	FILE *signF = fopen(sign.c_str(), "r");
	if (pub_key == NULL || cipherF == NULL || signF == NULL) {
		cout << "One or more required could not be open:" << endl;
		if (pub_key == NULL) { 
			cout << "\tUnable to open public key" << endl; 
			exit(1);
		}
		if (cipherF == NULL) { 
			cout << "\tUnable to open ciphertext" << endl;
			exit(1);
		}
		if (signF == NULL) { 
			cout << "\tUnable to open signature" << endl;
			exit(1);
		}
	}

	//read contents from ciphertext into dis_cip
	fseek(cipherF, 0, SEEK_END);
	DESCipherLen = ftell(cipherF);
	fseek(cipherF, 0, SEEK_SET);
	DESCipher = (unsigned char *)malloc(DESCipherLen);
	fread(DESCipher, 1, DESCipherLen, cipherF);
	fclose(cipherF);

	//setup sha256 message digest of des_cip
	md = (unsigned char *)malloc(mdlen);
	if (!mdptr) {
		cout << "Unknown message digest" << endl;
		exit(1);
	}
	mdCTX = EVP_MD_CTX_create();
	if (!mdCTX) { 
		cout << "Invalid MD context" << endl;
		exit(1);
	}
	if (EVP_DigestInit_ex(mdCTX, mdptr, NULL) == 0) {
		cout << "Failed to initialize digest" << endl;
		exit(-1);
	}
	if (EVP_DigestUpdate(mdCTX, DESCipher, DESCipherLen) == 0) {
		cout << "Failed to update digest" << endl;
		exit(-1);
	}
	if (EVP_DigestFinal_ex(mdCTX, md, NULL) == 0) {
		cout << "Failed to finalize hash" << endl;
		exit(-1);
	}
	EVP_MD_CTX_destroy(mdCTX);

	//read signature file and verify
	fseek(signF, 0, SEEK_END);
	signLen = ftell(signF);
	fseek(signF, 0, SEEK_SET);
	sig = (unsigned char *)malloc(signLen);
	fread(sig, 1, signLen, signF);
	fclose(signF);

	//verify signature
	verkey = PEM_read_PUBKEY(pub_key, NULL, NULL, NULL);
	ctx = EVP_PKEY_CTX_new(verkey, NULL);
	if (!ctx) {
		cout << "Invalid context" << endl;
		exit(1);
		}
	if (EVP_PKEY_verify_init(ctx) <= 0) {
		cout << "Verify failed to initialize" << endl;
		exit(1);
	}
	if (EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_PADDING) <= 0) {
		cout << "Padding failed" << endl;
		exit(1);
	}
	if (EVP_PKEY_CTX_set_signature_md(ctx, EVP_sha256()) <= 0) {
		cout << "Signature not set" << endl;
		exit(1);
	}
	int vercode = EVP_PKEY_verify(ctx, sig, signLen, md, mdlen);

	//free memory
	EVP_PKEY_CTX_free(ctx);
	EVP_PKEY_free(verkey);
	free(md);
	free(sig);
	free(DESCipher);

	return vercode;
}
