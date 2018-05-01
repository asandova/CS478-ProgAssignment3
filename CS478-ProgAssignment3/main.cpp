/*
*	Author: August B. Sandoval
*	File: main.cpp
*	Class: CS478
*	Date: 4/13/18
*	Purpose: contains the main function
*/

#include <iostream>
#include <fstream>
#include <stdio.h>
#include "DES.h"
#include <string>
#include <stdio.h>
#include "BinaryString.h"
#include "EnDecrypt.h"
//#include <openssl\des.h>

using namespace std;

int main(int argc, char* argv[]) {
	int i = 1;
	string pub3rdpath = "";
	string pubpath = "";
	string session = "";
	string privpath = "";
	string plain = "";
	string tmp = "";
	string cipher = "";
	string iv;
	string signpath = "";
	bool parts = 0;
	//part II = True, III = false
	while (i < argc) {
		if (strcmp(argv[i], "-plain") == 0) {
			tmp = string(argv[i + 1]);
			plain = tmp;
			parts = true;
			i++;
		}
		if (strcmp(argv[i], "-cipher") == 0) {
			tmp = string(argv[i + 1]);
			cipher = tmp;
			parts = false;
			i++;
		}
		if (strcmp(argv[i], "-pub3rd") == 0) {
			pub3rdpath = string(argv[i+1]);
			i++;
		}
		if (strcmp(argv[i], "-pub") == 0) {
			pubpath = string(argv[i+1]);
			i++;
		}
		if (strcmp(argv[i], "-priv") == 0) {
			privpath = string(argv[i + 1]);
			i++;
		}
		if (strcmp(argv[i], "-session") == 0) {
			tmp = string(argv[i + 1]);
			session = tmp;
			i++;
		}
		if (strcmp(argv[i], "-iv") == 0){
			tmp = string(argv[i + 1]);
			iv = tmp;
			i++;
		}
		if (strcmp(argv[i], "-signature") == 0) {
			tmp = string(argv[i + 1]);
			signpath = tmp;
			i++;
		}
		i++;
	}
	if (session == "") {
		exit(1);
	}
	if (plain == "") {
		exit(1);
	}
	/*
	cout << "Part 1(0) or 2(1)" << endl;
	bool responce;
	cin >> responce;
	*/

	if (!parts) {
		if (pubpath != "") {
			Encrypt(cipher, pubpath, true);
			string s1,s2,temp;
			s1 = readfile(cipher);
			temp = cipher + ".dec.txt";
			s2 = readfile(temp);
			if (s1.compare(s2) != 0) {
				exit(1);
			}
			string key = readfile(session);

			DES des = DES(iv, key.substr(0, 16),true);
			cout << des.Decrypt(s1,false) << endl;
		}
		else {
		
		}
	}
	else {
		if (pub3rdpath != "") {
			//uses decryption with public 3rd party key
			Encrypt(session, pub3rdpath, true);

			//DES with key in session key
			
			session += ".enc.txt";
			string indat = readfile(session);
			string data = BString::TexttoHex(indat);
			string key = data.substr(0, 16);
			//DES des = DES("43533437382d5033",key,true);
			DES des = DES(iv,key,true);
			data = readfile(plain);
			string enc = des.Encrypt(data, false);
			char * fout;
			strncpy(fout, enc.c_str(),enc.size());
			plain += ".enc.txt";
			writefile( (unsigned char*)fout,enc.size(), plain);
			//use decryption with private key to sign
			Decrypt( plain,privpath,false);
			
		}
		else {
			cout << "ERROR: No public 3rd party key file Specified" << endl;
		}
	}

	return 0;
}
