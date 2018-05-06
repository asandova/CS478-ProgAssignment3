/*
*	Author: August B. Sandoval
*	File: main.cpp
*	Class: CS478
*	Date: 4/13/18
*	Purpose: contains the main function
*/

#include <iostream>
#include <fstream>
#include "DES.h"
#include <string>
#include <stdio.h>
#include "BinaryString.h"
#include "EnDecrypt.h"
#include <string.h>
using namespace std;

int main(int argc, char* argv[]) {
	/**
		command line args setup
		partII:
			./a.out
				-II{must be first} 
				-message <messageFilePath>
				-sess <encryptedSessionPath>
				-pub <thirdPartyKeyPath>
				-priv <privatekeyPath>
				-IV <ivpath>
		partIII:
			./a.out 
				-III{must be first}
				-pub <publickeyPath>
				-sess <decryptedSessionPath>
				-des <desCipherPath>
				-sign <signaturePath>
				-IV <ivpath>
	*/
	bool parts = 0;
	string pubPath;
	string privPath;
	string desPath;
	string signPath;
	string sessionPath;
	string messagePath;
	string IVpath;
	if (argc > 0) {
		int i = 1;
		if (strcmp(argv[i],"-II") == 0) {
			parts = false;
			i++;
		}
		else if (strcmp(argv[i], "-III") == 0) {
			parts = true;
			i++;
		}
		else {
			cout << "invalid argument string\nExiting..." << endl;
			exit(1);
		}
		while(i < argc) {
			if (strcmp(argv[i], "-pub") == 0) {
				pubPath = string(argv[i+1]);
				i++;
			}
			else if (strcmp(argv[i], "-sess") == 0) {
				sessionPath = string(argv[i+1]);
				i++;
			}
			else if (strcmp(argv[i], "-message") == 0) {
				messagePath = string(argv[i+1]);
				i++;
			}
			else if (strcmp(argv[i], "-priv") == 0) {
				privPath = string(argv[i+1]);
				i++;
			}
			else if (strcmp(argv[i], "-des") == 0) {
				desPath = string(argv[i+1]);
				i++;
			}
			else if (strcmp(argv[i], "-sign") == 0) {
				signPath = string(argv[i+1]);
				i++;
			}
			else if (strcmp(argv[i], "-IV") == 0) {
				IVpath = string(argv[i + 1]);
				i++;
			}
			else {
				cout << argv[i] << " is not a valid argument\nSkipping..." << endl;

			}
			i++;
		}
	}
	else {
		cout << "no arguments passed.\nExiting..." << endl;
		exit(1);
	}

	if (!parts) {
		//Part II
		if (messagePath == "" || sessionPath == "" || pubPath == "" || privPath == "") {
			cout << "One or all required filepaths was not entered for PART II.\nExiting.." << endl;
			exit(1);
		}else{
			PARTII(pubPath,sessionPath,privPath,messagePath,IVpath);
		}
	}
	else {
		//Part III
		
	}

	return 0;
}
