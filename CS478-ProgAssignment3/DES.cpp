/*
*	Author: August B. Sandoval
*	File: DES.cpp
*	Class: CS478
*	Date: 4/13/18
*	Purpose: Contains DES Class definitions
*/
#include <vector>
#include <cstdlib>
#include <fstream>
#include "DES.h"
#include "des_utils.h"
#include <string>

using namespace std;

//Public
DES::DES() {
	//default constructor
	subkeys = vector<BString>();
	setKey(GenRandomKey());
	setIV(string(16,'0'));
	CBC = false;
}
DES::DES(const string& Key, bool cbc) {
	/*
	*	overloaded constructor
	*	takes in a Hex string for Key
	*	and a boolean value for CBC mode
	*/
	subkeys = vector<BString>();
	setKey(Key);
	setIV("0000000000000000");
	CBC = cbc;
}
DES::DES(const string& IV, const string& KEY, bool cbc) {
	/*
	* overloaded constuctor
	* takes in a HEX string for IV amd KEY
	* and a boolean value for CBC mode
	*/
	subkeys = vector<BString>();
	setIV(IV);
	setKey(KEY);
	CBC = cbc;
}
void DES::setKey(string KHex) {
	/**
	*	Sets the given string of Hexadecimal characters and
	*	converts it to a binary string and sets that binary string as
	*	the current key
	**/
	if (!Check(KHex)) {
		cout << KHex << " is a Invalid Key" << endl;
		exit(1);
	}
	KEY = BString::HextoBinary(KHex);
	GenSubKeys();
}
void DES::setCBC(bool cbc) {
	CBC = cbc;
}
string DES::GenRandomKey() {
	/**
	*	Generates a random string with only 16 Hexadecimal character.
	**/
	string K = "";
	for (size_t i = 0; i < 16; i++) {
		size_t r = rand() % 16;
		if (r < 10) {
			K += r + '0';
		}
		else {
			K += (r-10) + 'A';
		}
	}
	return K;
}
string DES::Encrypt(const string& P,bool ishex) {
	/**
	*	Encrypts plaintext P with current KEY and IV
	**/
	string cipher="";
	BString PBinary;
	if (ishex) {
		PBinary = BString::HextoBinary(P);
	}
	else {
		string PHex = BString::TexttoHex(P);
		PBinary = BString::HextoBinary(PHex);
	}
	size_t missing = PBinary.size() % 64;
	if (missing != 0) {
		PBinary = PBinary + BString(64 - missing, '0' );
	}
	//Seperates the plaintest into blocks
	vector<BString>Blocks = PBinary.Split(PBinary.size() / 64);

	//CBC part of DES. Chaining each each block to its previous
	for (size_t i = 0; i < Blocks.size(); i++) {
		//performing the encoding prossess on the current block
		if (CBC) {
			if (i == 0) {
				Blocks[i] = Blocks[i] ^ IV;
			}
			else {
				Blocks[i] = Blocks[i] ^ Blocks[i - 1];
			}
			Blocks[i] = encode(Blocks[i]);

		} else{
			Blocks[i] = encode(Blocks[i]);
		}
	}
	//converting block to string representation
	vector<BString>::const_iterator itr;
	for (itr = Blocks.begin(); itr != Blocks.end(); ++itr) {
		cipher += BString::BinarytoHex(*itr);
	}
	if (!ishex) {
		cipher = BString::HextoText(cipher);
		return cipher;
	}
	return cipher;
}
string DES::Decrypt(const string& C,bool isHex) {
	/**
	*	Decrypts cipher text C with current KEY and IV
	**/
	BString CBinary;
	if (isHex) {
		CBinary = BString::HextoBinary(C);
	}
	else {
		string CHex = BString::TexttoHex(C);
		CBinary = BString::HextoBinary(CHex);
	}
	//cout << CBinary.size() << endl;
	if (CBinary.size() % 64 != 0) {
		//int missing = CBinary.size() % 64;
		//CBinary = CBinary + BString::BString(64-missing, '0');
		
		cout << "ERROR: Given Cipher Text Binary string does not have a length that is a multiple of 64" << endl;
		cout << "Cannont perform Decryption" << endl;
		cout << "Exiting program..." << endl;
		exit(1);
	}
	//spliting the cipher text into 64bit long blocks
	vector<BString>Blocks = CBinary.Split(CBinary.size() / 64);
	vector<BString>PBlocks = Blocks;
	//CBC part of DES. Chaining each each block to its previous
	for (size_t i = 0; i < Blocks.size(); i++) {
		//performing the decoding prossess on the current block
		if (CBC) {
			//if CBC is true chain the blocks
			PBlocks[i] = decode(Blocks[i]);
			if (i == 0) {
				PBlocks[i] = PBlocks[i] ^ IV;
			}
			else {
				PBlocks[i] = PBlocks[i] ^ Blocks[i - 1];
			}
		}
		else {
			//if CBC is false don't chain the blocks
			PBlocks[i] = decode(Blocks[i]);
		}
	}
	//converting block to string representation
	string plain = "";
	vector<BString>::const_iterator itr;
	for (itr = PBlocks.begin(); itr != PBlocks.end(); ++itr) {
		plain += BString::BinarytoHex(*itr);
	}
	//returning the plain text in Hexadecimal
	if (!isHex) {
		return BString::HextoText(plain);
	}
	return plain;
}
void DES::setIV(string iv) { 
	/*
		Sets the IV value after checking if correct
	*/
	if (!Check(iv)) {
		cout << iv << " is not a valid Initalization Vector" << endl;
		exit(1);
	}
	IV = BString::HextoBinary(iv);
}
string DES::getIV()const {
	/**
	*	returns current Initiazation Value in Hexadecimal
	**/
	return BString::BinarytoHex(IV);
}
string DES::getKEY()const {
	/**
	*	returns current Key in Hexadecimal
	**/
	return BString::BinarytoHex(KEY);
}
//Private
void DES::GenSubKeys() {
	/**
	*	Generates all DES Sub Keys
	**/
	BString K56 = PCPermutate(KEY, PC1, 0);
	vector<BString> S = K56.Split(2);
	vector<BString> CDkey = vector<BString>();
	CDkey.push_back(S[0]);
	CDkey.push_back(S[1]);
	for (size_t i = 1; i <= 16; i++) {
		if (i <= 2 || i == 9 || i == 16) {
			S[0] = S[0] << 1;
			S[1] = S[1] << 1;
		}
		else {
			S[0] = S[0] << 2;
			S[1] = S[1] << 2;
		}
		CDkey.push_back(S[0]);
		CDkey.push_back(S[1]);
	}
	for (size_t i = 2; i < CDkey.size()-1; i+=2) {
		BString CD = CDkey[i] + CDkey[i + 1];
		BString temp = PCPermutate(CD, PC2, 1);
		subkeys.push_back(temp);
	}
}

BString DES::IFPermutate(BString& bs, char* table) {
	/**
	*	Performes DES Permutation with table for either
	*	Intial permutation table or Final permutation table
	**/
	BString r = BString( 64,'0' );
	for (size_t i = 0; i < 64; i++) {
		size_t p = table[i];
		r[i] = bs[p-1];
	}
	return r;
}
BString DES::PPermuate(BString& bs) {
	/*
		Does DES permutation on BS according to table P
	*/
	BString r = BString(32, '0');
	for (size_t i = 0; i < 32; i++) {
		size_t p = P[i];
		r[i] = bs[p-1];
	}
	return r;
}
BString DES::PCPermutate(BString& bs, int* table, int num) {
	/**
	*	Does DES Permutation on a BinaryString with either PC-1 or PC-2 tables 
	**/
	size_t n;
	if (num == 0) {
		n = 56;
	}
	else {
		n = 48;
	}
	BString r = BString(n, '0');
	for (size_t i = 0; i < n; i++) {
		size_t p = table[i];
		r[i] = bs[p-1];
	}
	return r;
}
BString DES::Expand(BString& bs) {
	/*
		Expands a 32 bit binarystring to 48bits
	*/
	BString Ebs = BString(48, '0');
	for (size_t i = 0; i < 48; i++) {
		size_t p = E[i];
		Ebs[i] = bs[p-1];
	}
	return Ebs;
}
BString DES::Sbox(BString& bs, int n) {
	/**
	*	Performes a single DES Sbox calculation with SBox table n
	**/
	size_t col=0, row=0;
	//calculating row value
	row = bs[0] - '0';
	row = row << 1;
	row += bs[5] - '0';
	//calculating column value
	col = 0;
	for (size_t i = 1; i < 5; i++) {
		col += bs[i] - '0';
		if(i < 4)
			col = col << 1;
	}
	//getting value from SBox_n
	size_t index = (row * 16) + col;
	size_t number = SBOXMAP[n][index];
	BString result = BString(4,'0');
	//converting to value to binarystring
	for (int i = 3; i >= 0; i--) {
		result[i] = (number % 2) + '0';
		number /= 2;
	}
	return result;
}
BString DES::Sboxes(BString& RB ){
	/**
	*	Performes all SBox calculations on RB
	**/
	vector<BString> sections = RB.Split(8);
	//creating place for Sbox results
	BString Result = BString();
	//Sboxes
	for (size_t i = 0; i < 8; i++) {
		sections[i] = Sbox(sections[i],i);//B_i = S_i(B_i)
		Result = Result + sections[i];//Result = Result + B_i
	}
	return Result;
}
BString DES::encode(BString b) {
	//Inital Permutation
	b = IFPermutate(b, IP);
	vector<BString> LR = b.Split(2);
	vector<BString>::const_iterator itr;
	for (itr = subkeys.begin(); itr != subkeys.end(); ++itr) {
	//for (size_t i = 0; i < 16; i++) {
		LR = DESRound(LR[0], LR[1], *itr);
	}
	//Final Permutation
	BString temp = LR[1] + LR[0];
	return IFPermutate( temp,FP);
}
//vector<BString> DES::DESRound(BString L, BString R, size_t key) {
vector<BString> DES::DESRound(BString& L, BString& R, BString key) {
	/**
		Performes one round of DES on L,R with subkey_key
		key is an index in subkeys
	*/
	//creating a value to hold result
	vector<BString> Result = vector<BString>(2,BString());
	//swaping L and R
	Result[0] = R;
	R = L ^ f(R, key);
	//R = L ^ f(R,subkeys[key]);
	Result[1] = R;

	return Result;
}
BString DES::decode(BString b) {
	//Initial Permuation on b
	b = IFPermutate(b, IP);
	//spliting b in two
	vector<BString> LR = b.Split(2);
	//DES rounds
	vector<BString>::const_reverse_iterator itr;
	for (itr = subkeys.rbegin(); itr != subkeys.rend(); ++itr) {
	//for (int i = 15; i > 0; i--) {
		LR = DESRound(LR[0], LR[1], *itr);
	}
	//Final Permutations
	BString temp = LR[1] + LR[0];
	return IFPermutate(temp, FP);
}
///Static methods
BString DES::f(BString& R, BString& k) {
	//explanding 32 bit to 48bits via expland table
	R = Expand(R);
	//XORing E(R) with k
	BString r = R ^ k;
	//spliting r in to 8 sections
	vector<BString> sections = r.Split(8);
	//storing sbox results
	//cout << r << endl;
 	BString Result = Sboxes(r);
	//cout << Result << endl;
	//Permutation Result with table P
	Result = PPermuate(Result);
	return Result;
}

bool DES::Check(string k) {
	/*
		Checks if the entered string is valid for DES KEY or IV
	*/
	if (k.size() == 16) {
		for (string::const_iterator itr = k.begin();
			itr != k.end(); ++itr) {
			//if any character in Hexstring is not a Hex character
			//returns false
			if (!((*itr >= '0' && *itr <= '9')	||
				  (*itr >= 'A' && *itr <= 'F')	||
				  (*itr >= 'a' && *itr <= 'f'))){
				return false;
			}
		}
		return true;
	}
	return false;
}