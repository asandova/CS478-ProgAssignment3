/*
*	Author: August B. Sandoval
*	File: DES.h
*	Class: CS478
*	Date: 4/13/18
*	Purpose: Contains class DES declarations
*/
#ifndef DES_H
#define DES_H

#include <vector>
#include <string>
#include <fstream>
#include "BinaryString.h"

using namespace std;

class DES {
public:
	///implemented
	DES();
	DES(const string& Key, bool CBC);
	///implemented
	DES(const string& IV, const string& KEY, bool CBC);
	void setKey(string KHex);
	///implemented
	static string GenRandomKey();

	string Encrypt(const string& P,bool ishex);

	string Decrypt(const string& C,bool ishex);
	///implemented
	void setCBC(bool cbc);
	///implemented
	void setIV(string iv);
	///implemented
	string getIV()const;
	///implemented
	string getKEY()const;
	///implemented
	static bool Check(string k);
private:
	BString IV;
	BString KEY;//64bits
	vector<BString> subkeys;
	bool CBC;
	bool debug;
	///implemented
	void GenSubKeys();
	BString encode(BString b);
	//vector<BString> DESRound(BString L, BString R, size_t Key);
	BString decode(BString b);
	static vector<BString> DESRound(BString& L, BString& R, BString Key);
	///implemented
	static BString IFPermutate(BString& bs, char* table);
	///implemented
	static BString PPermuate(BString& bs);
	///implemented
	static BString PCPermutate(BString& bs, int* table,int num);
	///implemented
	static BString Expand(BString& bs);
	///implemented
	static BString Sbox(BString& bs,int n);
	///implemented
	static BString Sboxes(BString& RB);
	///implemented
	static BString f(BString& R, BString& k);
};
#endif // !DES_H
