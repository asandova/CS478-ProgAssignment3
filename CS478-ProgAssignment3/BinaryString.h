/*
*	Author: August B. Sandoval
*	File: BinaryString.h
*	Class: CS478
*	Date: 4/13/18
*	Purpose: contains BString class Declarations
*/
#ifndef BINARYSTRING_H
#define BINARYSTRING_H
#include <vector>
#include <string>
#include <iostream>

using namespace std;

///class BString Implemented
class BString {
	public:
		BString();
		BString(string hex);
		//BString(char s);
		//BString(vector<char> s);
		friend ostream& operator<<(ostream& out, const BString& s);
		BString(const BString &s);
		BString(size_t n, char val);
		BString operator^(const BString& value);
		BString operator+(const BString& value);
		BString operator+(const char value);
		BString operator<<(size_t n);
		char& operator[](size_t index);
		const char& operator[](size_t index)const;
		vector<BString> Split(int n)const;
		size_t size()const;
		void pop_front();
		static string BinarytoHex(BString bs);
		static BString HextoBinary(const string& Hex);
		static string TexttoHex(const string& text);
		static string HextoText(const string& Hex);
	private:
		///holds all character values that make up the BString
		vector<char> values;
};

#endif // !BINARYSTRING_H
