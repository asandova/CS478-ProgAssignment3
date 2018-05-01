/*
*	Author: August B. Sandoval
*	File: BinaryString.cpp
*	Class: CS478
*	Date: 4/13/18
*	Purpose: Contains BString Class definitions
*/

#include <vector>
#include <iostream>
#include <cctype>
#include "BinaryString.h"

using namespace std;

BString::BString() {
	values = vector<char>();
}

BString::BString(string hex) {
	values = HextoBinary(hex).values;
}
BString::BString(const BString& s) {
	values = s.values;
}
BString::BString(size_t n, char val) {
	values = vector<char>(n, val);
}
BString BString::operator^(const BString& val) {
	BString r = BString();
	if (values.size() == val.size()) {
		for (size_t i = 0; i < values.size(); i++) {
			size_t c1 = values[i] - '0', c2 = val[i] - '0';
			if (c1 ^ c2) {
				//r.push_back('1');
				r = r + '1';
			}
			else {
				//r.push_back('0');
				r = r + '0';
			}
		}
	}
	return r;
}
BString BString::operator+(const BString& val) {
	BString r = BString(*this);
	for (size_t i = 0; i < val.size(); i++) {
		r.values.push_back(val[i]);
	}
	return r;
}
BString BString::operator+(const char val) {
	BString r = BString(*this);
	r.values.push_back(val);
	return r;
}
BString BString::operator<<(size_t n) {
	BString r = BString(*this);
	for (size_t i = 0; i < n; i++) {
		char temp = r.values[0];
		r.values.erase(r.values.begin());
		r.values.push_back(temp);
	}
	return r;
}
char& BString::operator[](size_t index) {
	return values[index];
}
const char& BString::operator[](size_t index)const {
	return values[index];
}
vector<BString> BString::Split(int n)const {
	vector<BString> s = vector<BString>();
	BString temp = BString();
	size_t splval = values.size() / n;
	for (size_t i = 0; i < values.size(); i++) {
		temp = temp + values[i];
		if ((i % splval == splval-1 && i != 0) ) {
			s.push_back(temp);
			temp = BString();
		}	
	}
	return s;
}
size_t BString::size()const {
	return values.size();
}
void BString::pop_front() {
	values.erase(values.begin());
}
string BString::BinarytoHex(BString bs) {
	BString temp = BString(bs);
	if (temp.size() % 4 != 0) {
		BString pad = BString(4 - (temp.size() % 4 ) ,'0');
		temp = pad + temp;
	}
	string HexChar = "";
	vector<size_t>HexVal = vector<size_t>();
	for (size_t i = 0; i < temp.size()-3; i+=4) {
		size_t val = 0;
		for (size_t j = i; j < i + 4; j++) {
			val += temp[j] - '0';
			if(j != i+3)
				val = val << 1;
		}
		HexVal.push_back(val);
	}
	vector<size_t>::const_iterator itr;
	for (itr = HexVal.begin(); itr != HexVal.end(); ++itr) {
		switch (*itr)
		{
			case 0:
				HexChar += '0';
				break;
			case 1:
				HexChar += '1';
				break;
			case 2:
				HexChar += '2';
				break;
			case 3:
				HexChar += '3';
				break;
			case 4:
				HexChar += '4';
				break;
			case 5:
				HexChar += '5';
				break;
			case 6:
				HexChar += '6';
				break;
			case 7:
				HexChar += '7';
				break;
			case 8:
				HexChar += '8';
				break;
			case 9:
				HexChar += '9';
				break;
			case 10:
				HexChar += 'A';
				break;
			case 11:
				HexChar += 'B';
				break;
			case 12:
				HexChar += 'C';
				break;
			case 13:
				HexChar += 'D';
				break;
			case 14:
				HexChar += 'E';
				break;
			case 15:
				HexChar += "F";
				break;
			default:
				cout <<  *itr << ": is not a valid Hex value" << endl;
				break;
		}
	}
	return HexChar;
}
BString BString::HextoBinary(const string& Hex) {

	BString bs = BString(Hex.size()*4,'0');
	for (size_t i = 0; i < Hex.size(); i++) {
		size_t j = i * 4;
		char temp = Hex[i];
		if (temp >= 'a' && temp <= 'z') {
			temp = toupper(temp);
		}
		switch (temp)
		{
		case '0':
			bs[j] = '0';
			bs[j + 1] = '0';
			bs[j + 2] = '0';
			bs[j + 3] = '0';
			break;
		case '1':
			bs[j] = '0';
			bs[j + 1] = '0';
			bs[j + 2] = '0';
			bs[j + 3] = '1';
			break;
		case '2':
			bs[j] = '0';
			bs[j + 1] = '0';
			bs[j + 2] = '1';
			bs[j + 3] = '0';
			break;
		case '3':
			bs[j] = '0';
			bs[j + 1] = '0';
			bs[j + 2] = '1';
			bs[j + 3] = '1';
			break;
		case '4':
			bs[j] = '0';
			bs[j + 1] = '1';
			bs[j + 2] = '0';
			bs[j + 3] = '0';
			break;
		case '5':
			bs[j] = '0';
			bs[j + 1] = '1';
			bs[j + 2] = '0';
			bs[j + 3] = '1';
			break;
		case '6':
			bs[j] = '0';
			bs[j + 1] = '1';
			bs[j + 2] = '1';
			bs[j + 3] = '0';
			break;
		case '7':
			bs[j] = '0';
			bs[j + 1] = '1';
			bs[j + 2] = '1';
			bs[j + 3] = '1';
			break;
		case '8':
			bs[j] = '1';
			bs[j + 1] = '0';
			bs[j + 2] = '0';
			bs[j + 3] = '0';
			break;
		case '9':
			bs[j] = '1';
			bs[j + 1] = '0';
			bs[j + 2] = '0';
			bs[j + 3] = '1';
			break;
		case 'A':
			bs[j] = '1';
			bs[j + 1] = '0';
			bs[j + 2] = '1';
			bs[j + 3] = '0';
			break;

		case 'B':
			bs[j] = '1';
			bs[j + 1] = '0';
			bs[j + 2] = '1';
			bs[j + 3] = '1';
			break;
		case 'C':
			bs[j] = '1';
			bs[j + 1] = '1';
			bs[j + 2] = '0';
			bs[j + 3] = '0';
			break;
		case 'D':
			bs[j] = '1';
			bs[j + 1] = '1';
			bs[j + 2] = '0';
			bs[j + 3] = '1';
			break;
		case 'E':
			bs[j] = '1';
			bs[j + 1] = '1';
			bs[j + 2] = '1';
			bs[j + 3] = '0';
			break;
		case 'F':
			bs[j] = '1';
			bs[j + 1] = '1';
			bs[j + 2] = '1';
			bs[j + 3] = '1';
			break;
		default:
			cout << Hex[i] << " is not a Hex value\nSkipping..." << endl;
			break;
		}
	}
	return bs;
}
string BString::TexttoHex(const string& text) {
	string Hex = "";

	for (size_t i = 0; i < text.size(); i++) {
		size_t HV[2];
		unsigned char HChar = text[i];
		/*if (text[i] < 0) {
			HChar =(text[i] * -1);
		}
		else {
			HChar = text[i];
		}*/
		HV[0] = (HChar) % 16;
		HV[1] = (HChar /16) % 16;
		if (HV[1] < 10) {
			Hex = Hex + (char)(HV[1] + '0');
		}
		else {
			HV[1] -= 10;
			Hex = Hex + (char)(HV[1] + 'A');
		}
		if (HV[0] < 10) {
			Hex = Hex + (char)(HV[0] + '0');
		}
		else {
			HV[0] -= 10;
			Hex = Hex + (char)(HV[0] + 'A');
		}
	}
	return Hex;
}
string BString::HextoText(const string& Hex) {
	string text = "";
	for (size_t i = 0; i < Hex.size() - 1; i += 2) {
		size_t val = 0;
		size_t t = 0;
		char L = Hex[i], R = Hex[i+1];
		if (L>= '0' && L <= '9') {
			t = (L - '0') * 16;
			val = t;
		}
		else {
			t = ( (L - 'A') + 10) * 16;
			val = t;
		}
		if (R >= '0' && R <= '9') {
			t = (R - '0');
			val += t;
		}
		else {
			t = (R - 'A') + 10;
			val += t;
		}

		text = text + (char)val;
	}
	return text;
}
ostream& operator<<(ostream& out, const BString& s) {
	vector<char>::const_iterator itr;
	size_t i = 1;
	for (itr = s.values.begin(); itr != s.values.end(); ++itr, i++) {
		out << *itr;
		if (i % 8 == 0)
			out << " ";
	}
	return out;
}