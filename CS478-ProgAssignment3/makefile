all: Assign3

Assign3: main.cpp openssl DES
	g++ -std=c++11 main.cpp -o Prog3 -lcrypto

openssl: EnDecrypt.cpp EnDecrypt.h
	g++ -std=c++11 -c EnDecrypt.cpp

DES: Binarystring.o des_utils.o DES.o

BinaryString.o: BinaryString.h BinaryString.cpp
	g++ -std=c++11 -c BinaryString.cpp

des_utils.o: des_utils.h des_utils.cpp
	g++ -std=c++11 -c des_utils.cpp

DES.o: DES.h DES.cpp des_utils.h
	g++ -std=c++11 -c DES.cpp