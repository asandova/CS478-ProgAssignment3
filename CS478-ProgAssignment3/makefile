all: Assign3

Assign3: main.o des_utils.o DES.o EnDecrypt.o BinaryString.o
	g++ -std=c++11 main.o DES.o EnDecrypt.o des_utils.o BinaryString.o -o Prog3 -lcrypto

main.o: main.cpp EnDecrypt.h
	g++ -c main.cpp

EnDecrypt.o: EnDecrypt.cpp EnDecrypt.h BinaryString.h DES.h
	g++ -std=c++11 -c EnDecrypt.cpp -lcrypto

BinaryString.o: BinaryString.h BinaryString.cpp
	g++ -std=c++11 -c BinaryString.cpp

des_utils.o: des_utils.h des_utils.cpp
	g++ -std=c++11 -c des_utils.cpp

DES.o: DES.h DES.cpp des_utils.h
	g++ -std=c++11 -c DES.cpp

clean:
	rm -rf *.o *.enc.txt signature.txt
