all: link

link:   main.o BinaryString.o des_utils.o DES.o
	g++ -std=c++11 main.o BinaryString.o des_utils.o DES.o -o des

main.o: main.cpp
	g++ -std=c++11 -c main.cpp

BinaryString.o: BinaryString.h BinaryString.cpp
	g++ -std=c++11 -c BinaryString.cpp

des_utils.o: des_utils.h des_utils.cpp
	g++ -std=c++11 -c des_utils.cpp

DES.o: DES.h DES.cpp des_utils.h
	g++ -std=c++11 -c DES.cpp
