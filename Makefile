# makefile for hw1.cpp
all: hw1.cpp
	g++ hw1.cpp -o main -lpcap
clean: 
	rm -f main