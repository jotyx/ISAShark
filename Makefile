# Makefile for ISAShark
ISA         = isashark
ISA_SOURCES = isashark.cpp

STD		= -std=c++14
CFLAGS	 	= -Wall -Werror -pedantic

CC          	= g++
###########################################

all:		$(ISA)

rebuild:	clean all run

run:
		./$(ISA) example.pcap

$(ISA):
		$(CC) $(STD) $(CFLAGS) -c $(ISA_SOURCES)
		$(CC) $(STD) $(CFLAGS) -lpcap -o $(ISA) isashark.o

###########################################

clean:
	rm $(ISA) *.o