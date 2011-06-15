all: RSA

LDFLAGS=-lgmp -lgmpxx
LDR=g++

RSA: sha1.o

sha1.o: sha1.h

clean:
	rm sha1.o RSA
