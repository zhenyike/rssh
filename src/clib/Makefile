cc = gcc

all: sshpass.o fillfile.o
	ar rcs libsshpass.a sshpass.o
	ar rcs libfillfile.a fillfile.o

sshpass.o: sshpass.c
	cc -I. -g -O2 -MT sshpass.o -MD -MP -MF sshpass.Tpo -c -o sshpass.o sshpass.c -static -fPIC

fillfile.o: fillfile.c
	cc -c -fPIC fillfile.c -o fillfile.o

install:
	cp libsshpass.a /usr/lib64
	cp libfillfile.a /usr/lib64

deinstall:
		rm -f /usr/lib64/libsshpass.a /usr/lib64/libfillfile.a
clean:
	rm -f libsshpass.a libfillfile.a sshpass.Tpo sshpass.o fillfile.o
