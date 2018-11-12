all: pal tescik custom_pam
pal: pal.cpp
	g++ pal.cpp -o pal -lpam -lpam_misc
tescik: tescik.c
	gcc -o tescik tescik.c -lpam -lpam_misc
custom_pam: custom_pam.c
	gcc -std=c11 -c custom_pam.c
	gcc custom_pam.o -shared -o pam_custom.so
	sudo mv pam_custom.so /lib/i386-linux-gnu/security/
