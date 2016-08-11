androidimage: androidimage.c Makefile
	$(CC) -O2 -Wall -Werror -o $@ $<  -lcrypto -lssl
