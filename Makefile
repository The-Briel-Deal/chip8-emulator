CC = gcc
CFLAGS = -Wall -g -lraylib

chip8: src/main.c
	$(CC) $(CFLAGS) -o $@ $^
