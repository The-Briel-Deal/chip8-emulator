CC = gcc
CFLAGS = -Wall -g -lraylib -lpulse-simple -lpulse -pthread -lm

chip8: src/main.c
	$(CC) $(CFLAGS) -o $@ $^
