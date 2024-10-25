CC = gcc
ARGS = -Wall -O0 -g -I .

all: listener talker

listener:
	$(CC) $(ARGS) -o listener listener.c

talker:
	$(CC) $(ARGS) -o talker talker.c

clean:
	rm -f *.o listener talker *~
