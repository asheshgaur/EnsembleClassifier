CPP = gcc
CFLGA = -g -Wall -Wsign-compare -Wformat -O2

SRC=pc.c ss.c
OBJ=$(SRC:.c=.o)


%.o: %.c
	${CPP} ${CFLGA} -c $^ -o $@ 

realpc: ${OBJ}
	${CPP} ${CFLGA}  ${OBJ} -lm -o realpc

all: realpc

clean: 
	rm -f *.o
	rm -f realpc
