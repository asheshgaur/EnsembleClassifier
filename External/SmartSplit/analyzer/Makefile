CPP = g++
CFLGA = -lm -g -Wall -Wsign-compare -Wformat -std=c++11

SRC=hypc.cc sp_tree.cc rtrie.cc
OBJ=$(SRC:.cc=.o)


%.o: %.cc
	${CPP} ${CFLGA} -c $^ -o $@ 

sp: ${OBJ}
	${CPP} ${CFLGA} ${OBJ} -o sp  

all: sp 

clean: 
	rm -f *.o
	rm -f sp
