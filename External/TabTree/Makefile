CPP=g++
CFLAGS = -g -w -std=c++11 -fpermissive -O3 $(INCLUDE)

# LIBS = -lghthash
main:main.cpp TabTree.cpp ./OVS/TupleSpaceSearch.cpp ./OVS/cmap.cpp ./OVS/MapExtensions.cpp
	${CPP} ${CFLAGS} -o main main.cpp TabTree.cpp ./OVS/TupleSpaceSearch.cpp ./OVS/cmap.cpp ./OVS/MapExtensions.cpp

all:main
clean:
	rm -f main
