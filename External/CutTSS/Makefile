CSPATH = CutSplit/
CTPATH = CutTSS/
OVSPATH = OVS/
PSPATH = PartitionSort/
HSPATH = HyperSplit/
VPATH = $(CSPATH) $(CTPATH) $(OVSPATH) $(PSPATH)

CPP=g++
CFLAGS = -g -w -std=c++14 -fpermissive -O3 $(INCLUDE)

# Targets needed to bring the executable up to date

main: main.o CutSplit.o CutTSS.o OVS.o PartitionSort.o HyperSplit.o
	$(CPP) $(CFLAGS) -o main *.o $(LIBS)
# ---------------------------------------------------------------------------------------------------------


# ** CutSplit **
#CutSplit.o: *.cpp
#	$(CPP) $(CFLAGS) -c $(CSPATH)*.cpp
HyperSplit.o: $(wildcard $(HSPATH)*.cpp)
	$(CPP) $(CFLAGS) -c $(HSPATH)*.cpp

CutSplit.o: $(wildcard $(CSPATH)*.cpp)
	$(CPP) $(CFLAGS) -c $(CSPATH)*.cpp

# ** CutTSS **
CutTSS.o: $(wildcard $(CTPATH)*.cpp)
	$(CPP) $(CFLAGS) -c $(CTPATH)*.cpp

# ** TupleSpace **
OVS.o: $(wildcard $(OVSPATH)*.cpp)
	$(CPP) $(CFLAGS) -c $(OVSPATH)*.cpp

# ** PartitionSort **
PartitionSort.o: $(wildcard $(PSPATH)*.cpp)
	$(CPP) $(CFLAGS) -c $(PSPATH)*.cpp

main.o: main.cpp CutTSS.h CutSplit.h TupleSpaceSearch.h ElementaryClasses.h
	$(CPP) $(CFLAGS) -c main.cpp


all:main
clean:
	rm -rf *.o main
