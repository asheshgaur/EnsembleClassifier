# Makefile

# Compiler to use
CXX = g++

# Compiler flags
CXXFLAGS = -Wall -std=c++11 -O3

all: main

main.o: main.cpp rules_and_packets.h
	$(CXX) $(CXXFLAGS) -c main.cpp
	
classbench_reader.o: classbench_reader.cpp classbench_reader.h rules_and_packets.h
	$(CXX) $(CXXFLAGS) -c classbench_reader.cpp

packet_gen.o: packet_gen.cpp trace_tools.h rules_and_packets.h
	$(CXX) $(CXXFLAGS) -c packet_gen.cpp

main: classbench_reader.o packet_gen.o main.o
	$(CXX) $(CXXFLAGS) -o main *.o

clean:
	rm -f *.o main