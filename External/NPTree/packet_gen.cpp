// File: trace_tools.cc
// David E. Taylor 
// Applied Research Laboratory
// Department of Computer Science and Engineering
// Washington University in Saint Louis
// det3@arl.wustl.edu
//
// Functions for generating synthetic trace of headers
//

#include "trace_tools.h"
#include <cmath>
//#include <iterator>

int NUM_PACKETS = 1000000;//1 million packets
// Generate headers
// a,b in ClassBench are 1 0.1 
// generate at least 'threshold' number of packets
// To ensure the generated dataset is deterministic, call this first!!
void RandomCorner(int RandFilt, std::vector<rule*>& filts, unsigned* new_hdr, int d){
  // Random number
	double p;
	srand(time(NULL));
  for (int i = 0; i < d; i++){
	  p = static_cast <float> (rand()) / static_cast<float> (RAND_MAX);
    // Select random number
    if (p < 0.5){
      // Choose low extreme of field
		new_hdr[i] = filts[RandFilt]->getDimRangeMin(i);
    } else {
      // Choose high extreme of field
		new_hdr[i] = filts[RandFilt]->getDimRangeMax(i);
    }
  }
  return;
}
int MyPareto(float a, float b){
  if (b == 0) return 1;
  double p;
  // Select random number
  p = static_cast <float> (rand()) / static_cast<float> (RAND_MAX);
 
  double x = (double)b / pow((double)(1 - p),(double)(1/(double)a));
  int Num = (int)ceil(x);
  return Num;
}

Packets header_gen(int d, std::vector<rule*>& filters, float a, float b, int threshold){
  int num_headers = 0;
  int fsize = filters.size();
  //int randMax = fsize - 1;
  Packets temp_packets;

  // Allocate temporary header
  unsigned *new_hdr = new unsigned[d];

  // Generate headers
  //srand(time(NULL));
  while(num_headers < threshold){
    // Pick a random filter
	
    //int RandFilt = rand() % (randMax + 0);

	int RandFilt = rand() % fsize;
    // Pick a random corner of the filter for a header
    RandomCorner(RandFilt, filters, new_hdr,d);

    // Select number of copies to add to header list
    // from Pareto distribution
    int Copies = MyPareto(a,b);
    // printf("RandFilt = %d, a = %.4f, b = %.4f, Copies = %d\n",RandFilt,a,b,Copies);

    // Add to header list
	Packet temp;
	for (int i = 0; i < d; i++) temp[i] = (new_hdr[i]);
	for (int i = 0; i < Copies; i++)  {
		temp_packets.push_back(temp);
	}
    // Increment number of headers
    num_headers += Copies;
  }

  delete[] new_hdr;
  return std::vector<Packet>(begin(temp_packets), begin(temp_packets)+threshold);
}

std::vector<Packet> GeneratePacketsFromRuleset(std::vector<rule*>& filters){
	//cout << endl << "Inside GeneratePacketsFromRuleset" << endl;
	if (filters.empty()) printf("warning there is no rule?\n");
	return header_gen(5, filters, 1, 0, NUM_PACKETS);
}
