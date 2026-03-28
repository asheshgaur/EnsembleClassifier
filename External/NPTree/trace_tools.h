#pragma once
#include "rules_and_packets.h"
extern int NUM_PACKETS;
std::vector<Packet> header_gen(int d, std::vector<rule*>& filters, float a, float b, int scale);
void RandomCorner(int RandFilt, std::vector<rule*>& filts, unsigned* new_hdr, int d);
int MyPareto(float a, float b);
std::vector<Packet> GeneratePacketsFromRuleset(std::vector<rule*>& filters);
