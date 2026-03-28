#pragma once
#include "rules_and_packets.h"

//CREDIT:: REUSE INPUT READER FROM Hypersplit's original code//
class  InputReader {
public:

	static int dim ;
	static int reps ;

	static std::vector<rule*> ReadFilterFile(const std::string& filename);

	static std::vector<std::vector<unsigned int>> ReadPackets(const std::string& filename);
	static unsigned int inline atoui(const std::string& in);
	static std::vector<std::string> &split(const std::string &s, char delim, std::vector<std::string> &elems);
	static std::vector<std::string> split(const std::string &s, char delim);

//	static void ReadIPRange(vector<unsigned int>& IPrange, const string& token);
	static void  ReadIPRange(rule* current_rule, const std::string& token, int currDim);
	static void ReadPort(rule* current_rule, const std::string& from, const std::string& to, int dim);
	static void ReadProtocol(rule* current_rule, const std::string& last_token, int dim);
	static void ParseRange(std::pair<unsigned int, unsigned int>& range, const std::string& text);
	static int ReadFilter(std::vector<std::string>& tokens, std::vector<rule*>& ruleset, unsigned int cost, int ruleCounter);
	static  void LoadFilters(std::ifstream& fp, std::vector<rule*>& ruleset);
	static std::vector<rule*> ReadFilterFileClassBench(const std::string&  filename);
	static std::vector<rule*> ReadFilterFileMSU(const std::string& filename);

	static const int LOW = 0;
	static const int HIGH = 1;
};
