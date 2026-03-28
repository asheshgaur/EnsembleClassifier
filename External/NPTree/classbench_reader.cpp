#include <vector>
#include <iostream>
#include <vector>
#include <algorithm>
#include <set>
#include <string>
#include <fstream>
#include <sstream>
#include <iterator>
#include <functional>
#include "classbench_reader.h"
#include "rules_and_packets.h"
#include <regex>

using namespace std;

int InputReader::dim = 5;
int InputReader::reps = 1;


unsigned int inline InputReader::atoui(const string& in) {
	std::istringstream reader(in);
	unsigned int val;
	reader >> val;
	return val;
}


std::vector<std::string>& InputReader::split(const std::string &s, char delim, std::vector<std::string> &elems) {
	std::stringstream ss(s);
	std::string item;
	while (std::getline(ss, item, delim)) {
		elems.push_back(item);
	}
	return elems;
}

std::vector<std::string> InputReader::split(const std::string &s, char delim) {
	std::vector<std::string> elems;
	split(s, delim, elems);
	return elems;
}

void InputReader::ReadIPRange(rule* current_rule, const string& token, int currDim)
{
	vector<string> split_slash = split(token, '/');
	vector<string> split_ip = split(split_slash[0], '.');
	/*asindmemacces IPv4 prefixes*/
	/*temporary variables to store IP range */
	unsigned int mask;
	int masklit1;
	unsigned int masklit2, masklit3;
	unsigned int ptrange[4];
	for (int i = 0; i < 4; i++)
		ptrange[i] = atoui(split_ip[i]);
	mask = atoui(split_slash[1]);
	
	current_rule->setPrefixLength(currDim, mask);

	mask = 32 - mask;
	masklit1 = mask / 8;
	masklit2 = mask % 8;

	/*count the start IP */
	for (int i = 3; i>3 - masklit1; i--)
		ptrange[i] = 0;
	if (masklit2 != 0){
		masklit3 = 1;
		masklit3 <<= masklit2;
		masklit3 -= 1;
		masklit3 = ~masklit3;
		ptrange[3 - masklit1] &= masklit3;
	}
	/*store start IP */
	unsigned int IP_start = current_rule->getDimRangeMin(currDim);
	IP_start = ptrange[0];
	IP_start <<= 8;
	IP_start += ptrange[1];
	IP_start <<= 8;
	IP_start += ptrange[2];
	IP_start <<= 8;
	IP_start += ptrange[3];
	
	current_rule->setDimRangeMin(currDim, IP_start);
	//key += std::bitset<32>(IPrange[0] >> prefix_length).to_string().substr(32 - prefix_length);
	/*count the end IP*/
	for (int i = 3; i>3 - masklit1; i--)
		ptrange[i] = 255;
	if (masklit2 != 0){
		masklit3 = 1;
		masklit3 <<= masklit2;
		masklit3 -= 1;
		ptrange[3 - masklit1] |= masklit3;
	}
	/*store end IP*/
	unsigned int IP_end = current_rule->getDimRangeMax(currDim);
	IP_end = ptrange[0];
	IP_end <<= 8;
	IP_end += ptrange[1];
	IP_end <<= 8;
	IP_end += ptrange[2];
	IP_end <<= 8;
	IP_end += ptrange[3];

	current_rule->setDimRangeMax(currDim, IP_end);
}

void InputReader::ReadPort(rule* current_rule, const string& from, const string& to, int dim)
{
	current_rule->setDimRangeMin(dim, atoui(from));
	//Portrange[LOW] = atoui(from);
	current_rule->setDimRangeMax(dim, atoui(to));
	//Portrange[HIGH] = atoui(to);
}

void InputReader::ReadProtocol(rule* current_rule, const string& last_token, int dim)
{
	// Example : 0x06/0xFF
	vector<string> split_slash = split(last_token, '/');

	if (split_slash[1] != "0xFF") {
		current_rule->setDimRangeMin(dim, 0);
		current_rule->setDimRangeMax(dim, 255);
	} else {
		current_rule->setDimRangeMin(dim, stoul(split_slash[0], nullptr, 16));
		current_rule->setDimRangeMax(dim, stoul(split_slash[0], nullptr, 16));
		//Protocol[LOW] = Protocol[HIGH] = std::stoul(split_slash[0], nullptr, 16);
	}
}

int InputReader::ReadFilter(vector<string>& tokens, vector<rule*>& ruleset, unsigned int cost, int ruleCounter)
{
	// 5 fields: sip, dip, sport, dport, proto = 0 (with@), 1, 2 : 4, 5 : 7, 8

	/*allocate a few more bytes just to be on the safe side to avoid overflow etc*/
    int dim = 5;
    int reps = 1;
	rule* temp_rule = new rule(dim, ruleCounter);
	string key;
	if (tokens[0].at(0) != '@')  {
		/* each rule should begin with an '@' */
		printf("ERROR: NOT A VALID RULE FORMAT\n");
		exit(1);
	}

	int index_token = 0;
	int i = 0;
	for (int rep = 0; rep < reps; rep++)
	{
		/* reading SIP range */
		if (i == 0) {
            
			ReadIPRange(temp_rule, tokens[index_token++].substr(1), i);
			
			i++;
		} else {
			ReadIPRange(temp_rule, tokens[index_token++], i);
			i++;
		}
		/* reading DIP range */
		ReadIPRange(temp_rule, tokens[index_token++], i);
		i++;
		ReadPort(temp_rule, tokens[index_token], tokens[index_token + 2], i++);
		index_token += 3;
		ReadPort(temp_rule, tokens[index_token], tokens[index_token + 2], i++);
		index_token += 3;
		ReadProtocol(temp_rule, tokens[index_token++], i++);
	}
    // Not working with priority right now.
	//temp_rule.priority = cost;

	ruleset.push_back(temp_rule);

	return 0;
}

// Adapted from the local benchmark parser implementation.
void InputReader::LoadFilters(ifstream& fp, vector<rule*>& ruleset)
{
	int line_number = 0;
	string content;
	int ruleCounter = 0;
	while (getline(fp, content)) {
		istringstream iss(content);
		vector<string> tokens{ istream_iterator < string > {iss}, istream_iterator < string > {} };
		ReadFilter(tokens, ruleset, line_number++, ruleCounter++);
	}
}

std::vector<rule*> InputReader::ReadFilterFileClassBench(const std::string&  filename)
{
	//assume 5*rep fields

	vector<rule*> rules;
	std::ifstream column_counter(filename);
	ifstream input_file(filename);
	if (!input_file.is_open() || !column_counter.is_open())
	{
		printf("Couldnt open filter set file \n");
		exit(1);
	}


	LoadFilters(input_file, rules);
	input_file.close();
	column_counter.close();

	return	rules;
}

bool IsPower2(unsigned int x) {
	return ((x - 1) & x) == 0;
}

bool IsPrefix(unsigned int low, unsigned int high) {
	unsigned int diff = high - low;

	return ((low & high) == low) && IsPower2(diff + 1);
}

unsigned int PrefixLength(unsigned int low, unsigned int high) {
	unsigned int x = high - low;
	int lg = 0;
	for (; x; x >>= 1) lg++;
	return 32 - lg;
}

void InputReader::ParseRange(std::pair<unsigned int, unsigned int>& range, const string& text) {
	vector<string> split_colon = split(text, ':');
	// to obtain interval
	range.first = atoui(split_colon[LOW]);
	range.second = atoui(split_colon[HIGH]);
	if (range.first > range.second) {
		printf("Problematic range: %u-%u\n", range.first, range.second);
	}
}

vector<rule*> InputReader::ReadFilterFileMSU(const string&  filename)
{
	vector<rule*> rules;
	ifstream input_file(filename);
	if (!input_file.is_open())
	{
		printf("Couldnt open filter set file \n");
		exit(1);
	}
	string content;
	getline(input_file, content);
	getline(input_file, content);
	vector<string> split_comma = split(content, ',');
	dim = split_comma.size();

	//int priority = 0;
	getline(input_file, content);
	vector<string> parts = split(content, ',');
	vector<pair<unsigned int, unsigned int>> bounds(parts.size());
	for (size_t i = 0; i < parts.size(); i++) {
		ParseRange(bounds[i], parts[i]);
		//printf("[%u:%u] %d\n", bounds[i][LOW], bounds[i][HIGH], PrefixLength(bounds[i][LOW], bounds[i][HIGH]));
	}

	while (getline(input_file, content)) {
		// 5 fields: sip, dip, sport, dport, proto = 0 (with@), 1, 2 : 4, 5 : 7, 8
        int ruleNum = 0;
		rule* temp_rule = new rule(dim, ruleNum);
		vector<string> split_comma = split(content, ',');
		// ignore priority at the end
		for (size_t i = 0; i < split_comma.size() - 1; i++)
		{
			ParseRange(temp_rule->fields[i], split_comma[i]);
			if (IsPrefix(temp_rule->fields[i].first, temp_rule->fields[i].second)) {
				temp_rule->prefix_length[i] = PrefixLength(temp_rule->fields[i].first, temp_rule->fields[i].second);
			}
			//if ((i == FieldSA || i == FieldDA) & !IsPrefix(temp_rule.range[i][LOW], temp_rule.range[i][HIGH])) {
			//	printf("Field is not a prefix!\n");
			//}
			if (temp_rule->fields[i].first < bounds[i].first || temp_rule->fields[i].second > bounds[i].second) {
				printf("rule out of bounds!\n");
			}
		}
		//temp_rule.priority = priority++;

        temp_rule->ruleNumber = rules.size();
        
		//temp_rule.tag = atoi(split_comma[split_comma.size() - 1].c_str());
		rules.push_back(temp_rule);
	}
	// for (auto & r : rules) {
	// 	r.priority = rules.size() - r.priority;
	// }

	/*for (auto& r : rules) {
	for (auto &p : r.range) {
	cout << p[0] << ":" << p[1] << " ";
	}
	cout << endl;
	}
	exit(0);*/
	return rules;
}

vector<rule*> InputReader::ReadFilterFile(const string&  filename) {
	ifstream in(filename);
	if (!in.is_open())
	{
		printf("Couldnt open filter set file \n");
		printf("%s\n", filename.c_str());
		exit(1);
	} else {
		//printf("Reading filter file %s\n", filename.c_str());
	}
	//cout << filename << " ";
	string content;
	getline(in, content);
	istringstream iss(content);
	vector<string> tokens{ istream_iterator < string > {iss}, istream_iterator < string > {} };
	if (content[0] == '!') {
		// MSU FORMAT
		vector<string> split_semi = split(tokens.back(), ';');
		reps = (atoi(split_semi.back().c_str()) + 1) / 5;
		dim = reps * 5;

		return ReadFilterFileMSU(filename);

	} else if (content[0] == '@') {
		// CLassBench Format
		/* COUNT COLUMN */

		if (tokens.size() % 9 == 0) {
			reps = tokens.size() / 9;
		}
		
	    dim = reps * 5;
		return ReadFilterFileClassBench(filename);
	} else {
		cout << "ERROR: unknown input format please use either MSU format or ClassBench format" << endl;
		exit(1);
	}
	in.close();
	vector<rule*> toAvoidWarning;
	return toAvoidWarning;
}
