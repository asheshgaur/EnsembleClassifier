#include "ElementaryClasses.h"
#include "IO/InputReader.h"
#include "IO/OutputWriter.h"
#include "Simulation.h"

#include "BruteForce.h"
#include "Trees/HyperSplit.h"
#include "Trees/HyperCuts.h"

#include "OVS/TupleSpaceSearch.h"
#include "ClassBenchTraceGenerator/trace_tools.h"

#include "PartitionSort/PartitionSort.h"
#include <stdio.h>


#include <assert.h>
#include <cctype>
#include <cstdlib>
#include <fstream>
#include <functional>
#include <memory>
#include <chrono>
#include <atomic>
#include <thread>
#include <limits.h>
#include <string>
#include <sstream>
#include <sys/wait.h>
#include <unistd.h>

using namespace std;

struct ClassifierDefinition {
	ClassifierTests flag;
	const char* canonicalName;
	bool supportsUpdates;
	function<unique_ptr<PacketClassifier>(const unordered_map<string, string>&)> factory;
};

string GetArgumentAlias(const unordered_map<string, string>& args, const vector<string>& keys, const string& defaultValue);
string NormalizeClassifierName(const string& classifier);
string Trim(const string& value);
string ShellEscape(const string& value);
string ResolveExistingPath(const string& path);
bool IsParallelTechniqueExecutionRequested(const unordered_map<string, string>& args);
bool IsParallelTechniqueExecutionActive(const unordered_map<string, string>& args);
size_t ResolveTechniqueWorkerCount(const unordered_map<string, string>& args, size_t taskCount);
string MakeTempFilePath(const string& prefix, const string& suffix);
string FormatIPv4(uint32_t value);
string FormatIPv4Prefix(const Rule& rule, int field);
const vector<ClassifierDefinition>& GetClassifierDefinitions();
bool IsClassifierSelected(ClassifierTests tests, ClassifierTests flag);
size_t ResolveAccuracyPacketCount(const unordered_map<string, string>& args, size_t packetCount);
vector<size_t> SelectAccuracySampleIndices(size_t packetCount, size_t sampleCount);
int BruteForceClassifyPacket(const vector<Rule>& sortedRules, const Packet& packet);
vector<int> BuildGroundTruthResults(const vector<Rule>& rules, const vector<Packet>& packets, const vector<size_t>& sampleIndices);
void AppendAccuracySummary(const vector<int>& results, const vector<size_t>& sampleIndices, const vector<int>& groundTruth, map<string, string>& summary);
int RunCommand(const string& command);
string RunCommandAndCapture(const string& command, int& exitCode, bool echoOutput = false);
bool TryReadMetric(const string& output, const string& prefix, string& value);
bool HasExternalBenchmarkSelection(ClassifierTests tests);
map<string, string> MakeDefaultBenchmarkSummary(const string& classifierName);
bool WriteExternalRulesFile(const string& filename, const vector<Rule>& rules);
bool WriteExternalTraceFile(const string& filename, const vector<Packet>& packets, const vector<int>* groundTruthRuleIds = nullptr);
bool MatchesRequestedClassifierName(const string& requestedName, const string& canonicalName);
vector<int> BuildGroundTruthRuleIds(const vector<Rule>& rules, const vector<Packet>& packets);
vector<Packet> SelectPacketsByIndex(const vector<Packet>& packets, const vector<size_t>& sampleIndices);
bool ReadResultsFile(const string& filename, vector<int>& results);
bool ReadSingleRowCsvFile(const string& filename, map<string, string>& row);
bool WriteSmartSplitTraceFile(const string& filename, const vector<Packet>& packets);
bool WriteNPTreeTraceFile(const string& filename, const vector<Packet>& packets);
bool WriteSmartSplitRulesFile(const string& filename, const vector<Rule>& rules);
void RunSmartSplitBenchmark(const unordered_map<string, string>& args, const vector<Rule>& rules, const vector<Packet>& packets, vector<map<string, string>>& data);
void RunTupleMergeBenchmark(const unordered_map<string, string>& args, const vector<Rule>& rules, const vector<Packet>& packets,
	const vector<size_t>& accuracySample, const vector<int>& groundTruth, vector<map<string, string>>& data);
void RunByteCutsBenchmark(const unordered_map<string, string>& args, const vector<Rule>& rules, const vector<Packet>& packets,
	const vector<size_t>& accuracySample, const vector<int>& groundTruth, vector<map<string, string>>& data);
void RunCutTSSBenchmark(const unordered_map<string, string>& args, const vector<Rule>& rules, const vector<Packet>& packets,
	const vector<size_t>& accuracySample, const vector<int>& sampleGroundTruthRuleIds, vector<map<string, string>>& data);
void RunCutSplitBenchmark(const unordered_map<string, string>& args, const vector<Rule>& rules, const vector<Packet>& packets,
	const vector<size_t>& accuracySample, const vector<int>& sampleGroundTruthRuleIds, vector<map<string, string>>& data);
void RunTabTreeBenchmark(const unordered_map<string, string>& args, const vector<Rule>& rules, const vector<Packet>& packets,
	const vector<size_t>& accuracySample, const vector<int>& sampleGroundTruthRuleIds, vector<map<string, string>>& data);
void RunNPTreeBenchmark(const unordered_map<string, string>& args, const vector<Rule>& rules, const vector<Packet>& packets,
	const vector<size_t>& accuracySample, const vector<int>& groundTruth, vector<map<string, string>>& data);

vector<int> RunSimulatorClassificationTrial(Simulator& s, const string& name, PacketClassifier& classifier, vector<map<string, string>>& data);
map<string, string> RunNativeClassifierBenchmark(const unordered_map<string, string>& args, const vector<Packet>& packets,
	const vector<Rule>& rules, const ClassifierDefinition& definition, const vector<size_t>& accuracySample, const vector<int>& groundTruth);

pair< vector<string>, vector<map<string, string>>>  RunSimulatorOnlyClassification(const unordered_map<string, string>& args, const vector<Packet>& packets, const vector<Rule>& rules, ClassifierTests tests, const string& outfile = "");

void RunSimulatorUpdateTrial(const Simulator& s, const string& name, PacketClassifier& classifier, const vector<Request>& req,vector<map<string, string>>& data, int reps);

pair< vector<string>, vector<map<string, string>>>  RunSimulatorUpdates(const unordered_map<string, string>& args, const vector<Packet>& packets, const vector<Rule>& rules, ClassifierTests tests, const string& outfile, int repetitions = 1);

bool Validation(const unordered_map<string, PacketClassifier*> classifiers, const vector<Rule>& rules, const vector<Packet>& packets, int threshold = 10);

void RunValidation(const unordered_map<string, string>& args, const vector<Packet>& packets, const vector<Rule>& rules, ClassifierTests tests);

ClassifierTests ParseClassifier(const string& line); 
TestMode ParseMode(const string& mode);


int main(int argc, char* argv[]) {
	unordered_map<string, string> args = ParseArgs(argc, argv);

	string filterFile = GetArgumentAlias(args, { "f", "rules", "ruleset" }, "fw1_seed_1.rules");
	string packetFile = GetArgumentAlias(args, { "p", "packets", "trace" }, "Auto");
	string outputFile = GetArgumentAlias(args, { "o", "output" }, "");
	string classifierArg = GetArgumentAlias(args, { "technique", "classifier", "c" }, "PriorityTuple,PartitionSort");

	string database = GetOrElse(args, "d", "");
	bool doShuffle = GetBoolOrElse(args, "Shuffle", true);

	//set by default
	ClassifierTests classifier = ParseClassifier(classifierArg);
	TestMode mode = ParseMode(GetOrElse(args, "m", "Classification"));

	int repeat = GetIntOrElse(args, "r", 1);

	if (GetBoolOrElse(args, "?", false)) {
		printf("Arguments:\n");
		printf("\tf=<file> or rules=<file>          Filter file in ClassBench/MSU format\n");
		printf("\tp=<file> or packets=<file>        Packet trace file, or Auto to generate from rules\n");
		printf("\to=<file> or output=<file>         CSV output file\n");
		printf("\tc=<name> or technique=<name>      Classifier: PartitionSort, PriorityTuple/PTSS, HyperCuts, HyperSplit, SmartSplit, TupleMerge, ByteCuts, CutTSS, CutSplit, TabTree, NPTree, All\n");
		printf("\tm=<mode>                          Mode: Classification, Update, Validation\n");
		printf("\tPacketCount=<n>                   Number of packets to auto-generate when p=Auto (default 1000000)\n");
		printf("\tAccuracyPackets=<n>               Packets used for exact accuracy checking in Classification mode (default 10000, -1 for all)\n");
		printf("\tSmartSplit.Repo=<path>            Override the vendored SmartSplit workspace path\n");
		printf("\tTupleMerge.Repo=<path>            Override the vendored TupleMerge workspace path\n");
		printf("\tByteCuts.Repo=<path>              Override the vendored ByteCuts workspace path\n");
		printf("\tCutTSS.Repo=<path>                Override the vendored CutTSS workspace path\n");
		printf("\tCutSplit.Repo=<path>              Override the vendored CutSplit workspace path\n");
		printf("\tTabTree.Repo=<path>               Override the vendored TabTree workspace path\n");
		printf("\tNPTree.Repo=<path>                Override the vendored NPTree workspace path\n");
		printf("\tNPTree.MaxRulesPerNode=<n>        Leaf size threshold for NPTree (default 16)\n");
		printf("\tNPTree.Mode=<Specific|Broadest>   NPTree query path to benchmark (default Specific)\n");
		printf("\tParallel=<0|1>                    Run selected classification techniques concurrently (default 0)\n");
		printf("\tTechniqueThreads=<n>              Cap concurrent classification technique workers (default: all selected when Parallel=1)\n");
		printf("\tShuffle=<0|1>                     Shuffle rules before construction (default 1)\n");
		exit(0);
	}
	
	//assign mode and classifer
	vector<Rule> rules = InputReader::ReadFilterFile(filterFile);
	if (rules.empty()) {
		printf("No rules loaded from %s\n", filterFile.c_str());
		exit(EINVAL);
	}

	vector<Packet> packets;
	//generate 1,000,000 packets from ruleset
	if (packetFile == "Auto") {
		int packetCount = GetIntOrElse(args, "PacketCount", 1000000);
		packets = GeneratePacketsFromRuleset(rules, packetCount);
	}
	else if(packetFile != "") packets = InputReader::ReadPackets(packetFile);


	if (doShuffle && HasExternalBenchmarkSelection(classifier)) {
		printf("Shuffle is disabled when external file-based techniques are selected, to keep benchmark rule priority semantics consistent.\n");
		doShuffle = false;
	}

	if (doShuffle) {
		rules = Random::shuffle_vector(rules);
	}

	switch (mode)
	{
			case ModeClassification:
			  RunSimulatorOnlyClassification(args, packets, rules, classifier, outputFile);
				break;
			case ModeUpdate:
				RunSimulatorUpdates(args, packets, rules, classifier, outputFile);
				break;
			case ModeValidation:
				RunValidation(args, packets, rules, classifier);
			        break;
	}
 
	printf("Done\n");
	return 0;
}


string GetArgumentAlias(const unordered_map<string, string>& args, const vector<string>& keys, const string& defaultValue) {
	for (const string& key : keys) {
		auto it = args.find(key);
		if (it != args.end()) {
			return it->second;
		}
	}
	return defaultValue;
}

string NormalizeClassifierName(const string& classifier) {
	string normalized;
	for (char ch : classifier) {
		if (isalnum(static_cast<unsigned char>(ch))) {
			normalized += static_cast<char>(tolower(static_cast<unsigned char>(ch)));
		}
	}
	return normalized;
}

string Trim(const string& value) {
	size_t start = 0;
	while (start < value.size() && isspace(static_cast<unsigned char>(value[start]))) {
		start++;
	}
	size_t end = value.size();
	while (end > start && isspace(static_cast<unsigned char>(value[end - 1]))) {
		end--;
	}
	return value.substr(start, end - start);
}

string ShellEscape(const string& value) {
	string escaped = "'";
	for (char ch : value) {
		if (ch == '\'') {
			escaped += "'\\''";
		}
		else {
			escaped += ch;
		}
	}
	escaped += "'";
	return escaped;
}

string ResolveExistingPath(const string& path) {
	string expanded = path;
	if (expanded == "~" || (expanded.size() >= 2 && expanded[0] == '~' && expanded[1] == '/')) {
		const char* home = getenv("HOME");
		if (home != nullptr && *home != '\0') {
			expanded = string(home) + (expanded.size() == 1 ? "" : expanded.substr(1));
		}
	}
	char resolved[PATH_MAX];
	if (realpath(expanded.c_str(), resolved) != nullptr) {
		return string(resolved);
	}
	if (!expanded.empty() && expanded[0] == '/') {
		return expanded;
	}
	char cwd[PATH_MAX];
	if (getcwd(cwd, sizeof(cwd)) == nullptr) {
		return expanded;
	}
	return string(cwd) + "/" + expanded;
}

bool IsParallelTechniqueExecutionRequested(const unordered_map<string, string>& args) {
	int requestedWorkers = GetIntOrElse(args, "TechniqueThreads", GetIntOrElse(args, "Threads", 0));
	if (requestedWorkers > 1) {
		return true;
	}
	return GetBoolOrElse(args, "Parallel", false);
}

bool IsParallelTechniqueExecutionActive(const unordered_map<string, string>& args) {
	return GetBoolOrElse(args, "__parallel_active", false);
}

size_t ResolveTechniqueWorkerCount(const unordered_map<string, string>& args, size_t taskCount) {
	if (taskCount <= 1) {
		return taskCount;
	}
	if (!IsParallelTechniqueExecutionRequested(args)) {
		return 1;
	}

	int requestedWorkers = GetIntOrElse(args, "TechniqueThreads", GetIntOrElse(args, "Threads", 0));
	if (requestedWorkers <= 0) {
		return taskCount;
	}
	return min(taskCount, static_cast<size_t>(requestedWorkers));
}

string MakeTempFilePath(const string& prefix, const string& suffix) {
	static atomic<unsigned long long> uniqueCounter(0);
	ostringstream ss;
	ss << "/tmp/codex_" << prefix << "_" << getpid() << "_" << uniqueCounter.fetch_add(1) << suffix;
	return ss.str();
}

string FormatIPv4(uint32_t value) {
	ostringstream ss;
	ss << ((value >> 24) & 0xFF) << "."
		<< ((value >> 16) & 0xFF) << "."
		<< ((value >> 8) & 0xFF) << "."
		<< (value & 0xFF);
	return ss.str();
}

string FormatIPv4Prefix(const Rule& rule, int field) {
	ostringstream ss;
	ss << FormatIPv4(rule.range[field][LowDim]) << "/" << rule.prefix_length[field];
	return ss.str();
}

const vector<ClassifierDefinition>& GetClassifierDefinitions() {
	static const vector<ClassifierDefinition> definitions = {
		{
			TestPartitionSort,
			"PartitionSort",
			true,
			[](const unordered_map<string, string>&) {
				return unique_ptr<PacketClassifier>(new PartitionSort());
			}
		},
		{
			TestPriorityTuple,
			"PriorityTuple",
			true,
			[](const unordered_map<string, string>&) {
				return unique_ptr<PacketClassifier>(new PriorityTupleSpaceSearch());
			}
		},
		{
			TestHyperCuts,
			"HyperCuts",
			false,
			[](const unordered_map<string, string>&) {
				return unique_ptr<PacketClassifier>(new HyperCuts());
			}
		},
		{
			TestHyperSplit,
			"HyperSplit",
			false,
			[](const unordered_map<string, string>& args) {
				return unique_ptr<PacketClassifier>(new HyperSplit(args));
			}
		}
	};
	return definitions;
}

bool IsClassifierSelected(ClassifierTests tests, ClassifierTests flag) {
	return (tests & flag) != 0;
}

bool HasExternalBenchmarkSelection(ClassifierTests tests) {
	return IsClassifierSelected(tests, TestSmartSplit)
		|| IsClassifierSelected(tests, TestTupleMerge)
		|| IsClassifierSelected(tests, TestByteCuts)
		|| IsClassifierSelected(tests, TestCutTSS)
		|| IsClassifierSelected(tests, TestCutSplit)
		|| IsClassifierSelected(tests, TestTabTree)
		|| IsClassifierSelected(tests, TestNPTree);
}

map<string, string> MakeDefaultBenchmarkSummary(const string& classifierName) {
	return {
		{ "Classifier", classifierName },
		{ "ConstructionTime(ms)", "N/A" },
		{ "ClassificationTime(s)", "N/A" },
		{ "Size(bytes)", "N/A" },
		{ "MemoryAccess", "N/A" },
		{ "Tables", "N/A" },
		{ "TableSizes", "N/A" },
		{ "TableQueries", "N/A" },
		{ "AvgQueries", "N/A" },
		{ "AccuracySampleSize", "0" },
		{ "CorrectPackets", "0" },
		{ "IncorrectPackets", "0" },
		{ "Accuracy(%)", "0" }
		};
}

bool MatchesRequestedClassifierName(const string& requestedName, const string& canonicalName) {
	string normalizedRequested = NormalizeClassifierName(requestedName);
	string normalizedCanonical = NormalizeClassifierName(canonicalName);
	if (normalizedRequested == normalizedCanonical) {
		return true;
	}
	return normalizedRequested == "ptss" && normalizedCanonical == "prioritytuple";
}

bool WriteExternalRulesFile(const string& filename, const vector<Rule>& rules) {
	return WriteSmartSplitRulesFile(filename, rules);
}

bool WriteExternalTraceFile(const string& filename, const vector<Packet>& packets, const vector<int>* groundTruthRuleIds) {
	ofstream out(filename);
	if (!out.is_open()) {
		return false;
	}

	if (groundTruthRuleIds != nullptr && groundTruthRuleIds->size() != packets.size()) {
		return false;
	}

	for (size_t i = 0; i < packets.size(); i++) {
		const Packet& packet = packets[i];
		if (packet.size() < 5) {
			return false;
		}

		int fid = 0;
		if (groundTruthRuleIds != nullptr) {
			fid = (*groundTruthRuleIds)[i];
		}

		out << packet[0] << '\t'
			<< packet[1] << '\t'
			<< packet[2] << '\t'
			<< packet[3] << '\t'
			<< packet[4] << '\t'
			<< 0 << '\t'
			<< fid << '\n';
	}
	return out.good();
}

vector<int> BuildGroundTruthRuleIds(const vector<Rule>& rules, const vector<Packet>& packets) {
	vector<Rule> sortedRules = rules;
	SortRules(sortedRules);

	vector<int> groundTruthRuleIds;
	groundTruthRuleIds.reserve(packets.size());
	for (const Packet& packet : packets) {
		int matchId = -1;
		for (size_t i = 0; i < sortedRules.size(); i++) {
			if (sortedRules[i].MatchesPacket(packet)) {
				matchId = static_cast<int>(i);
				break;
			}
		}
		groundTruthRuleIds.push_back(matchId);
	}
	return groundTruthRuleIds;
}

vector<Packet> SelectPacketsByIndex(const vector<Packet>& packets, const vector<size_t>& sampleIndices) {
	vector<Packet> selected;
	selected.reserve(sampleIndices.size());
	for (size_t index : sampleIndices) {
		selected.push_back(packets[index]);
	}
	return selected;
}

bool ReadResultsFile(const string& filename, vector<int>& results) {
	ifstream input(filename);
	if (!input.is_open()) {
		return false;
	}

	results.clear();
	string line;
	while (getline(input, line)) {
		line = Trim(line);
		if (line.empty()) {
			continue;
		}
		results.push_back(stoi(line));
	}
	return input.good() || input.eof();
}

bool ReadSingleRowCsvFile(const string& filename, map<string, string>& row) {
	ifstream input(filename);
	if (!input.is_open()) {
		return false;
	}

	string headerLine;
	string valueLine;
	if (!getline(input, headerLine) || !getline(input, valueLine)) {
		return false;
	}

	vector<string> headers;
	vector<string> values;
	Split(headerLine, ',', headers);
	Split(valueLine, ',', values);
	if (headers.empty() || headers.size() != values.size()) {
		return false;
	}

	row.clear();
	for (size_t i = 0; i < headers.size(); i++) {
		row[Trim(headers[i])] = Trim(values[i]);
	}
	return true;
}

size_t ResolveAccuracyPacketCount(const unordered_map<string, string>& args, size_t packetCount) {
	int requested = GetIntOrElse(args, "AccuracyPackets", 10000);
	if (requested < 0) {
		return packetCount;
	}
	return min(packetCount, static_cast<size_t>(requested));
}

vector<size_t> SelectAccuracySampleIndices(size_t packetCount, size_t sampleCount) {
	vector<size_t> indices;
	if (sampleCount == 0 || packetCount == 0) {
		return indices;
	}
	indices.reserve(sampleCount);
	if (sampleCount >= packetCount) {
		for (size_t i = 0; i < packetCount; i++) {
			indices.push_back(i);
		}
		return indices;
	}
	for (size_t i = 0; i < sampleCount; i++) {
		indices.push_back((i * packetCount) / sampleCount);
	}
	return indices;
}

int BruteForceClassifyPacket(const vector<Rule>& sortedRules, const Packet& packet) {
	for (const Rule& rule : sortedRules) {
		if (rule.MatchesPacket(packet)) {
			return rule.priority;
		}
	}
	return -1;
}

vector<int> BuildGroundTruthResults(const vector<Rule>& rules, const vector<Packet>& packets, const vector<size_t>& sampleIndices) {
	vector<Rule> sortedRules = rules;
	SortRules(sortedRules);

	vector<int> groundTruth;
	groundTruth.reserve(sampleIndices.size());
	for (size_t packetIndex : sampleIndices) {
		groundTruth.push_back(BruteForceClassifyPacket(sortedRules, packets[packetIndex]));
	}
	return groundTruth;
}

int RunCommand(const string& command) {
	int status = system(command.c_str());
	if (status == -1) {
		return -1;
	}
	if (WIFEXITED(status)) {
		return WEXITSTATUS(status);
	}
	return status;
}

string RunCommandAndCapture(const string& command, int& exitCode, bool echoOutput) {
	FILE* pipe = popen(command.c_str(), "r");
	if (pipe == nullptr) {
		exitCode = -1;
		return "";
	}

	char buffer[4096];
	string output;
	while (fgets(buffer, sizeof(buffer), pipe) != nullptr) {
		output += buffer;
		if (echoOutput) {
			fputs(buffer, stdout);
			fflush(stdout);
		}
	}

	int status = pclose(pipe);
	if (status == -1) {
		exitCode = -1;
	}
	else if (WIFEXITED(status)) {
		exitCode = WEXITSTATUS(status);
	}
	else {
		exitCode = status;
	}
	return output;
}

bool TryReadMetric(const string& output, const string& prefix, string& value) {
	size_t pos = output.rfind(prefix);
	if (pos == string::npos) {
		return false;
	}
	size_t start = pos + prefix.size();
	size_t end = output.find('\n', start);
	value = Trim(output.substr(start, end == string::npos ? string::npos : end - start));
	return true;
}

bool TryReadTechniqueMetric(const string& output, const string& technique, const string& metric, string& value) {
	return TryReadMetric(output, "BENCHMARK." + technique + "." + metric + "=", value);
}

bool WriteSmartSplitTraceFile(const string& filename, const vector<Packet>& packets) {
	ofstream out(filename);
	if (!out.is_open()) {
		return false;
	}

	for (const Packet& packet : packets) {
		if (packet.size() < 5) {
			return false;
		}
		out << packet[0] << '\t'
			<< packet[1] << '\t'
			<< packet[2] << '\t'
			<< packet[3] << '\t'
			<< packet[4] << '\t'
			<< 0 << '\t'
			<< 0 << '\n';
	}
	return out.good();
}

bool WriteNPTreeTraceFile(const string& filename, const vector<Packet>& packets) {
	ofstream out(filename);
	if (!out.is_open()) {
		return false;
	}

	for (const Packet& packet : packets) {
		if (packet.size() < 5) {
			return false;
		}
		out << packet[0] << '\t'
			<< packet[1] << '\t'
			<< packet[2] << '\t'
			<< packet[3] << '\t'
			<< packet[4] << '\n';
	}
	return out.good();
}

bool WriteSmartSplitRulesFile(const string& filename, const vector<Rule>& rules) {
	vector<Rule> sortedRules = rules;
	SortRules(sortedRules);

	ofstream out(filename);
	if (!out.is_open()) {
		return false;
	}

	for (const Rule& rule : sortedRules) {
		ostringstream line;
		line << "@" << FormatIPv4Prefix(rule, FieldSA) << '\t'
			<< FormatIPv4Prefix(rule, FieldDA) << '\t'
			<< rule.range[FieldSP][LowDim] << " : " << rule.range[FieldSP][HighDim] << '\t'
			<< rule.range[FieldDP][LowDim] << " : " << rule.range[FieldDP][HighDim] << '\t';

		if (rule.range[FieldProto][LowDim] == 0 && rule.range[FieldProto][HighDim] == 0xFF) {
			line << "0x0/0x0\t";
		}
		else {
			line << "0x" << hex << rule.range[FieldProto][LowDim] << "/0xFF\t" << dec;
		}
		line << "0x0/0x0\n";
		out << line.str();
	}
	return out.good();
}

void AppendAccuracySummary(const vector<int>& results, const vector<size_t>& sampleIndices, const vector<int>& groundTruth, map<string, string>& summary) {
	size_t sampleSize = sampleIndices.size();
	if (sampleSize == 0) {
		printf("\tAccuracy sample size: 0\n");
		printf("\tAccuracy: 0.000000%%\n");
		summary["AccuracySampleSize"] = "0";
		summary["CorrectPackets"] = "0";
		summary["IncorrectPackets"] = "0";
		summary["Accuracy(%)"] = "0";
		return;
	}

	size_t correct = 0;
	for (size_t i = 0; i < sampleSize; i++) {
		if (results[sampleIndices[i]] == groundTruth[i]) {
			correct++;
		}
	}

	size_t incorrect = sampleSize - correct;
	double accuracy = 100.0 * correct / sampleSize;
	printf("\tAccuracy sample size: %zu\n", sampleSize);
	printf("\tAccuracy: %.6f%% (%zu/%zu)\n", accuracy, correct, sampleSize);
	summary["AccuracySampleSize"] = to_string(sampleSize);
	summary["CorrectPackets"] = to_string(correct);
	summary["IncorrectPackets"] = to_string(incorrect);
	summary["Accuracy(%)"] = to_string(accuracy);
}

void RunSmartSplitBenchmark(const unordered_map<string, string>& args, const vector<Rule>& rules, const vector<Packet>& packets, vector<map<string, string>>& data) {
	map<string, string> summary = {
		{ "Classifier", "SmartSplit" },
		{ "ConstructionTime(ms)", "N/A" },
		{ "ClassificationTime(s)", "N/A" },
		{ "Size(bytes)", "N/A" },
		{ "MemoryAccess", "N/A" },
		{ "Tables", "N/A" },
		{ "TableSizes", "N/A" },
		{ "TableQueries", "N/A" },
		{ "AvgQueries", "N/A" },
		{ "AccuracySampleSize", "0" },
		{ "CorrectPackets", "0" },
		{ "IncorrectPackets", "0" },
		{ "Accuracy(%)", "0" }
	};

	printf("SmartSplit\n");
	if (packets.empty()) {
		printf("\tNo packets available for classification\n");
		data.push_back(summary);
		return;
	}
	printf("\tSmartSplit runs an external multi-stage build and can take a long time on large rulesets.\n");
	bool echoOutput = !IsParallelTechniqueExecutionActive(args);
	if (echoOutput) {
		printf("\tStreaming SmartSplit progress below.\n");
	}
	else {
		printf("\tParallel execution is enabled, so SmartSplit subprocess output is buffered until completion.\n");
	}

	string repoRoot = ResolveExistingPath(GetArgumentAlias(args, { "SmartSplit.Repo", "SmartSplit.Path" }, "External/SmartSplit"));
	string analyzerDir = repoRoot + "/analyzer";
	string hcDir = repoRoot + "/hc";
	string hsDir = repoRoot + "/hs_lookup";

	if (RunCommand("make -C " + ShellEscape(hcDir)) != 0 ||
		RunCommand("make -C " + ShellEscape(hsDir)) != 0 ||
		RunCommand("make -C " + ShellEscape(analyzerDir)) != 0) {
		printf("\tSmartSplit build failed\n");
		data.push_back(summary);
		return;
	}

	ostringstream tracePath;
	tracePath << "/tmp/codex_smartsplit_trace_" << getpid() << ".txt";
	ostringstream rulesPath;
	rulesPath << "/tmp/codex_smartsplit_rules_" << getpid() << ".rules";
	if (!WriteSmartSplitTraceFile(tracePath.str(), packets)) {
		printf("\tFailed to write SmartSplit trace file\n");
		data.push_back(summary);
		return;
	}
	if (!WriteSmartSplitRulesFile(rulesPath.str(), rules)) {
		printf("\tFailed to write SmartSplit rules file\n");
		remove(tracePath.str().c_str());
		data.push_back(summary);
		return;
	}

	string command = "cd " + ShellEscape(analyzerDir)
		+ " && bash ./run.sh " + ShellEscape(rulesPath.str()) + " " + ShellEscape(tracePath.str()) + " 2>&1";
	int exitCode = 0;
	string output = RunCommandAndCapture(command, exitCode, echoOutput);
	remove(tracePath.str().c_str());
	remove(rulesPath.str().c_str());

	if (exitCode != 0) {
		printf("\tSmartSplit benchmark failed\n");
		printf("%s\n", output.c_str());
		data.push_back(summary);
		return;
	}

	string totalNsText;
	string buildMsText;
	string memoryBytesText;
	string accuracyText;
	string correctText;
	string incorrectText;
	string packetCountText;
	if (!TryReadMetric(output, "BENCHMARK.TIME_NS_TOTAL=", totalNsText) ||
		!TryReadMetric(output, "BENCHMARK.CONSTRUCTION_MS=", buildMsText) ||
		!TryReadMetric(output, "BENCHMARK.MEMORY_BYTES=", memoryBytesText) ||
		!TryReadMetric(output, "BENCHMARK.ACCURACY_PERCENT=", accuracyText) ||
		!TryReadMetric(output, "BENCHMARK.CORRECT=", correctText) ||
		!TryReadMetric(output, "BENCHMARK.INCORRECT=", incorrectText) ||
		!TryReadMetric(output, "BENCHMARK.PACKETS=", packetCountText)) {
		printf("\tSmartSplit benchmark output was not parseable\n");
		printf("%s\n", output.c_str());
		data.push_back(summary);
		return;
	}

	double classificationSeconds = stod(totalNsText) / 1000000000.0;
	double accuracy = stod(accuracyText);
	summary["ConstructionTime(ms)"] = buildMsText;
	summary["Size(bytes)"] = memoryBytesText;
	printf("\tClassification time: %f s\n", classificationSeconds);
	printf("\tAccuracy sample size: %s\n", packetCountText.c_str());
	printf("\tAccuracy: %.6f%% (%s/%s)\n", accuracy, correctText.c_str(), packetCountText.c_str());

	summary["ClassificationTime(s)"] = to_string(classificationSeconds);
	summary["AccuracySampleSize"] = packetCountText;
	summary["CorrectPackets"] = correctText;
	summary["IncorrectPackets"] = incorrectText;
	summary["Accuracy(%)"] = accuracyText;
	data.push_back(summary);
}

void RunTupleMergeBenchmark(const unordered_map<string, string>& args, const vector<Rule>& rules, const vector<Packet>& packets,
	const vector<size_t>& accuracySample, const vector<int>& groundTruth, vector<map<string, string>>& data) {
	map<string, string> summary = MakeDefaultBenchmarkSummary("TupleMerge");
	printf("TupleMerge\n");
	if (packets.empty()) {
		printf("\tNo packets available for classification\n");
		data.push_back(summary);
		return;
	}

	string repoRoot = ResolveExistingPath(GetArgumentAlias(args, { "TupleMerge.Repo", "TupleMerge.Path" }, "External/TupleMerge"));
	if (RunCommand("make -C " + ShellEscape(repoRoot)) != 0) {
		printf("\tTupleMerge build failed\n");
		data.push_back(summary);
		return;
	}

	string rulesPath = MakeTempFilePath("tuplemerge_rules", ".rules");
	string tracePath = MakeTempFilePath("tuplemerge_trace", ".txt");
	string resultsPath = MakeTempFilePath("tuplemerge_results", ".txt");
	if (!WriteExternalRulesFile(rulesPath, rules) || !WriteExternalTraceFile(tracePath, packets, nullptr)) {
		printf("\tFailed to write TupleMerge input files\n");
		remove(rulesPath.c_str());
		remove(tracePath.c_str());
		data.push_back(summary);
		return;
	}

	string command = "cd " + ShellEscape(repoRoot)
		+ " && script -q /dev/null ./main f=" + ShellEscape(rulesPath)
		+ " p=" + ShellEscape(tracePath)
		+ " c=" + ShellEscape("TMOffline")
		+ " m=" + ShellEscape("Classification")
		+ " Results=" + ShellEscape(resultsPath)
		+ " Shuffle=0 2>&1";
	int exitCode = 0;
	string output = RunCommandAndCapture(command, exitCode, false);
	vector<int> results;
	string constructionText;
	string classificationText;
	string sizeText;
	string tablesText;
	string avgQueriesText;
	if (!ReadResultsFile(resultsPath, results) || results.size() != packets.size()
		|| !TryReadMetric(output, "\tConstruction time: ", constructionText)
		|| !TryReadMetric(output, "\tClassification time: ", classificationText)
		|| !TryReadMetric(output, "\tSize(bytes): ", sizeText)
		|| !TryReadMetric(output, "\tTables: ", tablesText)
		|| !TryReadMetric(output, "\tAverage tables queried: ", avgQueriesText)) {
		printf("\tTupleMerge benchmark output was not parseable\n");
		remove(rulesPath.c_str());
		remove(tracePath.c_str());
		remove(resultsPath.c_str());
		data.push_back(summary);
		return;
	}

	summary["ConstructionTime(ms)"] = Trim(constructionText.substr(0, constructionText.find(' ')));
	summary["ClassificationTime(s)"] = Trim(classificationText.substr(0, classificationText.find(' ')));
	summary["Size(bytes)"] = Trim(sizeText.substr(0, sizeText.find(' ')));
	summary["Tables"] = Trim(tablesText.substr(0, tablesText.find(' ')));
	summary["AvgQueries"] = Trim(avgQueriesText.substr(0, avgQueriesText.find(' ')));
	printf("\tClassification time: %s s\n", summary["ClassificationTime(s)"].c_str());
	AppendAccuracySummary(results, accuracySample, groundTruth, summary);

	remove(rulesPath.c_str());
	remove(tracePath.c_str());
	remove(resultsPath.c_str());
	data.push_back(summary);
}

void RunByteCutsBenchmark(const unordered_map<string, string>& args, const vector<Rule>& rules, const vector<Packet>& packets,
	const vector<size_t>& accuracySample, const vector<int>& groundTruth, vector<map<string, string>>& data) {
	map<string, string> summary = MakeDefaultBenchmarkSummary("ByteCuts");
	printf("ByteCuts\n");
	if (packets.empty()) {
		printf("\tNo packets available for classification\n");
		data.push_back(summary);
		return;
	}

	string repoRoot = ResolveExistingPath(GetArgumentAlias(args, { "ByteCuts.Repo", "ByteCuts.Path" }, "External/ByteCuts"));
	if (RunCommand("make -C " + ShellEscape(repoRoot)) != 0) {
		printf("\tByteCuts build failed\n");
		data.push_back(summary);
		return;
	}

	string rulesPath = MakeTempFilePath("bytecuts_rules", ".rules");
	string tracePath = MakeTempFilePath("bytecuts_trace", ".txt");
	string csvPath = MakeTempFilePath("bytecuts_stats", ".csv");
	string resultsPath = MakeTempFilePath("bytecuts_results", ".txt");
	if (!WriteExternalRulesFile(rulesPath, rules) || !WriteExternalTraceFile(tracePath, packets, nullptr)) {
		printf("\tFailed to write ByteCuts input files\n");
		remove(rulesPath.c_str());
		remove(tracePath.c_str());
		data.push_back(summary);
		return;
	}

	string command = "cd " + ShellEscape(repoRoot)
		+ " && ./main Rules=" + ShellEscape(rulesPath)
		+ " Packets=" + ShellEscape(tracePath)
		+ " Stats=" + ShellEscape(csvPath)
		+ " Results=" + ShellEscape(resultsPath)
		+ " 2>&1";
	int exitCode = 0;
	string output = RunCommandAndCapture(command, exitCode, !IsParallelTechniqueExecutionActive(args));
	if (exitCode != 0) {
		printf("\tByteCuts benchmark failed\n");
		printf("%s\n", output.c_str());
		remove(rulesPath.c_str());
		remove(tracePath.c_str());
		remove(csvPath.c_str());
		remove(resultsPath.c_str());
		data.push_back(summary);
		return;
	}

	map<string, string> csvRow;
	vector<int> results;
	if (!ReadSingleRowCsvFile(csvPath, csvRow) || !ReadResultsFile(resultsPath, results) || results.size() != packets.size()) {
		printf("\tByteCuts benchmark output was not parseable\n");
		remove(rulesPath.c_str());
		remove(tracePath.c_str());
		remove(csvPath.c_str());
		remove(resultsPath.c_str());
		data.push_back(summary);
		return;
	}

	auto buildIt = csvRow.find("Build");
	if (buildIt != csvRow.end()) {
		summary["ConstructionTime(ms)"] = to_string(stod(buildIt->second) * 1000.0);
	}
	auto classifyIt = csvRow.find("Classify");
	if (classifyIt != csvRow.end()) {
		summary["ClassificationTime(s)"] = classifyIt->second;
	}
	auto memoryIt = csvRow.find("Memory");
	if (memoryIt != csvRow.end()) {
		summary["Size(bytes)"] = memoryIt->second;
	}
	auto treesIt = csvRow.find("Trees");
	if (treesIt != csvRow.end()) {
		summary["Tables"] = treesIt->second;
	}

	AppendAccuracySummary(results, accuracySample, groundTruth, summary);

	remove(rulesPath.c_str());
	remove(tracePath.c_str());
	remove(csvPath.c_str());
	remove(resultsPath.c_str());
	data.push_back(summary);
}

void RunCutTSSBenchmark(const unordered_map<string, string>& args, const vector<Rule>& rules, const vector<Packet>& packets,
	const vector<size_t>& accuracySample, const vector<int>& sampleGroundTruthRuleIds, vector<map<string, string>>& data) {
	map<string, string> summary = MakeDefaultBenchmarkSummary("CutTSS");
	printf("CutTSS\n");
	if (packets.empty()) {
		printf("\tNo packets available for classification\n");
		data.push_back(summary);
		return;
	}

	string repoRoot = ResolveExistingPath(GetArgumentAlias(args, { "CutTSS.Repo", "CutTSS.Path" }, "External/CutTSS"));
	if (RunCommand("make -C " + ShellEscape(repoRoot)) != 0) {
		printf("\tCutTSS build failed\n");
		data.push_back(summary);
		return;
	}

	vector<Packet> samplePackets = SelectPacketsByIndex(packets, accuracySample);
	string rulesPath = MakeTempFilePath("cuttss_rules", ".rules");
	string fullTracePath = MakeTempFilePath("cuttss_trace", ".txt");
	string sampleTracePath = MakeTempFilePath("cuttss_trace_sample", ".txt");
	bool runSampleAccuracy = !samplePackets.empty();
	if (!WriteExternalRulesFile(rulesPath, rules)
		|| !WriteExternalTraceFile(fullTracePath, packets, nullptr)
		|| (runSampleAccuracy && !WriteExternalTraceFile(sampleTracePath, samplePackets, &sampleGroundTruthRuleIds))) {
		printf("\tFailed to write CutTSS input files\n");
		remove(rulesPath.c_str());
		remove(fullTracePath.c_str());
		remove(sampleTracePath.c_str());
		data.push_back(summary);
		return;
	}

	int bucket = GetIntOrElse(args, "CutTSS.Bucket", 8);
	int threshold = GetIntOrElse(args, "CutTSS.Threshold", 12);
	string baseCommand = "cd " + ShellEscape(repoRoot)
		+ " && ./main -b " + to_string(bucket)
		+ " -t " + to_string(threshold)
		+ " -r " + ShellEscape(rulesPath)
		+ " -c 1 -u 0 -e ";
	bool echoOutput = !IsParallelTechniqueExecutionActive(args);

	int fullExitCode = 0;
	string fullOutput = RunCommandAndCapture(baseCommand + ShellEscape(fullTracePath) + " 2>&1", fullExitCode, echoOutput);
	int sampleExitCode = 0;
	string sampleOutput;
	if (runSampleAccuracy) {
		sampleOutput = RunCommandAndCapture(baseCommand + ShellEscape(sampleTracePath) + " 2>&1", sampleExitCode, false);
	}

	remove(rulesPath.c_str());
	remove(fullTracePath.c_str());
	remove(sampleTracePath.c_str());

	if (fullExitCode != 0 || sampleExitCode != 0) {
		printf("\tCutTSS benchmark failed\n");
		if (fullExitCode != 0) {
			printf("%s\n", fullOutput.c_str());
		}
		if (sampleExitCode != 0) {
			printf("%s\n", sampleOutput.c_str());
		}
		data.push_back(summary);
		return;
	}

	string timeNsText;
	string buildMsText;
	string memoryBytesText;
	string accuracyText;
	string correctText;
	string incorrectText;
	string packetCountText;
	if (!TryReadTechniqueMetric(fullOutput, "CutTSS", "TIME_NS_TOTAL", timeNsText)) {
		printf("\tCutTSS benchmark output was not parseable\n");
		data.push_back(summary);
		return;
	}
	if (runSampleAccuracy && (!TryReadTechniqueMetric(sampleOutput, "CutTSS", "ACCURACY_PERCENT", accuracyText)
		|| !TryReadTechniqueMetric(sampleOutput, "CutTSS", "CORRECT", correctText)
		|| !TryReadTechniqueMetric(sampleOutput, "CutTSS", "INCORRECT", incorrectText)
		|| !TryReadTechniqueMetric(sampleOutput, "CutTSS", "PACKETS", packetCountText))) {
		printf("\tCutTSS sample accuracy output was not parseable\n");
		data.push_back(summary);
		return;
	}

	if (TryReadTechniqueMetric(fullOutput, "CutTSS", "CONSTRUCTION_MS", buildMsText)) {
		summary["ConstructionTime(ms)"] = buildMsText;
	}
	if (TryReadTechniqueMetric(fullOutput, "CutTSS", "MEMORY_BYTES", memoryBytesText)) {
		summary["Size(bytes)"] = memoryBytesText;
	}
	summary["ClassificationTime(s)"] = to_string(stod(timeNsText) / 1000000000.0);
	if (runSampleAccuracy) {
		int repeatedPacketCount = stoi(packetCountText);
		int sampleSize = static_cast<int>(samplePackets.size());
		int repeatFactor = sampleSize > 0 ? max(1, repeatedPacketCount / sampleSize) : 1;
		summary["AccuracySampleSize"] = to_string(sampleSize);
		summary["CorrectPackets"] = to_string(stoi(correctText) / repeatFactor);
		summary["IncorrectPackets"] = to_string(stoi(incorrectText) / repeatFactor);
		summary["Accuracy(%)"] = accuracyText;
	}
	printf("\tClassification time: %s s\n", summary["ClassificationTime(s)"].c_str());
	if (runSampleAccuracy) {
		printf("\tAccuracy sample size: %s\n", summary["AccuracySampleSize"].c_str());
		printf("\tAccuracy: %s%% (%s/%s)\n", accuracyText.c_str(), summary["CorrectPackets"].c_str(), summary["AccuracySampleSize"].c_str());
	}
	data.push_back(summary);
}

void RunCutSplitBenchmark(const unordered_map<string, string>& args, const vector<Rule>& rules, const vector<Packet>& packets,
	const vector<size_t>& accuracySample, const vector<int>& sampleGroundTruthRuleIds, vector<map<string, string>>& data) {
	map<string, string> summary = MakeDefaultBenchmarkSummary("CutSplit");
	printf("CutSplit\n");
	if (packets.empty()) {
		printf("\tNo packets available for classification\n");
		data.push_back(summary);
		return;
	}

	string repoRoot = ResolveExistingPath(GetArgumentAlias(args, { "CutSplit.Repo", "CutSplit.Path" }, "External/CutSplit"));
	if (RunCommand("make -C " + ShellEscape(repoRoot)) != 0) {
		printf("\tCutSplit build failed\n");
		data.push_back(summary);
		return;
	}

	vector<Packet> samplePackets = SelectPacketsByIndex(packets, accuracySample);
	string rulesPath = MakeTempFilePath("cutsplit_rules", ".rules");
	string fullTracePath = MakeTempFilePath("cutsplit_trace", ".txt");
	string sampleTracePath = MakeTempFilePath("cutsplit_trace_sample", ".txt");
	bool runSampleAccuracy = !samplePackets.empty();
	if (!WriteExternalRulesFile(rulesPath, rules)
		|| !WriteExternalTraceFile(fullTracePath, packets, nullptr)
		|| (runSampleAccuracy && !WriteExternalTraceFile(sampleTracePath, samplePackets, &sampleGroundTruthRuleIds))) {
		printf("\tFailed to write CutSplit input files\n");
		remove(rulesPath.c_str());
		remove(fullTracePath.c_str());
		remove(sampleTracePath.c_str());
		data.push_back(summary);
		return;
	}

	int bucket = GetIntOrElse(args, "CutSplit.Bucket", 8);
	int threshold = GetIntOrElse(args, "CutSplit.Threshold", 12);
	string baseCommand = "cd " + ShellEscape(repoRoot)
		+ " && ./main -b " + to_string(bucket)
		+ " -t " + to_string(threshold)
		+ " -r " + ShellEscape(rulesPath)
		+ " -c 1 -u 0 -e ";
	bool echoOutput = !IsParallelTechniqueExecutionActive(args);

	int fullExitCode = 0;
	string fullOutput = RunCommandAndCapture(baseCommand + ShellEscape(fullTracePath) + " 2>&1", fullExitCode, echoOutput);
	int sampleExitCode = 0;
	string sampleOutput;
	if (runSampleAccuracy) {
		sampleOutput = RunCommandAndCapture(baseCommand + ShellEscape(sampleTracePath) + " 2>&1", sampleExitCode, false);
	}

	remove(rulesPath.c_str());
	remove(fullTracePath.c_str());
	remove(sampleTracePath.c_str());

	if (fullExitCode != 0 || sampleExitCode != 0) {
		printf("\tCutSplit benchmark failed\n");
		if (fullExitCode != 0) {
			printf("%s\n", fullOutput.c_str());
		}
		if (sampleExitCode != 0) {
			printf("%s\n", sampleOutput.c_str());
		}
		data.push_back(summary);
		return;
	}

	string timeNsText;
	string buildMsText;
	string memoryBytesText;
	string accuracyText;
	string correctText;
	string incorrectText;
	string packetCountText;
	if (!TryReadTechniqueMetric(fullOutput, "CutSplit", "TIME_NS_TOTAL", timeNsText)) {
		printf("\tCutSplit benchmark output was not parseable\n");
		data.push_back(summary);
		return;
	}
	if (runSampleAccuracy && (!TryReadTechniqueMetric(sampleOutput, "CutSplit", "ACCURACY_PERCENT", accuracyText)
		|| !TryReadTechniqueMetric(sampleOutput, "CutSplit", "CORRECT", correctText)
		|| !TryReadTechniqueMetric(sampleOutput, "CutSplit", "INCORRECT", incorrectText)
		|| !TryReadTechniqueMetric(sampleOutput, "CutSplit", "PACKETS", packetCountText))) {
		printf("\tCutSplit sample accuracy output was not parseable\n");
		data.push_back(summary);
		return;
	}

	if (TryReadTechniqueMetric(fullOutput, "CutSplit", "CONSTRUCTION_MS", buildMsText)) {
		summary["ConstructionTime(ms)"] = buildMsText;
	}
	if (TryReadTechniqueMetric(fullOutput, "CutSplit", "MEMORY_BYTES", memoryBytesText)) {
		summary["Size(bytes)"] = memoryBytesText;
	}
	summary["ClassificationTime(s)"] = to_string(stod(timeNsText) / 1000000000.0);
	if (runSampleAccuracy) {
		int repeatedPacketCount = stoi(packetCountText);
		int sampleSize = static_cast<int>(samplePackets.size());
		int repeatFactor = sampleSize > 0 ? max(1, repeatedPacketCount / sampleSize) : 1;
		summary["AccuracySampleSize"] = to_string(sampleSize);
		summary["CorrectPackets"] = to_string(stoi(correctText) / repeatFactor);
		summary["IncorrectPackets"] = to_string(stoi(incorrectText) / repeatFactor);
		summary["Accuracy(%)"] = accuracyText;
	}
	printf("\tClassification time: %s s\n", summary["ClassificationTime(s)"].c_str());
	if (runSampleAccuracy) {
		printf("\tAccuracy sample size: %s\n", summary["AccuracySampleSize"].c_str());
		printf("\tAccuracy: %s%% (%s/%s)\n", accuracyText.c_str(), summary["CorrectPackets"].c_str(), summary["AccuracySampleSize"].c_str());
	}
	data.push_back(summary);
}

void RunTabTreeBenchmark(const unordered_map<string, string>& args, const vector<Rule>& rules, const vector<Packet>& packets,
	const vector<size_t>& accuracySample, const vector<int>& sampleGroundTruthRuleIds, vector<map<string, string>>& data) {
	map<string, string> summary = MakeDefaultBenchmarkSummary("TabTree");
	printf("TabTree\n");
	if (packets.empty()) {
		printf("\tNo packets available for classification\n");
		data.push_back(summary);
		return;
	}

	string repoRoot = ResolveExistingPath(GetArgumentAlias(args, { "TabTree.Repo", "TabTree.Path" }, "External/TabTree"));
	if (RunCommand("make -C " + ShellEscape(repoRoot)) != 0) {
		printf("\tTabTree build failed\n");
		data.push_back(summary);
		return;
	}

	vector<Packet> samplePackets = SelectPacketsByIndex(packets, accuracySample);
	string rulesPath = MakeTempFilePath("tabtree_rules", ".rules");
	string fullTracePath = MakeTempFilePath("tabtree_trace", ".txt");
	string sampleTracePath = MakeTempFilePath("tabtree_trace_sample", ".txt");
	bool runSampleAccuracy = !samplePackets.empty();
	if (!WriteExternalRulesFile(rulesPath, rules)
		|| !WriteExternalTraceFile(fullTracePath, packets, nullptr)
		|| (runSampleAccuracy && !WriteExternalTraceFile(sampleTracePath, samplePackets, &sampleGroundTruthRuleIds))) {
		printf("\tFailed to write TabTree input files\n");
		remove(rulesPath.c_str());
		remove(fullTracePath.c_str());
		remove(sampleTracePath.c_str());
		data.push_back(summary);
		return;
	}

	int bucket = GetIntOrElse(args, "TabTree.Bucket", 4);
	int threshold = GetIntOrElse(args, "TabTree.Threshold", 16);
	string baseCommand = "cd " + ShellEscape(repoRoot)
		+ " && ./main -b " + to_string(bucket)
		+ " -t " + to_string(threshold)
		+ " -r " + ShellEscape(rulesPath)
		+ " -u 0 -e ";
	bool echoOutput = !IsParallelTechniqueExecutionActive(args);

	int fullExitCode = 0;
	string fullOutput = RunCommandAndCapture(baseCommand + ShellEscape(fullTracePath) + " 2>&1", fullExitCode, echoOutput);
	int sampleExitCode = 0;
	string sampleOutput;
	if (runSampleAccuracy) {
		sampleOutput = RunCommandAndCapture(baseCommand + ShellEscape(sampleTracePath) + " 2>&1", sampleExitCode, false);
	}

	remove(rulesPath.c_str());
	remove(fullTracePath.c_str());
	remove(sampleTracePath.c_str());

	if (fullExitCode != 0 || sampleExitCode != 0) {
		printf("\tTabTree benchmark failed\n");
		if (fullExitCode != 0) {
			printf("%s\n", fullOutput.c_str());
		}
		if (sampleExitCode != 0) {
			printf("%s\n", sampleOutput.c_str());
		}
		data.push_back(summary);
		return;
	}

	string timeNsText;
	string buildMsText;
	string memoryBytesText;
	string accuracyText;
	string correctText;
	string incorrectText;
	string packetCountText;
	if (!TryReadTechniqueMetric(fullOutput, "TabTree", "TIME_NS_TOTAL", timeNsText)) {
		printf("\tTabTree benchmark output was not parseable\n");
		data.push_back(summary);
		return;
	}
	if (runSampleAccuracy && (!TryReadTechniqueMetric(sampleOutput, "TabTree", "ACCURACY_PERCENT", accuracyText)
		|| !TryReadTechniqueMetric(sampleOutput, "TabTree", "CORRECT", correctText)
		|| !TryReadTechniqueMetric(sampleOutput, "TabTree", "INCORRECT", incorrectText)
		|| !TryReadTechniqueMetric(sampleOutput, "TabTree", "PACKETS", packetCountText))) {
		printf("\tTabTree sample accuracy output was not parseable\n");
		data.push_back(summary);
		return;
	}

	if (TryReadTechniqueMetric(fullOutput, "TabTree", "CONSTRUCTION_MS", buildMsText)) {
		summary["ConstructionTime(ms)"] = buildMsText;
	}
	if (TryReadTechniqueMetric(fullOutput, "TabTree", "MEMORY_BYTES", memoryBytesText)) {
		summary["Size(bytes)"] = memoryBytesText;
	}
	summary["ClassificationTime(s)"] = to_string(stod(timeNsText) / 1000000000.0);
	if (runSampleAccuracy) {
		summary["AccuracySampleSize"] = packetCountText;
		summary["CorrectPackets"] = correctText;
		summary["IncorrectPackets"] = incorrectText;
		summary["Accuracy(%)"] = accuracyText;
	}
	printf("\tClassification time: %s s\n", summary["ClassificationTime(s)"].c_str());
	if (runSampleAccuracy) {
		printf("\tAccuracy sample size: %s\n", packetCountText.c_str());
		printf("\tAccuracy: %s%% (%s/%s)\n", accuracyText.c_str(), correctText.c_str(), packetCountText.c_str());
	}
	data.push_back(summary);
}

void RunNPTreeBenchmark(const unordered_map<string, string>& args, const vector<Rule>& rules, const vector<Packet>& packets,
	const vector<size_t>& accuracySample, const vector<int>& groundTruth, vector<map<string, string>>& data) {
	map<string, string> summary = MakeDefaultBenchmarkSummary("NPTree");
	printf("NPTree\n");
	if (packets.empty()) {
		printf("\tNo packets available for classification\n");
		data.push_back(summary);
		return;
	}

	string repoRoot = ResolveExistingPath(GetArgumentAlias(args, { "NPTree.Repo", "NPTree.Path" }, "External/NPTree"));
	if (RunCommand("make -C " + ShellEscape(repoRoot)) != 0) {
		printf("\tNPTree build failed\n");
		data.push_back(summary);
		return;
	}

	string rulesPath = MakeTempFilePath("nptree_rules", ".rules");
	string tracePath = MakeTempFilePath("nptree_trace", ".txt");
	string resultsPath = MakeTempFilePath("nptree_results", ".txt");
	if (!WriteExternalRulesFile(rulesPath, rules) || !WriteNPTreeTraceFile(tracePath, packets)) {
		printf("\tFailed to write NPTree input files\n");
		remove(rulesPath.c_str());
		remove(tracePath.c_str());
		remove(resultsPath.c_str());
		data.push_back(summary);
		return;
	}

	int maxRulesPerNode = GetIntOrElse(args, "NPTree.MaxRulesPerNode", 16);
	string nptreeMode = GetArgumentAlias(args, { "NPTree.Mode" }, "Specific");
	string normalizedNptreeMode = NormalizeClassifierName(nptreeMode);
	string command = "cd " + ShellEscape(repoRoot)
		+ " && NPTREE_MODE=" + ShellEscape(nptreeMode)
		+ " NPTREE_RESULTS_FILE=" + ShellEscape(resultsPath)
		+ " ./main " + ShellEscape(rulesPath)
		+ " " + ShellEscape(tracePath)
		+ " " + to_string(maxRulesPerNode)
		+ " 0 0 2>&1";
	int exitCode = 0;
	string output = RunCommandAndCapture(command, exitCode, false);

	vector<int> results;
	string buildMsText;
	string timeNsText;
	string memoryBytesText;
	string timeMetric = normalizedNptreeMode == "broadest" ? "TIME_NS_TOTAL" : "SPECIFIC_TIME_NS_TOTAL";
	if (exitCode != 0 || !ReadResultsFile(resultsPath, results) || results.size() != packets.size()
		|| !TryReadTechniqueMetric(output, "NPTree", "CONSTRUCTION_MS", buildMsText)
		|| !TryReadTechniqueMetric(output, "NPTree", timeMetric, timeNsText)
		|| !TryReadTechniqueMetric(output, "NPTree", "MEMORY_BYTES", memoryBytesText)) {
		printf("\tNPTree benchmark output was not parseable\n");
		if (exitCode != 0) {
			printf("%s\n", output.c_str());
		}
		remove(rulesPath.c_str());
		remove(tracePath.c_str());
		remove(resultsPath.c_str());
		data.push_back(summary);
		return;
	}

	int maxPriority = static_cast<int>(rules.size()) - 1;
	for (int& result : results) {
		if (result >= 0) {
			result = maxPriority - result;
		}
	}

	summary["ConstructionTime(ms)"] = buildMsText;
	summary["ClassificationTime(s)"] = to_string(stod(timeNsText) / 1000000000.0);
	summary["Size(bytes)"] = memoryBytesText;
	printf("\tClassification time: %s s\n", summary["ClassificationTime(s)"].c_str());
	AppendAccuracySummary(results, accuracySample, groundTruth, summary);

	remove(rulesPath.c_str());
	remove(tracePath.c_str());
	remove(resultsPath.c_str());
	data.push_back(summary);
}


vector<int> RunSimulatorClassificationTrial(Simulator& s, const string& name, PacketClassifier& classifier, vector<map<string, string>>& data) {
	map<string, string> d = { { "Classifier", name } };
	printf("%s\n", name.c_str());
	auto r = s.PerformOnlyPacketClassification(classifier, d);
	data.push_back(d);
	return r;
}

map<string, string> RunNativeClassifierBenchmark(const unordered_map<string, string>& args, const vector<Packet>& packets,
	const vector<Rule>& rules, const ClassifierDefinition& definition, const vector<size_t>& accuracySample, const vector<int>& groundTruth) {
	Simulator simulator(rules, packets);
	vector<map<string, string>> localData;
	unique_ptr<PacketClassifier> classifier = definition.factory(args);
	vector<int> results = RunSimulatorClassificationTrial(simulator, definition.canonicalName, *classifier, localData);
	if (localData.empty()) {
		return MakeDefaultBenchmarkSummary(definition.canonicalName);
	}
	AppendAccuracySummary(results, accuracySample, groundTruth, localData.back());
	return localData.back();
}

pair< vector<string>, vector<map<string, string>>>  RunSimulatorOnlyClassification(const unordered_map<string, string>& args, const vector<Packet>& packets, const vector<Rule>& rules, ClassifierTests tests, const string& outfile) {
	printf("Classification Simulation\n");

	vector<string> header = { "Classifier", "ConstructionTime(ms)", "ClassificationTime(s)", "Size(bytes)", "MemoryAccess", "Tables", "TableSizes", "TableQueries", "AvgQueries", "AccuracySampleSize", "CorrectPackets", "IncorrectPackets", "Accuracy(%)" };
	vector<map<string, string>> data;
	vector<size_t> accuracySample = SelectAccuracySampleIndices(packets.size(), ResolveAccuracyPacketCount(args, packets.size()));
	vector<int> groundTruth = BuildGroundTruthResults(rules, packets, accuracySample);
	string classifierArg = GetArgumentAlias(args, { "technique", "classifier", "c" }, "PriorityTuple,PartitionSort");
	vector<int> sampleGroundTruthRuleIds;
	if (IsClassifierSelected(tests, TestCutTSS) || IsClassifierSelected(tests, TestCutSplit) || IsClassifierSelected(tests, TestTabTree)) {
			vector<Packet> samplePackets = SelectPacketsByIndex(packets, accuracySample);
			sampleGroundTruthRuleIds = BuildGroundTruthRuleIds(rules, samplePackets);
		}

	struct ClassificationTask {
		string name;
		function<map<string, string>()> run;
	};

	size_t taskCountEstimate = 0;
	if (IsClassifierSelected(tests, TestSmartSplit)) taskCountEstimate++;
	if (IsClassifierSelected(tests, TestTupleMerge)) taskCountEstimate++;
	if (IsClassifierSelected(tests, TestByteCuts)) taskCountEstimate++;
	if (IsClassifierSelected(tests, TestCutTSS)) taskCountEstimate++;
	if (IsClassifierSelected(tests, TestCutSplit)) taskCountEstimate++;
	if (IsClassifierSelected(tests, TestTabTree)) taskCountEstimate++;
	if (IsClassifierSelected(tests, TestNPTree)) taskCountEstimate++;
	for (const auto& definition : GetClassifierDefinitions()) {
		if (IsClassifierSelected(tests, definition.flag)) {
			taskCountEstimate++;
		}
	}
	size_t workerCount = ResolveTechniqueWorkerCount(args, taskCountEstimate);
	unordered_map<string, string> benchmarkArgs = args;
	benchmarkArgs["__parallel_active"] = workerCount > 1 ? "1" : "0";

	vector<ClassificationTask> tasks;
	if (IsClassifierSelected(tests, TestSmartSplit)) {
		tasks.push_back({ "SmartSplit", [&, benchmarkArgs]() {
			vector<map<string, string>> localData;
			RunSmartSplitBenchmark(benchmarkArgs, rules, packets, localData);
			return localData.empty() ? MakeDefaultBenchmarkSummary("SmartSplit") : localData.front();
		} });
	}
	if (IsClassifierSelected(tests, TestTupleMerge)) {
		tasks.push_back({ "TupleMerge", [&, benchmarkArgs]() {
			vector<map<string, string>> localData;
			RunTupleMergeBenchmark(benchmarkArgs, rules, packets, accuracySample, groundTruth, localData);
			return localData.empty() ? MakeDefaultBenchmarkSummary("TupleMerge") : localData.front();
		} });
	}
	if (IsClassifierSelected(tests, TestByteCuts)) {
		tasks.push_back({ "ByteCuts", [&, benchmarkArgs]() {
			vector<map<string, string>> localData;
			RunByteCutsBenchmark(benchmarkArgs, rules, packets, accuracySample, groundTruth, localData);
			return localData.empty() ? MakeDefaultBenchmarkSummary("ByteCuts") : localData.front();
		} });
	}
	if (IsClassifierSelected(tests, TestCutTSS)) {
		tasks.push_back({ "CutTSS", [&, benchmarkArgs]() {
			vector<map<string, string>> localData;
			RunCutTSSBenchmark(benchmarkArgs, rules, packets, accuracySample, sampleGroundTruthRuleIds, localData);
			return localData.empty() ? MakeDefaultBenchmarkSummary("CutTSS") : localData.front();
		} });
	}
	if (IsClassifierSelected(tests, TestCutSplit)) {
		tasks.push_back({ "CutSplit", [&, benchmarkArgs]() {
			vector<map<string, string>> localData;
			RunCutSplitBenchmark(benchmarkArgs, rules, packets, accuracySample, sampleGroundTruthRuleIds, localData);
			return localData.empty() ? MakeDefaultBenchmarkSummary("CutSplit") : localData.front();
		} });
	}
	if (IsClassifierSelected(tests, TestTabTree)) {
		tasks.push_back({ "TabTree", [&, benchmarkArgs]() {
			vector<map<string, string>> localData;
			RunTabTreeBenchmark(benchmarkArgs, rules, packets, accuracySample, sampleGroundTruthRuleIds, localData);
			return localData.empty() ? MakeDefaultBenchmarkSummary("TabTree") : localData.front();
		} });
	}
	if (IsClassifierSelected(tests, TestNPTree)) {
		tasks.push_back({ "NPTree", [&, benchmarkArgs]() {
			vector<map<string, string>> localData;
			RunNPTreeBenchmark(benchmarkArgs, rules, packets, accuracySample, groundTruth, localData);
			return localData.empty() ? MakeDefaultBenchmarkSummary("NPTree") : localData.front();
		} });
	}

	for (const auto& definition : GetClassifierDefinitions()) {
		if (!IsClassifierSelected(tests, definition.flag)) {
			continue;
		}
		tasks.push_back({ definition.canonicalName, [&, benchmarkArgs, definition]() {
			return RunNativeClassifierBenchmark(benchmarkArgs, packets, rules, definition, accuracySample, groundTruth);
		} });
	}

	vector<string> requestedNames;
	Split(classifierArg, ',', requestedNames);
	vector<ClassificationTask> orderedTasks;
	vector<bool> usedTask(tasks.size(), false);
	for (const string& requestedName : requestedNames) {
		string normalizedRequested = NormalizeClassifierName(requestedName);
		if (normalizedRequested.empty() || normalizedRequested == "all") {
			continue;
		}
		for (size_t taskIndex = 0; taskIndex < tasks.size(); taskIndex++) {
			if (usedTask[taskIndex]) {
				continue;
			}
			if (MatchesRequestedClassifierName(requestedName, tasks[taskIndex].name)) {
				orderedTasks.push_back(tasks[taskIndex]);
				usedTask[taskIndex] = true;
				break;
			}
		}
	}
	for (size_t taskIndex = 0; taskIndex < tasks.size(); taskIndex++) {
		if (!usedTask[taskIndex]) {
			orderedTasks.push_back(tasks[taskIndex]);
		}
	}
	tasks = std::move(orderedTasks);

	if (workerCount > 1) {
		printf("Running %zu selected techniques with %zu worker threads\n", tasks.size(), workerCount);
		vector<map<string, string>> orderedData(tasks.size());
		atomic<size_t> nextTask(0);
		vector<thread> workers;
		workers.reserve(workerCount);
		for (size_t worker = 0; worker < workerCount; worker++) {
			workers.emplace_back([&]() {
				while (true) {
					size_t taskIndex = nextTask.fetch_add(1);
					if (taskIndex >= tasks.size()) {
						break;
					}
					try {
						orderedData[taskIndex] = tasks[taskIndex].run();
					}
					catch (const exception& ex) {
						printf("%s\n", tasks[taskIndex].name.c_str());
						printf("\tBenchmark failed with exception: %s\n", ex.what());
						orderedData[taskIndex] = MakeDefaultBenchmarkSummary(tasks[taskIndex].name);
					}
				}
			});
		}
		for (thread& worker : workers) {
			worker.join();
		}
		data = std::move(orderedData);
	}
	else {
		for (const auto& task : tasks) {
			try {
				data.push_back(task.run());
			}
			catch (const exception& ex) {
				printf("%s\n", task.name.c_str());
				printf("\tBenchmark failed with exception: %s\n", ex.what());
				data.push_back(MakeDefaultBenchmarkSummary(task.name));
			}
		}
	}
	if (outfile != "") {
		OutputWriter::WriteCsvFile(outfile, header, data);
	}
	return make_pair(header, data);
}

void RunSimulatorUpdateTrial(const Simulator& s, const string& name, PacketClassifier& classifier, const vector<Request>& req,vector<map<string, string>>& data, int reps) {


	map<string, string> d = { { "Classifier", name } };
	map<string, double> trial;

	printf("%s\n", name.c_str());

	for (int r = 0; r < reps; r++) { 
		s.PerformPacketClassification(classifier, req, trial);
	}
	for (auto pair : trial) {
		d[pair.first] = to_string(pair.second / reps);
	}
	data.push_back(d);
}

pair< vector<string>, vector<map<string, string>>>  RunSimulatorUpdates(const unordered_map<string, string>& args, const vector<Packet>& packets, const vector<Rule>& rules, ClassifierTests tests, const string& outfile, int repetitions) {
	printf("Update Simulation\n");

	vector<string> header = { "Classifier", "UpdateTime(s)" };
	vector<map<string, string>> data;

	Simulator s(rules, packets);
	const auto req = s.SetupComputation(0, 500000, 500000);

	for (const auto& definition : GetClassifierDefinitions()) {
		if (!IsClassifierSelected(tests, definition.flag)) {
			continue;
		}
		if (!definition.supportsUpdates) {
			printf("Skipping %s: update simulation is not implemented for this classifier\n", definition.canonicalName);
			continue;
		}
		unique_ptr<PacketClassifier> classifier = definition.factory(args);
		RunSimulatorUpdateTrial(s, definition.canonicalName, *classifier, req, data, repetitions);
	}
	if (IsClassifierSelected(tests, TestSmartSplit)) {
		printf("Skipping SmartSplit: update simulation is not implemented for this classifier\n");
	}
		if (IsClassifierSelected(tests, TestTupleMerge) || IsClassifierSelected(tests, TestByteCuts) || IsClassifierSelected(tests, TestCutTSS)
			|| IsClassifierSelected(tests, TestCutSplit) || IsClassifierSelected(tests, TestTabTree)
			|| IsClassifierSelected(tests, TestNPTree)) {
			printf("Skipping external repository techniques: update simulation is not implemented in the unified driver for these classifiers\n");
		}
	if (outfile != "") {
		OutputWriter::WriteCsvFile(outfile, header, data);
	}
	return make_pair(header, data);
}

bool Validation(const unordered_map<string, PacketClassifier*> classifiers, const vector<Rule>& rules, const vector<Packet>& packets, int threshold) {
	int numWrong = 0;
	vector<Rule> sorted = rules;
	sort(sorted.begin(), sorted.end(), [](const Rule& rx, const Rule& ry) { return rx.priority >= ry.priority; });
	for (const Packet& p : packets) {
		unordered_map<string, int> results;
		int result = -1;
		for (const auto& pair : classifiers) {
			result = pair.second->ClassifyAPacket(p);
			results[pair.first] = result;
		}
		if (!all_of(results.begin(), results.end(), [=](const auto& pair) { return pair.second == result; })) {
			numWrong++;
			for (auto x : p) {
				printf("%u ", x);
			}
			printf("\n");
			for (const auto& pair : results) {
				printf("\t%s: %d\n", pair.first.c_str(), pair.second);
			}
			for (const Rule& r : sorted) {
				if (r.MatchesPacket(p)) {
					printf("\tTruth: %d\n", r.priority);
					break;
				}
			}
		}
		if (numWrong >= threshold) {
			break;
		}
	}
	return numWrong == 0;
}

void RunValidation(const unordered_map<string, string>& args, const vector<Packet>& packets, const vector<Rule>& rules, ClassifierTests tests) {
	printf("Validation Simulation\n");
	unordered_map<string, PacketClassifier*> classifiers;

	for (const auto& definition : GetClassifierDefinitions()) {
		if (!IsClassifierSelected(tests, definition.flag)) {
			continue;
		}
		classifiers[definition.canonicalName] = definition.factory(args).release();
	}
	if (IsClassifierSelected(tests, TestSmartSplit)) {
		printf("Skipping SmartSplit: validation mode is not implemented for this classifier\n");
	}
		if (IsClassifierSelected(tests, TestTupleMerge) || IsClassifierSelected(tests, TestByteCuts) || IsClassifierSelected(tests, TestCutTSS)
			|| IsClassifierSelected(tests, TestCutSplit) || IsClassifierSelected(tests, TestTabTree)
			|| IsClassifierSelected(tests, TestNPTree)) {
			printf("Skipping external repository techniques: validation mode is not implemented in the unified driver for these classifiers\n");
		}

	printf("Building\n");
	for (auto& pair : classifiers) {
		printf("\t%s\n", pair.first.c_str());
		pair.second->ConstructClassifier(rules);
	}

	printf("Testing\n");
	int threshold = GetIntOrElse(args, "Validate.Threshold", 10);
	if (Validation(classifiers, rules, packets, threshold)) {
		printf("All classifiers are in accord\n");
	}

	for (auto& pair : classifiers) {
		delete pair.second;
	}
}


ClassifierTests ParseClassifier(const string& line) {
	vector<string> tokens;
	Split(line, ',', tokens);
	ClassifierTests tests = ClassifierTests::TestNone;

	for (const string& classifier : tokens) {
		string normalized = NormalizeClassifierName(classifier);
	        if (normalized == "partitionsort") {
			tests = tests | TestPartitionSort;
		}
		else if (normalized == "prioritytuple" || normalized == "prioritytuplesearch" || normalized == "ptss") {
			tests = tests | TestPriorityTuple;
		}
		else if (normalized == "hypersplit") {
			tests = tests | TestHyperSplit;
		}
		else if (normalized == "hypercuts") {
			tests = tests | TestHyperCuts;
		}
		else if (normalized == "smartsplit") {
			tests = tests | TestSmartSplit;
		}
		else if (normalized == "tuplemerge" || normalized == "tuplemergeoffline") {
			tests = tests | TestTupleMerge;
		}
		else if (normalized == "bytecuts") {
			tests = tests | TestByteCuts;
		}
		else if (normalized == "cuttss") {
			tests = tests | TestCutTSS;
		}
		else if (normalized == "cutsplit") {
			tests = tests | TestCutSplit;
		}
		else if (normalized == "tabtree") {
			tests = tests | TestTabTree;
		}
		else if (normalized == "nptree") {
			tests = tests | TestNPTree;
		}
		else if (normalized == "all") {
			tests = tests | TestAll;
		}
		else {
			printf("Unknown classifier: %s\n", classifier.c_str());
			printf("Supported classifiers: PartitionSort, PriorityTuple/PTSS, HyperCuts, HyperSplit, SmartSplit, TupleMerge, ByteCuts, CutTSS, CutSplit, TabTree, NPTree, All\n");
			exit(EINVAL);
		}
	}
	return tests;
}

TestMode ParseMode(const string& mode) {
	printf("%s\n", mode.c_str());
	if (mode == "Classification") {
		return ModeClassification;
	}
	else if (mode == "Update") {
		return ModeUpdate;
	}
	else if (mode == "Validation") {
		return ModeValidation;
	}
	else {
		printf("Unknown mode: %s\n", mode.c_str());
		exit(EINVAL);
	}
}
