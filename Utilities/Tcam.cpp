#include "Tcam.h"

#include <algorithm>

using namespace std;

namespace tcam {
	unsigned int PrefixSizeHelper(unsigned int low, unsigned int high, unsigned int boundLow, unsigned int boundHigh) {
		if (boundHigh < low || boundLow > high) return 0;
		if (low <= boundLow && high >= boundHigh) return 1;

		unsigned int boundMid = (boundLow / 2) + (boundHigh / 2); // Guard against overflow
		return PrefixSizeHelper(low, high, boundLow, boundMid) + PrefixSizeHelper(low, high, boundMid + 1, boundHigh);
	}

	unsigned int SizeAsPrefixes(const array<unsigned int, 2>& range) {
		unsigned int low = range[LowDim];
		unsigned int high = range[HighDim];
		return PrefixSizeHelper(low, high, 0, 0xFFFFFFFF);
	}

	unsigned int NumOfPrefixRules(const Rule& r) {
		unsigned int area = 1;
		for (const auto& range : r.range) {
			area *= SizeAsPrefixes(range);
		}
		return area;
	}
	unsigned int SizeAsPrefixRules(const vector<Rule>& rules) {
		unsigned int sum = 0;
		for (const Rule& r : rules) {
			sum += NumOfPrefixRules(r);
		}
		return sum;
	}
}

void TCAMClassifier::ConstructClassifier(const vector<Rule>& rules) {
	this->rules = rules;
	SortRules(this->rules);
	RecomputePrefixRuleCount();
}

int TCAMClassifier::ClassifyAPacket(const Packet& packet) {
	QueryUpdate(1);
	for (const Rule& rule : rules) {
		if (rule.MatchesPacket(packet)) {
			return rule.priority;
		}
	}
	return -1;
}

void TCAMClassifier::DeleteRule(size_t index) {
	if (index >= rules.size()) {
		return;
	}
	rules.erase(rules.begin() + index);
	RecomputePrefixRuleCount();
}

void TCAMClassifier::InsertRule(const Rule& rule) {
	rules.push_back(rule);
	SortRules(rules);
	RecomputePrefixRuleCount();
}

Memory TCAMClassifier::MemSizeBytes() const {
	return static_cast<Memory>(prefixRuleCount * ruleSizeBytes);
}

void TCAMClassifier::RecomputePrefixRuleCount() {
	prefixRuleCount = static_cast<size_t>(tcam::SizeAsPrefixRules(rules));
}
