#pragma once

#include "../Simulation.h"

#include <vector>

namespace tcam {
	unsigned int SizeAsPrefixes(const std::array<unsigned int, 2>& range);
	unsigned int NumOfPrefixRules(const Rule& r);
	unsigned int SizeAsPrefixRules(const std::vector<Rule>& rules);
}

class TCAMClassifier : public PacketClassifier {
public:
	void ConstructClassifier(const std::vector<Rule>& rules) override;
	int ClassifyAPacket(const Packet& packet) override;
	void DeleteRule(size_t index) override;
	void InsertRule(const Rule& rule) override;
	Memory MemSizeBytes() const override;
	int MemoryAccess() const override { return 1; }
	size_t NumTables() const override { return 1; }
	size_t RulesInTable(size_t tableIndex) const override { return tableIndex == 0 ? prefixRuleCount : 0; }

private:
	void RecomputePrefixRuleCount();

	std::vector<Rule> rules;
	size_t prefixRuleCount = 0;
	Memory ruleSizeBytes = 19;
};
