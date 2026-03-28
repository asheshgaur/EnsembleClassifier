#include <iostream>
using namespace std;
#include <vector>
#include <queue>
#include <stack>
#include <set>
#include <cstdlib>
#include <algorithm>
#include <string>
#include <fstream>
#include <sstream>
#include <iterator>
#include <functional>
#include <regex>
#include <ctime>
#include <cctype>
#include <random>
#include <chrono>
#include <memory>
#include "classbench_reader.h"
#include "rules_and_packets.h"
#include "trace_tools.h"

// default constructor
rule::rule(int dimensions, int ruleCounter)
{
	this->ruleNumber = ruleCounter;
    this->numDimensions = dimensions;
	fields.resize(5);
	for (int i = 0; i < 5; i++) {
		fields[i].first = 0;
		fields[i].second = 0;
	}
	prefix_length.resize(2);
}

// non-default constructor
rule::rule(vector<pair<unsigned int, unsigned int>>field, int num, int dimensions)
{
	this->ruleNumber = num;
	this->fields = field;
	this->numDimensions = dimensions;
}
rule::~rule() {
 //Don't need it cause no dynamic allocation.
}

//To check if a certain rule satisfies a packet or not.
bool rule::satisfiesPacket(const Packet& p) {
	for (int i = 0; i < MAX_DIMENSIONS; i++) {
		if ((fields[i].first <= p[i]) && (fields[i].second >= p[i]))
			continue;
		else return false;
	}
	return true;
}

bool rule::satisfiesPacketDim(const Packet& p, int dim) {
	if ((fields[dim].first <= p[dim]) && (fields[dim].second >= p[dim]))
		return true;
	else return false;
	
}

// display method for rule
void rule::printRule()
{
	std::cout << "Rule " << ruleNumber << ": " << endl;
	for(int i = 0; i < numDimensions; i++)
		std::cout << "Field" << i+1 << ": " << fields[i].first << " " << fields[i].second << endl;
}

int rule::getLR(int dimension){
	return fields[dimension - 1].first;
}

int rule::getRR(int dimension){
	return fields[dimension - 1].second;
}

int rule::getDimensionality(){
	return this->numDimensions;
}
unsigned int rule::getPrefixLength(int dim){
    return this->prefix_length[dim];
}

unsigned int rule::getDimRangeMin(int dimension){
    return fields[dimension].first;
}
unsigned int rule::getDimRangeMax(int dimension){
    return fields[dimension].second;
}
int rule::getRuleNumber(){
	return this->ruleNumber;
}
void rule::setDimRangeMin(int dimension, unsigned int value){
		this->fields[dimension].first = value;

}
void rule::setDimRangeMax(int dimension, unsigned int value){
		this->fields[dimension].second = value;

}

void rule::setPrefixLength(int dim, unsigned int value){
	this->prefix_length[dim] = value;
}

int maxDimensions = 5;
unsigned int maxRulesPerNode = 8;

//Global declarations
vector<rule*> rules; // vector for storing the rules from the classbench files.
vector<Packet> packets; // vector for storing randomly generated packets.
vector<pair<Packet*, set<int>>> classificationResult; // vector for storing the result of classification.

vector<unsigned int>* getEndPoints (vector<int>* ruleIDs, int d){

	vector<unsigned int>* eP = new vector<unsigned int> ();
	int numRules = (*ruleIDs).size();
	for (int i = 0; i < numRules; i++) {
		// if ((*ruleIDs)[i] == 58576) {
		// 	std::cout << "\nInvalid index 58576!!\n";
		// 	exit(0);
		// }
		// if (d < rules[(*ruleIDs)[i]]->fields.size()) {
			// Safe to access myVector[index]
			//std::cout << (*ruleIDs)[i] << " ";
			(*eP).push_back(rules[(*ruleIDs)[i]]->getDimRangeMin(d));
        	(*eP).push_back(rules[(*ruleIDs)[i]]->getDimRangeMax(d));
		// } else {
		// 	// Index out of bounds
		// 	std::cout << "Index out of bounds for fields vector of rule "
		// 	<< rules[(*ruleIDs)[i]] <<std::endl;
		// 	exit(0);
		// }
        // (*eP).push_back(rules[(*ruleIDs)[i]]->getDimRangeMin(d));
        // (*eP).push_back(rules[(*ruleIDs)[i]]->getDimRangeMax(d));
	}
	//std::cout << "\n" << d << "\n&&&&&&&&&&&&&&&&&&&\n";

	return eP;
}

/* we may not need this program */
int countEndPoints (vector<unsigned int>* eP) {
	int count = 0;
	int numEP = (*eP).size();
	if (numEP == 0) return count;
	count = 1;
	for (int i = 1; i < numEP; i++) {
		if ((*eP)[i-1] != (*eP)[i]) count++;
	}
	return count;
}

class RangeTree {
public:
	uint32_t low;
	uint32_t lowModifier;
	uint32_t high;
	uint32_t highModifier;
	int dimension;
	bool leftRangeModified = false;
	bool rightRangeModified = false;
	RangeTree* left;
	RangeTree* right;
	RangeTree* nextDimension;
	vector<int>* ruleIDs;
	vector<int>* partialRuleIDs;
	RangeTree ();
	~RangeTree();
	RangeTree (unsigned int l, unsigned int h, int dim, RangeTree* lChild, RangeTree* rChild);
	bool insertARule (int ruleNum, int dim);
	bool satisfiesPacket(unsigned int point);
	bool satisfiesRule( int ruleNum, int dim);
	bool partialSatisfiesRule(int ruleNum, int dim);
	bool hasRules();
	int linearSearchRule(Packet& packet);
	bool isleaf();
	int getDimension();
	void preOrder();
};

size_t EstimateRuleVectorBytes(const vector<int>* rulesInNode) {
	if (rulesInNode == nullptr) {
		return 0;
	}
	return sizeof(*rulesInNode) + rulesInNode->capacity() * sizeof(int);
}

size_t EstimateRangeTreeBytes(const RangeTree* node) {
	if (node == nullptr) {
		return 0;
	}

	size_t total = sizeof(*node);
	total += EstimateRuleVectorBytes(node->ruleIDs);
	total += EstimateRuleVectorBytes(node->partialRuleIDs);
	total += EstimateRangeTreeBytes(node->left);
	total += EstimateRangeTreeBytes(node->right);
	total += EstimateRangeTreeBytes(node->nextDimension);
	return total;
}

int RangeTree::linearSearchRule(Packet& p) {
	if (this->dimension == MAX_DIMENSIONS - 1) {
		if (this->hasRules()) {
			return (*ruleIDs)[0];
		} 
		else return -1;
	}
	else {
		if (this->hasRules()){
			for (auto ruleID : *ruleIDs) {
				bool foundRule = true;
				for (int i = this->dimension + 1; i < MAX_DIMENSIONS; i++) {
					if (!(rules[ruleID]->satisfiesPacketDim(p, fieldOrder[i]))) {
						foundRule = false;
						break;
					}
				}
				if (foundRule) {
					return ruleID;
				}
			}
		}
	}
	return -1;
}
RangeTree::RangeTree () {
	low = 0;
	high = 0;
	dimension = 0;
	left = NULL;
	right = NULL;
	nextDimension = NULL;
	ruleIDs = NULL;
	partialRuleIDs = NULL;
	
}

RangeTree::RangeTree (unsigned int l, unsigned int h, int dim, RangeTree* lChild, RangeTree* rChild) {
	low = l;
	high = h;
	dimension = dim;
	left = lChild;
	right = rChild;
	ruleIDs = NULL;
	nextDimension = NULL;
	partialRuleIDs = NULL;
}

RangeTree::~RangeTree() {
	if (this->ruleIDs != nullptr){
		delete this->ruleIDs;
	}
	if (this->partialRuleIDs != nullptr) {
		delete this->partialRuleIDs;
	}
	ruleIDs = nullptr;
	partialRuleIDs = nullptr;
	delete this->left;
	//this->left = nullptr;
	delete this->right;
	//this->right = nullptr;
	delete this->nextDimension;
	//this->nextDimension = nullptr;
}
bool RangeTree::hasRules() {
	if ((this->ruleIDs != NULL) && this->ruleIDs->size() > 0)
	{
		return true;
	}
	else return false;
}
bool RangeTree::isleaf() {
	if ((this->left == NULL) && (this->right == NULL)) {
		return true;
	}
	else return false;
}

int RangeTree::getDimension(){
	return dimension;
}

bool RangeTree:: insertARule (int ruleNum, int dim) {

	bool inserted = false;
    if (satisfiesRule(ruleNum, dim)) {
		if (ruleIDs == NULL) {
			ruleIDs = new vector<int>();
		}
		(*ruleIDs).push_back(ruleNum);
		inserted = true;
	}
	return inserted;
}


bool RangeTree::satisfiesPacket(unsigned int point) {
	if ((low <= point) && (high >= point))
		return true;
	else return false;
}

bool RangeTree::satisfiesRule(int ruleNum, int dim) {
	if ((rules[ruleNum]->getDimRangeMin(dim) <= low) && (rules[ruleNum]->getDimRangeMax(dim) >= high))
		return true;
	else return false;
}

bool RangeTree::partialSatisfiesRule(int ruleNum, int dim) {
	//Partial overlap with rules
	if (((low >= rules[ruleNum]->getDimRangeMin(dim)) && (low < rules[ruleNum]->getDimRangeMax(dim)))
		|| ((high > rules[ruleNum]->getDimRangeMin(dim)) && (high <= rules[ruleNum]->getDimRangeMax(dim)))) {
		return true;
	}
	//Total encompassing overlap with rules
	else if ((rules[ruleNum]->getDimRangeMin(dim) >= low) && (rules[ruleNum]->getDimRangeMax(dim) <= high)) {
		return true;
	}
	else return false;
}


void RangeTree::preOrder () {
	stack<RangeTree*> s;
	RangeTree* t;
	s.push(this);
	while (!s.empty()) {
		t = s.top();
		s.pop();
		if ((*t).ruleIDs != NULL) {
			//cout << "(" << (*t).low << ": " << (*t).high << "); Size = " << (*(*t).ruleIDs).size() << "==";
			int numRules = (*(*t).ruleIDs).size();
			for (int k=0; k < numRules; k++)
				//cout << " " << (*(*t).ruleIDs)[k];
			//cout << endl;
			if ((*t).nextDimension != NULL) {
				//cout << "******************************** (1)" << endl;
				(*(*t).nextDimension).preOrder();
				//cout << "******************************** (2)" << endl;
			}
		}
		else
			//cout << "(" << (*t).low << ": " << (*t).high << "); Size = 0" << endl;
		if ((*t).right != NULL) s.push((*t).right);
		if ((*t).left != NULL) s.push((*t).left);
	}
}

void insertRules (RangeTree* node, vector<int>* ruleIDs, int dim) {
    // cout << endl << "Inside insert rules with node ("<<node->low
    //     << " : " << node->high << ") and dim: " << dim << endl;
	stack<RangeTree*> s;
	RangeTree* t;
	bool inserted;
	int numRules = (*ruleIDs).size();
	for (int i=0; i < numRules; i++) {
        // cout << "Inside for loop for iteration: " << i << endl;
		s.push(node);
		while (!s.empty()) {
			t = s.top();
			s.pop();
			//cout << "(" << (*t).low << ": " << (*t).high << ")" << endl;
			
			inserted = 	(*t).insertARule ((*ruleIDs)[i], dim);
			if (!inserted) {
				if (((*t).right != NULL) && ((*t).right->partialSatisfiesRule((*ruleIDs)[i], dim))) {
					s.push((*t).right);
				}
				if (((*t).left != NULL) && ((*t).left->partialSatisfiesRule((*ruleIDs)[i], dim))) {
					s.push((*t).left);
				}
			}
			// if (!inserted) {
			// 	if ((*t).right != NULL) s.push((*t).right);
			// 	if ((*t).left != NULL) s.push((*t).left);
			// }
		}
	}
}
//This function only goes one way when a rule is not inserted into a node.
void insertRulesOnce (RangeTree* node, vector<int>* ruleIDs, int dim) {
    // cout << endl << "Inside insert rules with node ("<<node->low
    //     << " : " << node->high << ") and dim: " << dim << endl;
	stack<RangeTree*> s;
	RangeTree* t;
	bool inserted;

	int numRules = (*ruleIDs).size();
	for (int i=0; i < numRules; i++) {
        // cout << "Inside for loop for iteration: " << i << endl;
		s.push(node);
		while (!s.empty()) {
			t = s.top();
			s.pop();
			//cout << "(" << (*t).low << ": " << (*t).high << ")" << endl;
			inserted = 	(*t).insertARule ((*ruleIDs)[i], dim);
			if (!inserted) {
				if ((*t).right != NULL){
					if ((*t).right->satisfiesRule((*ruleIDs)[i], dim))
						s.push((*t).right);
				} 
				else if ((*t).left != NULL){
					if ((*t).left->satisfiesRule((*ruleIDs)[i], dim))
						s.push((*t).left);
				} 
			}
		}
	}
}

unsigned int inline atoui(const string& in) {
	std::istringstream reader(in);
	unsigned int val;
	reader >> val;
	return val;
}

RangeTree* buildTree (vector<int>* ruleIDs, int dim, const vector<int>& fieldOrder) {
	//std::cout << "\nruleIDs size: " << ruleIDs->size() << std::endl;
	vector<unsigned int>* endPoints;
	RangeTree* aNode;
	RangeTree* root = NULL;
	stack<RangeTree*> s;
	RangeTree* t;
	queue<RangeTree*> myQ;
	unsigned int k;
    // cout << endl << "Inside buildTree for dimension: " << dim
    //     << endl << "And the number of rules: " << ruleIDs->size() << endl;
	unsigned int numRules = (*ruleIDs).size();
	if (numRules > maxRulesPerNode) { //A full tree will be created.
	
		endPoints = getEndPoints (ruleIDs,fieldOrder[dim]);
		//std::cout << "\n EndPoints done!\n";
		sort((*endPoints).begin(), (*endPoints).end());
		//int numEndPoints = countEndPoints (endPoints);
		//cout << "Number of end points = " << numEndPoints << endl;

		k = (*endPoints)[0];
		int numEP = (*endPoints).size();
		for (int i=1; i < numEP; i++) {
			if ((*endPoints)[i] != k) {
				aNode = new RangeTree(k, (*endPoints)[i], fieldOrder[dim], NULL, NULL);
				k = (*endPoints)[i];
				myQ.push(aNode);
				//cout << dim << ": >>>>> " << (*aNode).low << ": " << (*aNode).high << endl;
			}
		}
		delete endPoints;
		
		while (myQ.size() > 1) {
			RangeTree* l = myQ.front();
			myQ.pop();
			RangeTree* r = myQ.front();
			if ((*l).high == (*r).low) {
				myQ.pop();
				RangeTree* n = new RangeTree ((*l).low, (*r).high, fieldOrder[dim], l, r);
				//cout << dim << ": ++++++++" << (*n).low << ": " << (*n).high << endl;
				myQ.push(n);
			}
			else myQ.push(l);
		}

		root = myQ.front(); //root of the dimension one range tree

		//Insert the rules in the first dimension range tree - root

		//insertRulesOnce(root, ruleIDs, fieldOrder[dim]);
		insertRules(root, ruleIDs, fieldOrder[dim]);
		//Process the next Dimension, if dim < maxDimensions
		if ((dim+1) < MAX_DIMENSIONS) { //dim 0 is already procesed
			s.push(root);
			while (!s.empty()) {
				t = s.top();
				s.pop();
				if ((*t).right != NULL) s.push((*t).right);
				if ((*t).left != NULL) s.push((*t).left);
				if (((*t).ruleIDs != NULL) && ((*(*t).ruleIDs).size() >= maxRulesPerNode)) {
					//cout << "@@@@: (" << (*t).low << ": " << (*t).high << ")" << endl;
					RangeTree* another = buildTree ((*t).ruleIDs, dim+1, fieldOrder);
					(*t).nextDimension = another;
					// if (((*t).low == 15) && ((*t).high == 20)) {
					// 	//cout << "$$$$$$$$$$$$$$$$$$$$$$$$" << endl;
					// 	(*another).preOrder();
					// }
				}
			}
		}

		//(*root).preOrder();
	}
	else {
		endPoints = getEndPoints (ruleIDs,fieldOrder[dim]);
		//sort((*endPoints).begin(), (*endPoints).end());
		int numEP = (*endPoints).size();
		uint32_t minEP = 4294967295;
		uint32_t maxEP = 0;
		//Finding min endpoint
		for (int i = 0; i < numEP; i++) {
			if (minEP > (*endPoints)[i]){
				minEP = (*endPoints)[i];
			}
			if (maxEP < (*endPoints)[i]) {
				maxEP = (*endPoints)[i];
			}
		}

		root = new RangeTree (minEP, maxEP, fieldOrder[dim], NULL,NULL);
		root->ruleIDs = new vector<int>();
		for (unsigned int i = 0; i < ruleIDs->size(); i++) {
			root->ruleIDs->push_back((*(ruleIDs))[i]);
		}
	}

	return root;
}
void deleteRule (RangeTree* root, int ruleID) {
	//Check if the root has the rule or not.
	if ((root->dimension == fieldOrder[0]) && (root->partialRuleIDs != NULL)) { //Check if the root has partial rules
		std::cout << "\n**********************\n";
		//Delete Rule from partialRuleIDs (if found)
		auto it = std::find(root->partialRuleIDs->begin(), root->partialRuleIDs->end(), ruleID);
		if (it != root->partialRuleIDs->end()) {
			//root->partialRuleIDs->erase(it);
			// Swap the found value with the last element
			std::swap(*it, root->partialRuleIDs->back());
			// Remove the last element
			root->partialRuleIDs->pop_back();
			return; 
		}
	}

	//Check if the root has rule legitimately
	if (root->satisfiesRule(ruleID, root->dimension)) {
		if (root->ruleIDs != nullptr) { //Check if the root has partial rules
			//Delete Rule from ruleIDs (if found)
			auto it = std::find(root->ruleIDs->begin(), root->ruleIDs->end(), ruleID);
			if (it != root->ruleIDs->end()) {
				//root->ruleIDs->erase(it);
				// Swap the found value with the last element
				std::swap(*it, root->ruleIDs->back());
				// Remove the last element
				root->ruleIDs->pop_back();
				if (root->nextDimension != NULL) {
					deleteRule(root->nextDimension, ruleID);
				}
				return;
			}
		}
	}
	else {
		
		if (((*root).right != NULL) && ((*root).right->partialSatisfiesRule(ruleID, root->dimension))) {
			deleteRule((*root).right, ruleID);
		}
		if (((*root).left != NULL) && ((*root).left->partialSatisfiesRule(ruleID, root->dimension))) {
			deleteRule((*root).left, ruleID);
		}
		
	}
}
void deleteRuleIterative (RangeTree* root, int ruleID) {
	std::stack<RangeTree*> s;
	RangeTree* t;
	s.push(root);

	while (!s.empty()) {
		t = s.top();
		s.pop();
		if (t->satisfiesRule(ruleID, t->dimension)) {
			if (t->ruleIDs != nullptr) { //Check if the root has partial rules
				//Delete Rule from ruleIDs (if found)
				auto it = std::find(t->ruleIDs->begin(), t->ruleIDs->end(), ruleID);
				if (it != t->ruleIDs->end()) {
					t->ruleIDs->erase(it);
					// // Swap the found value with the last element
					// std::swap(*it, t->ruleIDs->back());
					// // Remove the last element
					// t->ruleIDs->pop_back();
					if (t->nextDimension != NULL) {
						s.push(t->nextDimension);
					}
				}
			}
		}
		else {
			if (((*t).right != NULL) && ((*t).right->partialSatisfiesRule(ruleID, t->dimension))) {
				s.push((*t).right);
			}
			if (((*t).left != NULL) && ((*t).left->partialSatisfiesRule(ruleID, t->dimension))) {
				s.push((*t).left);
			}
		}
		
	}
	
}
uint32_t getLeftOverlapSize(RangeTree* root, int ruleIndex, int dim) {
	uint32_t leftOverlapSize;
	leftOverlapSize = rules[ruleIndex]->getDimRangeMax(root->dimension) - root->low;
	return leftOverlapSize;
}
uint32_t getRightOverlapSize(RangeTree* root, int ruleIndex, int dim) {
	uint32_t rightOverlapSize;
	rightOverlapSize = root->high - rules[ruleIndex]->getDimRangeMin(root->dimension);
	return rightOverlapSize;
}
void partialInsertOneRule(RangeTree* root, int ruleIndex, int dim) {
	
	//Partially insert each rule at closest to the leaf?
	stack<RangeTree*> s;
	RangeTree* t;
	bool inserted;

	//Checking if the overlap is total, partial or none with the root.
	//Checking for partial overlap such that only left range is extended.
	if (((rules[ruleIndex]->getDimRangeMin(root->dimension) < root->low) && 
		((rules[ruleIndex]->getDimRangeMax(root->dimension) >= root->low) && (rules[ruleIndex]->getDimRangeMax(root->dimension) <= root->high)))) {

		root->lowModifier = rules[ruleIndex]->getDimRangeMin(root->dimension);
		root->leftRangeModified = true;
		//GOTO the last node on the left with overlapping range, and store it there.
		uint32_t overlapSize = getLeftOverlapSize(root, ruleIndex, dim);
		while ((overlapSize < getLeftOverlapSize(root->left, ruleIndex, dim)) && (root->left != NULL)) {
			root = root->left;
			root->lowModifier = rules[ruleIndex]->getDimRangeMin(root->dimension);
		}
		if (root->partialRuleIDs == NULL) {
			root->partialRuleIDs = new vector<int>();
		}
		root->partialRuleIDs->push_back(ruleIndex);
			
	}

	//Checking for partial overlap such that only right range is extended.
	else if (((rules[ruleIndex]->getDimRangeMax(root->dimension) > root->high) && 
		((rules[ruleIndex]->getDimRangeMin(root->dimension) >= root->low) && (rules[ruleIndex]->getDimRangeMin(root->dimension) <= root->high)))) {
		root->highModifier = rules[ruleIndex]->getDimRangeMax(root->dimension);
		root->rightRangeModified = true;
		//GOTO the last node on the left with overlapping range, and store it there.
		uint32_t overlapSize = getRightOverlapSize(root, ruleIndex, dim);
		while ((overlapSize < getRightOverlapSize(root->right, ruleIndex, dim)) && (root->right != NULL)) {
			root = root->right;
			root->highModifier = rules[ruleIndex]->getDimRangeMax(root->dimension);
		}
		if (root->partialRuleIDs == NULL) {
			root->partialRuleIDs = new vector<int>();
		}
		root->partialRuleIDs->push_back(ruleIndex);
	}

	//Checking for rules which extend range on both sides.
	else if (rules[ruleIndex]->getDimRangeMin(root->dimension) < root-> low && rules[ruleIndex]->getDimRangeMax(root->dimension) > root->high) {
		root->highModifier = rules[ruleIndex]->getDimRangeMax(root->dimension);
		root->lowModifier = rules[ruleIndex]->getDimRangeMin(root->dimension);
		root->leftRangeModified = true;
		root->rightRangeModified = true;
		if (root->partialRuleIDs == NULL) {
			root->partialRuleIDs = new vector<int>();
		}
		root->partialRuleIDs->push_back(ruleIndex);
	}

	//Checking for no overlap
	else if ((rules[ruleIndex]->getDimRangeMax(root->dimension) < root->low ) || (rules[ruleIndex]->getDimRangeMin(root->dimension) > root->high )) {
		if (root->low > rules[ruleIndex]->getDimRangeMax(root->dimension)) {
			root->lowModifier = rules[ruleIndex]->getDimRangeMin(root->dimension);
			root->leftRangeModified = true;
		}
		else {
			root->highModifier = rules[ruleIndex]->getDimRangeMax(root->dimension);
			root->rightRangeModified = true;
		}
		if (root->partialRuleIDs == NULL) {
			root->partialRuleIDs = new vector<int>();
		}
	}

	else {
	
	// cout << "Inside for loop for iteration: " << i << endl;
		s.push(root);
		while (!s.empty()) {
			t = s.top();
			s.pop();
			//cout << "(" << (*t).low << ": " << (*t).high << ")" << endl;
			inserted = 	(*t).insertARule (ruleIndex, t->dimension);
			if (!inserted) {
				if (((*t).right != NULL) && ((*t).right->partialSatisfiesRule(ruleIndex, t->dimension))) {
					s.push((*t).right);
				}
				if (((*t).left != NULL) && ((*t).left->partialSatisfiesRule(ruleIndex, t->dimension))) {
					s.push((*t).left);
				}
			}
			// if (!inserted) {
			// 	if ((*t).right != NULL) s.push((*t).right);
			// 	if ((*t).left != NULL) s.push((*t).left);
			// }
		}
	}
}

RangeTree* updateTree (RangeTree* root, vector<int>* ruleIDsToInsert, vector <int>* treeRuleIDs, const vector<int>& fieldOrder, size_t treeSize){
	//std::cout << "$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$!\n";

	//add rules till 10% of the tree's original capacity, then remake the tree with the 110% rules.
	size_t numRulesToUpdate = (*ruleIDsToInsert).size();	//Total rules to be updated.
	size_t numRulesToBeUpdatedBeforeRebuilding = treeSize/3;	//Rules to be inserted before the tree is redrawn.
	//For each of these rules, we will add them to the tree individually, as if the rules were buffered.
	size_t rulesUpdated = 0;
	int buildTreeIteration = 0;
	for (size_t i = 0; i < numRulesToUpdate; i++) {
		
		if (rulesUpdated >= numRulesToBeUpdatedBeforeRebuilding) {
			//Redraw the tree!
			treeRuleIDs->insert(treeRuleIDs->end(), ruleIDsToInsert->begin() + buildTreeIteration * numRulesToBeUpdatedBeforeRebuilding,
			 ruleIDsToInsert->begin() + buildTreeIteration * numRulesToBeUpdatedBeforeRebuilding + numRulesToBeUpdatedBeforeRebuilding); //adding the 
			//std::cout << "treeRuleIDs size: " << treeRuleIDs->size() << std::endl;

			delete root;
			root = nullptr;
			// std::ofstream buildTreeFile("buildTreeIDs.txt");

			// for (int val : *treeRuleIDs){
			// 	buildTreeFile << val << std::endl;
			// }

			// buildTreeFile.close();

			root = buildTree (treeRuleIDs, 0, fieldOrder);
			rulesUpdated = 0;
			buildTreeIteration++;
			//std::cout << "\nIteration " << buildTreeIteration << " of buildTree\n";
			continue;
		}
		partialInsertOneRule(root, (*ruleIDsToInsert)[i], 0);

		rulesUpdated++;
		//std::cout << rulesUpdated << " ";
	}
	return root;
}

void classify (RangeTree* root, Packet& packet, int dim, vector<int>* matches) {

	RangeTree* node = root;
	//cout << "%%%% packet[dim] = " << packet[dim] <<"; dim = " << dim << endl;
	//cout << "%%%% node values (" << (*node).low <<":" << (*node).high << ")" << endl;
	if (node != NULL) {
		if ((packet[dim] >= (*node).low) && (packet[dim] <= (*node).high)) {
			//cout << "Packet Attribute: " << dim << " = " << packet[dim];
			//cout << "; node values (" << (*node).low <<":" << (*node).high << ")" << endl;
			if (((*node).nextDimension == NULL) && ((*node).ruleIDs != NULL)) {
				int numCurrNodeRules = (*(*node).ruleIDs).size();
				for (int k=0; k < numCurrNodeRules; k++)
					(*matches).push_back((*(*node).ruleIDs)[k]);
					//cout << " " << (*(*node).ruleIDs)[k];
			}
			if ((*node).nextDimension != NULL) {
				//cout << "next dimension" << endl;
				//RangeTree* t = node;
				/*if ((*t).ruleIDs != NULL) {
					cout << "(" << (*t).low << ": " << (*t).high << "); Size = " << (*(*t).ruleIDs).size() << "==";
					for (int k=0; k < (*(*t).ruleIDs).size(); k++)
						cout << " " << (*(*t).ruleIDs)[k];
					cout << endl;
				}*/
				classify((*node).nextDimension, packet, dim+1, matches);
			}
		}
		if (!(((*node).low > packet[dim]) || ((*node).high < packet[dim]))) {
			if ((*node).left != NULL)
				classify((*node).left, packet, dim, matches);
			if ((*node).right != NULL) 
				classify((*node).right, packet, dim, matches);
		}
	}
} 
//The one used for numbers in the paper submitted.
void classifyFirst (RangeTree* root, Packet packet, int dim, const vector<int>& fieldOrder, int& matchRule) {
	RangeTree* node = root;
	bool found = false;

	if (node != NULL) {
		if ((packet[fieldOrder[dim]] >= (*node).low) && (packet[fieldOrder[dim]] <= (*node).high)) {
			if (((*node).nextDimension == NULL) && ((*node).ruleIDs != NULL)) {
				if ((*(*node).ruleIDs).size() > 0) {
					found = true;
					matchRule = (*(*node).ruleIDs)[0];
					//cout << "^^^^^ " << matchRule << endl;
					return;
				}
			}
			if (((*node).nextDimension != NULL) && (!found)) {
				//RangeTree* t = node;
				classifyFirst((*node).nextDimension, packet, dim+1, fieldOrder, matchRule);
			}
		}
		if (!found) {

			if (!(((*node).low > packet[dim]) || ((*node).high < packet[dim]))) {
				if ((*node).left != NULL)
					classifyFirst((*node).left, packet, dim, fieldOrder, matchRule);
				else if ((*node).right != NULL) 
					classifyFirst((*node).right, packet, dim, fieldOrder, matchRule);
			}
		}
	}
}
//This one classifies to a single rule, but still accurate since the rule classified to is the dont care rule.
void classifyFirstTest (RangeTree* root, Packet packet, int dim, const vector<int>& fieldOrder, int& matchRule) {
	RangeTree* node = root;
	//bool found = false;

	if (node != NULL) {
		if ((packet[fieldOrder[dim]] >= (*node).low) && (packet[fieldOrder[dim]] <= (*node).high)) {
			if ((node->ruleIDs != NULL) && (*(*node).ruleIDs).size() > 0) {
				if ((*node).nextDimension == NULL){
					matchRule = (*(*node).ruleIDs)[0];
					return;
				}
				else
					classifyFirstTest((*node).nextDimension, packet, dim+1, fieldOrder, matchRule);
			}
			else {
				if ((*node).left != NULL){
					if ((packet[fieldOrder[dim]] >= (*(*node).left).low) && (packet[fieldOrder[dim]] <= (*(*node).left).high)) {
						classifyFirstTest((*node).left, packet, dim, fieldOrder, matchRule);
					}
				}
				else if ((*node).right != NULL){
					if ((packet[fieldOrder[dim]] >= (*(*node).right).low) && (packet[fieldOrder[dim]] <= (*(*node).right).high)) {
						classifyFirstTest((*node).right, packet, dim, fieldOrder, matchRule);
					}
				}
				else return;
			}
		}
		else return;
	}
}
//An update of the classifyFirstTest algo. This one checks all rules sequentially at the terminal node.
void classifyBroadest (RangeTree* root, Packet packet, int dim, const vector<int>& fieldOrder, int& matchRule) {
	RangeTree* node = root;
	if (node == NULL) {
		return;
	}
	
	if (node->satisfiesPacket(packet[fieldOrder[dim]])) {
		if (node->nextDimension == NULL) {
			matchRule = node->linearSearchRule(packet);
			if (matchRule != -1){
				return;
			}	
		}
		else {
			classifyBroadest(node->nextDimension, packet, dim+1, fieldOrder, matchRule);
		}
	}
	
	//Go left or right
	if ((matchRule == -1) && (node->left != NULL) && (node->left->satisfiesPacket(packet[fieldOrder[dim]]))) {
		// if (node->left->satisfiesPacket(packet[fieldOrder[dim]])) {
			classifyBroadest(node->left, packet, dim, fieldOrder, matchRule);
		// }
	}
	if ((matchRule == -1) && (node->right!=NULL) && (node->right->satisfiesPacket(packet[fieldOrder[dim]]))) {
		// if (node->right->satisfiesPacket(packet[fieldOrder[dim]])) {
			classifyBroadest(node->right, packet, dim, fieldOrder, matchRule);
		// }
	}
}
//Function for finding the most specific rule applicable to the packet. This one does classify to other rules but not accurate.
void classifyLastRecursive (RangeTree* node, Packet packet, int dim, const vector<int>& fieldOrder, int& matchRule) {
	//RangeTree* t;
	//bool found = false;

	if (!node) return;

	if ((*node).satisfiesPacket(packet[fieldOrder[dim]])) {
		if (((*node).isleaf()) || 
			(((*node).ruleIDs != NULL) && ((*(*node).ruleIDs).size() == 1))) { // if node is leaf or it only has a single rule.
			if ((*node).ruleIDs != NULL) matchRule = (*((*node).ruleIDs))[0]; 
			return;
		}
		else //Rule ambiguity is there 
			classifyLastRecursive ((*node).nextDimension, packet, dim + 1, fieldOrder, matchRule);
	}
	// Based on packet characteristics, push left or right node to the stack.
	if (((*node).left != NULL) && ((*(*node).left).satisfiesPacket(packet[node->getDimension()])))
		classifyLastRecursive ((*node).left, packet, dim, fieldOrder, matchRule);
	else if (((*node).right != NULL) && ((*(*node).right).satisfiesPacket(packet[node->getDimension()])))
		classifyLastRecursive ((*node).right, packet, dim, fieldOrder, matchRule);
	
	
	//No match was found
	return;

}

//Function for finding the most specific rule applicable to the packet. This one classifies to a single rule.
void classifyLastIterative (RangeTree* node, Packet packet, int dim, const vector<int>& fieldOrder, int& matchRule) {
	//RangeTree* t;
	stack<RangeTree*> s;
	//bool found = false;

	s.push(node);
	while (!s.empty()){
		//t = s.top();
		s.pop();
		if ((*node).satisfiesPacket(packet[node->getDimension()])) {
			if (((*node).isleaf()) || 
				(((*node).ruleIDs != NULL) && ((*(*node).ruleIDs).size() > 0))) { // if node is leaf or it only has a single rule.
				matchRule = (*((*node).ruleIDs))[0]; 
				return;
			}
			else //Rule ambiguity is there 
				s.push((*node).nextDimension);
		}
		// Based on packet characteristics, push left or right node to the stack.
		if (((*node).left != NULL) && ((*(*node).left).satisfiesPacket(packet[node->getDimension()])))
			s.push((*node).left);
		else if (((*node).right != NULL) && ((*(*node).right).satisfiesPacket(packet[node->getDimension()])))
			s.push((*node).left);
		
	}
	//No match was found
	return;

}

bool classifyLastIterativeBacktrack (RangeTree* node, Packet packet, int dim, const vector<int>& fieldOrder, int& matchRule) {
	std::stack<RangeTree*> s;

	if ((node != NULL) && (node->satisfiesPacket(packet[node->getDimension()])) /*&& ((node->ruleIDs) != NULL)*/) { //cannot force the root to have rules.
		if (node->ruleIDs != NULL){
			s.push(node);
		}
			
	}
	else return false;
	bool flag = false;

	while (!flag) {
		if ((node->right != NULL) && (node->right->satisfiesPacket(packet[fieldOrder[dim]]))) {
			if ((node->right->ruleIDs != NULL))
				s.push(node->right);
			node = node->right;
		}
		else if ((node->left != NULL) && (node->left->satisfiesPacket(packet[fieldOrder[dim]]))) {
			if ((node->left->ruleIDs != NULL))
				s.push(node->left);
			node = node->left;
		}
		else flag = true; //Leaf node was encountered so all relevant nodes are in the stack.
	} // While loop ends here. The stack 's' should have all nodes satisfying the packet in a single dimension.

	//The next while loop will go through these nodes in the stack and check the next dimension.

	while (!s.empty()) { //Backtracking through the nodes by popping them out now.
		RangeTree* y = s.top();
		s.pop(); 	//backtracking requires removing the node visited.

		if ((y->ruleIDs != NULL) && (y->ruleIDs->size() == 1)) { //just one rule
			//just check for the remaining dimensions (if there are any).
			bool ruleFound = false;
			if (y->nextDimension != NULL) {
				RangeTree* z = y->nextDimension;
				
				while (z != NULL) {
					if (z->satisfiesPacket(packet[z->getDimension()])) {
						if (z->nextDimension != NULL){
							z = z->nextDimension;
						}
							
						else {
							matchRule = (*(z->ruleIDs))[0];
							ruleFound = true;
							return true;
						}
					}
					else {
						ruleFound = false;
						break;
					} 
				}
				if (ruleFound) break;
			}
			//if (ruleFound) return;
		}
		else { //have to do the same stuff with the remaining dimensions.
			bool ruleFound = classifyLastIterativeBacktrack (y->nextDimension, packet, dim+1, fieldOrder, matchRule);
			
			if (ruleFound) return true;
		}
	}
	return false;
}

bool classifyLastIterativeBacktrackLeafSize (RangeTree* node, Packet packet, int dim, const vector<int>& fieldOrder, int& matchRule) {
	std::stack<RangeTree*> s;

	if ((node != NULL) && (node->satisfiesPacket(packet[node->getDimension()])) /*&& ((node->ruleIDs) != NULL)*/) { //cannot force the root to have rules.
		if (node->ruleIDs != NULL){
			s.push(node);
		}
			
	}
	else return false;
	bool flag = false;

	while (!flag) {
		if ((node->right != NULL) && (node->right->satisfiesPacket(packet[fieldOrder[dim]]))) {
			if ((node->right->ruleIDs != NULL))
				s.push(node->right);
			node = node->right;
		}
		else if ((node->left != NULL) && (node->left->satisfiesPacket(packet[fieldOrder[dim]]))) {
			if ((node->left->ruleIDs != NULL))
				s.push(node->left);
			node = node->left;
		}
		else flag = true; //Leaf node was encountered so all relevant nodes are in the stack.
	} // While loop ends here. The stack 's' should have all nodes satisfying the packet in a single dimension.

	//The next while loop will go through these nodes in the stack and check the next dimension.

	while (!s.empty()) { //Backtracking through the nodes by popping them out now.
		RangeTree* y = s.top();
		s.pop(); 	//backtracking requires removing the node visited.

		if (y->nextDimension == NULL) { 
			//looping through each rule in the node to see which one satisfies MAX_DIMENSIONS - dim fields.
			for (unsigned int i = 0; i < y->ruleIDs->size(); i++) {
				for (int j = dim; j < MAX_DIMENSIONS; j++) {
					if (rules[(*(y->ruleIDs))[i]]->satisfiesPacketDim(packet, fieldOrder[j])) {
						matchRule = (*(y->ruleIDs))[i];
						return true;
					}
				}
			}
			return false;
		}
		else { //have to do the same stuff with the remaining dimensions.
			if (classifyLastIterativeBacktrackLeafSize (y->nextDimension, packet, dim+1, fieldOrder, matchRule)) return true;
		}
	}
	return false;
}

bool classifyLastIterativeBacktrackLeafSizeAllRules (RangeTree* node, Packet& packet, int dim, const vector<int>& fieldOrder, int& matchRule) {
	std::stack<RangeTree*> s;
	if ((packet[0] == 2165248841) && (packet[1] == 2165302995) && (packet[2] ==	32205) && (packet[3] == 22096) && (packet[4] == 55657)){
		cout << "Catch Debugger\n";
	}
	if ((node != NULL) && (node->satisfiesPacket(packet[node->getDimension()])) /*&& ((node->ruleIDs) != NULL)*/) { //cannot force the root to have rules.
		if ((node->ruleIDs != NULL) && (node->ruleIDs->size() > 0)){
			s.push(node);
		}
			
	}
	else return false;
	bool flag = false;

	while (!flag) {
		if ((node->right != NULL) && (node->right->satisfiesPacket(packet[fieldOrder[dim]]))) {
			if ((node->right->ruleIDs != NULL) && (node->right->ruleIDs->size() > 0))
				s.push(node->right);
			node = node->right;
		}
		if ((node->left != NULL) && (node->left->satisfiesPacket(packet[fieldOrder[dim]]))) {
			if ((node->left->ruleIDs != NULL) && (node->left->ruleIDs->size() > 0))
				s.push(node->left);
			node = node->left;
		}
		else flag = true; //Leaf node was encountered so all relevant nodes are in the stack.
	} // While loop ends here. The stack 's' should have all nodes satisfying the packet in a single dimension.

	//The next while loop will go through these nodes in the stack and check the next dimension.

	while (!s.empty()) { //Backtracking through the nodes by popping them out now.
		RangeTree* y = s.top();
		s.pop(); 	//backtracking requires removing the node visited.

		if (y->nextDimension == NULL) { 
			//looping through each rule in the node to see which one satisfies MAX_DIMENSIONS - dim fields.
			size_t numRules = y->ruleIDs->size();
			for (unsigned int i = 0; i < numRules; i++) {
				bool found = true;
				
				for (int j = dim; j < MAX_DIMENSIONS; j++) {
					if (!(rules[(*(y->ruleIDs))[i]]->satisfiesPacketDim(packet, fieldOrder[j]))) {
						found = false;
						break;
					}
				}
				if (found) {
					matchRule = (*(y->ruleIDs))[i];
					return true;
				}
			}
			//return false;
		}
			else { //have to do the same stuff with the remaining dimensions.
				if (classifyLastIterativeBacktrackLeafSizeAllRules (y->nextDimension, packet, dim+1, fieldOrder, matchRule)) return true;
			}
		}
		return false;
	}
//update to classifyLastIterativeBacktrackLeafSizeAllRules function by adding capability to detect forks.
bool classifySpecific (RangeTree* node, Packet& packet, int dim, const vector<int>& fieldOrder, int& matchRule) {
	std::stack<RangeTree*> s;
	if ((node != NULL) /*&& (node->satisfiesPacket(packet[node->getDimension()]))*/ /*&& ((node->ruleIDs) != NULL)*/) { //cannot force the root to have rules.
		if ((node->ruleIDs != NULL) && (node->ruleIDs->size() > 0)){
			s.push(node);
		}
	}
	else return false;
	bool flag = false;

	while (!flag) {
		//Checking if there is a fork
		if (((node->right != NULL) && (node->right->satisfiesPacket(packet[fieldOrder[dim]])))
			&& ((node->left != NULL) && (node->left->satisfiesPacket(packet[fieldOrder[dim]])))) {
				if (classifySpecific(node->left, packet, dim, fieldOrder, matchRule)) {
					return true;
				}
				else {
					if ((node->right->ruleIDs != NULL) && (node->right->ruleIDs->size() > 0)) {
						s.push(node->right);
					}
					node = node->right;
				}
		}
		else {
			if ((node->right != NULL) && (node->right->satisfiesPacket(packet[fieldOrder[dim]]))) {
				if ((node->right->ruleIDs != NULL) && (node->right->ruleIDs->size() > 0))
					s.push(node->right);
				node = node->right;
			}
			else if ((node->left != NULL) && (node->left->satisfiesPacket(packet[fieldOrder[dim]]))) {
				if ((node->left->ruleIDs != NULL) && (node->left->ruleIDs->size() > 0))
					s.push(node->left);
				node = node->left;
			}
			else flag = true; //Leaf node was encountered so all relevant nodes are in the stack.
		}
		
	} // While loop ends here. The stack 's' should have all nodes satisfying the packet in a single dimension.

	//The next while loop will go through these nodes in the stack and check the next dimension.

	while (!s.empty()) { //Backtracking through the nodes by popping them out now.
		RangeTree* y = s.top();
		s.pop(); 	//backtracking requires removing the node visited.

		if (y->nextDimension == NULL) { 
			//looping through each rule in the node to see which one satisfies MAX_DIMENSIONS - dim fields.
			size_t numRules = y->ruleIDs->size();
			for (unsigned int i = 0; i < numRules; i++) {
				bool found = true;
				
				for (int j = dim; j < MAX_DIMENSIONS; j++) {
					if (!(rules[(*(y->ruleIDs))[i]]->satisfiesPacketDim(packet, fieldOrder[j]))) {
						found = false;
						break;
					}
				}
				if (found) {
					matchRule = (*(y->ruleIDs))[i];
					return true;
				}
			}
			//return false;
		}
		else { //have to do the same stuff with the remaining dimensions.
			if (classifySpecific (y->nextDimension, packet, dim+1, fieldOrder, matchRule)) return true;
		}
	}
	return false;
}
//Called from within the classifyBruteForce() function.
void determineMostRelevantRule (const vector<int>& ruleSet, int dim, const vector<int>& fieldOrder, int& matchRule) {
	unsigned int minRangeSpan = 1;
	vector<int> minRules;
	if (dim == MAX_DIMENSIONS)
		return;
	if (ruleSet.size() == 1){
		matchRule = ruleSet[0];
		return;
	}
	int numRules = ruleSet.size();
	for (int i = 0; i < numRules; i++) {
		unsigned int rangeSpan = rules[ruleSet[i]]->getDimRangeMax(fieldOrder[dim]) - 
							rules[ruleSet[i]]->getDimRangeMin(fieldOrder[dim]);
		if (i == 0) {
			minRangeSpan = rangeSpan;
		}
		else {
			if (minRangeSpan > rangeSpan)
				minRangeSpan = rangeSpan;
		}

	}
	// After getting the value of minRangeSpan we will check the rules in ruleSet and push them into a vector to pass to next
	// dimension processing.

	for (int i = 0; i < numRules; i++) {
		unsigned int rangeSpan = rules[ruleSet[i]]->getDimRangeMax(fieldOrder[dim]) - 
							rules[ruleSet[i]]->getDimRangeMin(fieldOrder[dim]);
		if (rangeSpan == minRangeSpan) {
			minRules.push_back(ruleSet[i]);
		}
	}
	if (minRules.size() == 1) {
		matchRule = minRules[0];
		return;
	}
	else determineMostRelevantRule (minRules, dim + 1, fieldOrder, matchRule);
}



vector<int> classifyBruteForce () {
	vector<vector<int>> queryResult;		//Stores all the applicable rules for each packet.
	vector<int> mostRelevantRules;		//Stores the most relevant rule for each packet.
	//Checking which rules are satisfied by each packet.

	//A temporary backdoor to print the values of each relevant rule for each packet to a file.
	std::ofstream allRelevantRules ("AllApplicableRules.txt");
	int numPackets = packets.size();
	for (int i = 0; i < numPackets; i++){
		vector<int> ruleSet;
		int numRules = rules.size();
		for (int j = 0; j < numRules; j++) {
			if (rules[j]->satisfiesPacket(packets[i])) {              
				ruleSet.push_back(j);
			}
		}
		int numQueryResult = ruleSet.size();
		allRelevantRules << numQueryResult;
		for ( int k = 0; k < numQueryResult; k++) {
			allRelevantRules << " "<< ruleSet[k];
		}
		allRelevantRules << std::endl;
		queryResult.push_back(ruleSet);
	}
	allRelevantRules.close();
	//Now to check the rule which is the most relevant one
	
	int matchRule = -1;
	int dim = 0;
	int numQueryResult = queryResult.size();
	for (int i = 0; i < numQueryResult; i++) {
		determineMostRelevantRule(queryResult[i], dim, fieldOrder, matchRule);
		mostRelevantRules.push_back(matchRule);
		matchRule = -1;
	}
	return mostRelevantRules;
}

vector<Packet> generatePacketsFromFile(string fileName) {
	ifstream inputFile (fileName);
	if (!inputFile) {
        std::cerr << "Failed to open the file for reading.\n";
        exit (0);
    }
	vector<Packet> Packets;
	std::string line;
    while (getline(inputFile, line)) {
        Packet packet;
		stringstream ss(line);
		string field;
		int i = 0;
        while (getline(ss, field, ' ')) {
			unsigned int intField = atoui(field);
			packet[i++] = (intField);
		}
		Packets.push_back(packet);
    }
	return Packets;
}

vector<rule*> generateRulesFromFile(string fileName) {
	ifstream inputFile (fileName);
	if (!inputFile) {
        std::cerr << "Failed to open the file for reading.\n";
        exit (0);
    }
	vector<rule*> Rules;
	std::string line;
	int ruleCounter = 0;
    while (getline(inputFile, line)) {
		stringstream ss(line);
		string field;
		int pairCounter = 1;
		
		unsigned int intField1 = 0;
		unsigned int intField2 = 0;
		vector <pair<unsigned int, unsigned int>> fields;
        while (getline(ss, field, ' ')) {
			
			if (pairCounter % 2 != 0)
				intField1 = atoui(field);
			else {
				intField2 = atoui(field);
				pair<unsigned int, unsigned int> fieldPair = {intField1, intField2};
				fields.push_back(fieldPair);
			}	
			pairCounter++;
		}
		rule* Rule = new rule (fields, ruleCounter, MAX_DIMENSIONS);
		Rules.push_back(Rule);
		ruleCounter++;
    }
	return Rules;
}
// Function to calculate the mean
double calculateMean(const std::vector<double>& values) {
    return std::accumulate(values.begin(), values.end(), 0.0) / values.size();
}

// Function to calculate the standard deviation
double calculateStdDev(const std::vector<double>& values, double mean) {
    double sum = 0.0;
    for (auto value : values) {
        sum += (value - mean) * (value - mean);
    }
    return std::sqrt(sum / values.size());
}
void writePacketsToFile(std::vector<Packet>&, string);
Packets readPacketsFromFile(string fileName);
Packets generateRandomTraceFromRules(vector<rule*>& rules);
vector<rule*> readRandomGenFile(string fileName);

string GetEnvOrDefault(const char* key, const string& defaultValue) {
	const char* value = getenv(key);
	if (value == nullptr || *value == '\0') {
		return defaultValue;
	}
	return string(value);
}

string NormalizeBenchmarkMode(const string& mode) {
	string normalized;
	for (char ch : mode) {
		if (!isspace(static_cast<unsigned char>(ch))) {
			normalized += static_cast<char>(tolower(static_cast<unsigned char>(ch)));
		}
	}
	return normalized;
}

bool ShouldRunSpecificClassification(const string& mode) {
	return mode != "broadest";
}

bool ShouldRunBroadestClassification(const string& mode) {
	return mode != "specific";
}

void WriteClassificationResults(const string& filename, const vector<int>& results) {
	ofstream output(filename);
	for (int result : results) {
		output << result << '\n';
	}
}

int main (int argc, char* argv[]) {

	RangeTree* mainRoot;
	set<int> ruleMatches;
	int argument_count = 1;
	int brute_force_choice = 0; //Default to no brute classification.
	int update_choice = 0; //Default to no updates.
    int dim = 0;
	if ((argc > 6) || (argc < 5))
	{
		std::cout << "Please use the following format:" << endl;
		std::cout << "./main {Rules_File} [Optional_Packets_File] {maximum_nodes_per_leaf} {Update = 0,1} {Brute = 0,1}\n";
		exit(-1);
	}
	    //numRules = stoi(argv[1]); //numRules is a global variable.
	    srand(time(NULL));
		string packetCountOverride = GetEnvOrDefault("NPTREE_PACKET_COUNT", "");
		if (!packetCountOverride.empty()) {
			NUM_PACKETS = stoi(packetCountOverride);
		}
		rules = InputReader::ReadFilterFileClassBench(argv[argument_count++]);
	//string ruleFile = argv[argument_count++];
	//rules = readRandomGenFile(ruleFile);
	// std::string rules_file = argv[1];
	// std::string packet_filename = rules_file + ".packets";
	//rules = generateRulesFromFile(argv[1]);
    int numRules = rules.size();
	for (int i = 0; i < numRules; i++) {
		for (int j = 0; j < 5; j++) {
			if (rules[i]->getDimRangeMin(j) == rules[i]->getDimRangeMax(j))
				rules[i]->setDimRangeMax(j,rules[i]->getDimRangeMax(j) + 1);
		}
		
	}
	if (argc == 6) {
		string packetFile = argv[argument_count++];
		packets = readPacketsFromFile(packetFile);
	}
	else {
		//packets = generateRandomTraceFromRules(rules);
		packets = GeneratePacketsFromRuleset(rules);
	}
	NUM_PACKETS = static_cast<int>(packets.size());
	maxRulesPerNode = std::stoi(argv[argument_count++]);
	update_choice = std::stoi(argv[argument_count++]);
	brute_force_choice = std::stoi(argv[argument_count++]);
	
	//packets = GeneratePacketsFromRuleset(rules);
	//writePacketsToFile(packets, packet_filename);
	vector<int>* ruleIDs = new vector<int>();
	for (int i =0; i < numRules; i++) {
		(*ruleIDs).push_back(i);
	}

	if (update_choice) {
		//Determine the rules to be removed for insertion.
		// Random generator
		std::random_device rd;
		std::mt19937 g(rd());
		std::vector<rule*> shuffleRules = rules;

		// Shuffle the  vector
		std::shuffle(shuffleRules.begin(), shuffleRules.end(), g);
		size_t halfSize = shuffleRules.size() / 2;
		vector<int>* buildRuleIDs = new vector<int>();
		//std::unique_ptr<std::vector<int>> shuffleRuleIDs = std::make_unique<std::vector<int>>();
		for (size_t i =0; i < halfSize; i++) {
			if (shuffleRules[i] != nullptr) {
				buildRuleIDs->push_back(shuffleRules[i]->getRuleNumber());
			} 
			else {
				std::cout << "Null pointer encountered at index " << i << std::endl;
			}
		}
		
		chrono::time_point<chrono::steady_clock> start = chrono::steady_clock::now();
		mainRoot = buildTree (buildRuleIDs, 0, fieldOrder);
		chrono::time_point<chrono::steady_clock> end = chrono::steady_clock::now();
		chrono::duration<double> elapsed = end - start;
		std::cout << elapsed.count() << ", ";
		
		vector<int>* updateRuleIDs = new vector<int>();
		
		for (size_t i = halfSize; i < shuffleRules.size(); i++) {
			(*updateRuleIDs).push_back(shuffleRules[i]->getRuleNumber());
		}
		
		start = chrono::steady_clock::now();
		mainRoot = updateTree (mainRoot, updateRuleIDs, buildRuleIDs, fieldOrder, halfSize);
		end = chrono::steady_clock::now();
		elapsed = end - start;
		std::cout << elapsed.count() << ", ";

		start = chrono::steady_clock::now();
		for (size_t i = 0 ; i < shuffleRules.size(); i++) {
			deleteRuleIterative(mainRoot, shuffleRules[i]->getRuleNumber());
		}
		end = chrono::steady_clock::now();
		elapsed = end - start;
		std::cout<< elapsed.count() << std::endl;

		//std::cout << 1.5 * halfSize - halfSize/2 <<std::endl;
		delete updateRuleIDs;
		delete buildRuleIDs;
		//std::cout <<"\nEverything done and dusted!\n";
	}
	    else {
			chrono::time_point<chrono::steady_clock> start = chrono::steady_clock::now();
			mainRoot = buildTree (ruleIDs, 0, fieldOrder);
			chrono::time_point<chrono::steady_clock> end = chrono::steady_clock::now();
			chrono::duration<double> elapsed = end - start;
			double constructionSeconds = elapsed.count();
			size_t memoryBytes = EstimateRangeTreeBytes(mainRoot);
			string benchmarkMode = NormalizeBenchmarkMode(GetEnvOrDefault("NPTREE_MODE", "both"));
			bool runSpecific = ShouldRunSpecificClassification(benchmarkMode);
			bool runBroadest = ShouldRunBroadestClassification(benchmarkMode);
			string resultsFile = GetEnvOrDefault("NPTREE_RESULTS_FILE", "Classification_Outupt.txt");
			int ruleClassified = -1;
			vector<int> queryResultSpecific;
			vector<int> queryResultBroadest;
			double specificSeconds = -1.0;
			double broadestSeconds = -1.0;
			if (runSpecific) {
				start = chrono::steady_clock::now();
				for (int j = 0; j < 10; j++) {
					queryResultSpecific.clear();
					for (int i = 0; i < NUM_PACKETS; i++) {
						classifySpecific (mainRoot, packets[i], dim, fieldOrder, ruleClassified);
						queryResultSpecific.push_back(ruleClassified);
						ruleClassified = -1;
					}
				}
				end = chrono::steady_clock::now();
				elapsed = end - start;
				specificSeconds = elapsed.count() / 10;
			}

			if (runBroadest) {
				start = chrono::steady_clock::now();
				for (int j = 0; j < 10; j++) {
					queryResultBroadest.clear();
					
					for (int i = 0; i < NUM_PACKETS; i++) {
						classifyBroadest (mainRoot, packets[i], dim, fieldOrder, ruleClassified);
						queryResultBroadest.push_back(ruleClassified);
						ruleClassified = -1;
					}
				}
				end = chrono::steady_clock::now();
				elapsed = end - start;
				broadestSeconds = elapsed.count() / 10;
			}

			std::cout << constructionSeconds;
			if (runSpecific) {
				std::cout << ", " << specificSeconds;
			}
			if (runBroadest) {
				std::cout << ", " << broadestSeconds;
			}
			std::cout << std::endl;
			std::cout << "BENCHMARK.NPTree.CONSTRUCTION_MS=" << constructionSeconds * 1000.0 << std::endl;
			std::cout << "BENCHMARK.NPTree.MEMORY_BYTES=" << memoryBytes << std::endl;
			if (runSpecific) {
				std::cout << "BENCHMARK.NPTree.SPECIFIC_TIME_NS_TOTAL=" << specificSeconds * 1000000000.0 << std::endl;
			}
			if (runBroadest) {
				std::cout << "BENCHMARK.NPTree.TIME_NS_TOTAL=" << broadestSeconds * 1000000000.0 << std::endl;
			}
	
		// //size_t halfSize = ruleIDs->size() / 2;
		// start = chrono::steady_clock::now();
		// for (size_t i = 0; i < ruleIDs->size(); i++) {
		// 	deleteRuleIterative(mainRoot, (*ruleIDs)[i]);
		// }
		// end = chrono::steady_clock::now();
		// elapsed = end - start;
		// std::cout << elapsed.count() << std::endl;
			if (!runSpecific && runBroadest) {
				WriteClassificationResults(resultsFile, queryResultBroadest);
			}
			else if (runSpecific && !runBroadest) {
				WriteClassificationResults(resultsFile, queryResultSpecific);
			}
			else {
				ofstream classificationOutput(resultsFile);
				for (size_t i = 0; i < queryResultBroadest.size(); i++) {
					classificationOutput << queryResultSpecific[i] << "\t"
						<< queryResultBroadest[i] << std::endl;
				}
				classificationOutput.close();
			}
		}
	//Classifying brute force
	if (brute_force_choice){
		std::cout <<"\n Classifying Brute force: \n";
		chrono::time_point<chrono::steady_clock> start = chrono::steady_clock::now();
		vector<int> bruteForceResult = classifyBruteForce();
		chrono::time_point<chrono::steady_clock> end = chrono::steady_clock::now();
		chrono::duration<double> elapsed = end - start;
		std::cout << "\n The time taken to brute force classify " << NUM_PACKETS << " packets is:" << elapsed.count() << " seconds\n";
		std::ofstream outfileBrute ("BruteClassification.txt");
		
		if (!outfileBrute) {
			std::cerr << "Failed to open the file for writing.\n";
			exit (0);
		}
		// Write the vector's contents to the file
		for (const auto& value : bruteForceResult) {
			outfileBrute << value << '\n';  // Writes each element on a new line
		}

		// Close the file (optional here, since the file will close when outfile goes out of scope)
		outfileBrute.close();
	}

	//cleanup.
	for (rule* currRule : rules) {
		delete currRule;
	}
	
	delete ruleIDs;
	delete mainRoot;
}

vector<rule*> readRandomGenFile(string fileName) {
	vector<rule*> rules;
	ifstream inputFile(fileName);
	if (!inputFile) {
		cout << "Rule File not found!\n";
		exit(-1);
	}
	string line;
	uint32_t sip_min, sip_max, dip_min, dip_max, sp_min, sp_max, dp_min, dp_max, proto_min, proto_max;
	int count = 0;
	while(getline(inputFile, line)) {
		stringstream ss(line);
		ss >> sip_min >> sip_max >> dip_min >> dip_max >> sp_min >> sp_max >> dp_min >> dp_max >> proto_min >> proto_max;
		pair<uint32_t, uint32_t> sip(sip_min, sip_max);
		pair<uint32_t, uint32_t> dip(dip_min, dip_max);
		pair<uint32_t, uint32_t> sp(sp_min, sp_max);
		pair<uint32_t, uint32_t> dp(dp_min, dp_max);
		pair<uint32_t, uint32_t> proto(proto_min, proto_max);
		vector<pair<uint32_t, uint32_t>> fields;
		fields.push_back(sip);
		fields.push_back(dip);
		fields.push_back(sp);
		fields.push_back(dp);
		fields.push_back(proto);
		rule* new_rule = new rule(fields, count++, 5);
		rules.push_back(new_rule);
	}
	return rules;
}
void writePacketsToFile(std::vector<Packet>& packets, string filename) {
	ofstream outputFile(filename);
	for (auto& packet:packets) {
		for (auto& val: packet){
			outputFile << val << '\t';
		}
		outputFile << std::endl;
	}
	outputFile.close();
}

Packets readPacketsFromFile(string fileName) {
	ifstream inputFile(fileName);
	//vector<Packet> packets;
	if (!inputFile) {
		cout << "Packets File not found!\n";
		exit(-1);
	}
	uint32_t sip, dip, sp, dp, proto;
	//int count = 0;
	while(inputFile >> sip >> dip >> sp >> dp >> proto) {
		Packet packet;
		packet[0] = sip;
		packet[1] = (dip);
		packet[2] = (sp);
		packet[3] = (dp);
		packet[4] = (proto);
		packets.push_back(packet);
	}
	return packets;
}

// Function to generate a random value within a range
uint32_t getRandomValueInRange(uint32_t first, uint32_t second) {
    return first + (rand() % (second - first + 1));
}
Packets generateRandomTraceFromRules(vector<rule*>& rules) {
	Packets packets;
	int trace_length = 1000000;
	for (int row = 0; row < trace_length; ++row) {
		Packet new_packet;
        for (int j = 0; j < MAX_DIMENSIONS; ++j) {
            int randomIndex = rand() % rules.size();
            uint32_t first = rules[randomIndex]->fields[j].first;
            uint32_t second = rules[randomIndex]->fields[j].second;
            uint32_t value = getRandomValueInRange(first, second);
            new_packet[j] = (value);
        }
		packets[row] = (new_packet);
    } 
	return packets;
}
