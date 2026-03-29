ICNP 2016: A Sorted Partitioning Approach to High-speed and Fast-update OpenFlow Classification

Tested on Ubuntu 14.04.4 LTS. 

Requirement:
g++ at least version 4.9.

Installation: make

To prebuild the vendored SmartSplit backend only: make smartsplit

Other top-level external build targets:

- make tuplemerge
- make bytecuts
- make cuttss
- make cutsplit
- make tabtree
- make nptree
- make externals

How to run the simulator: ./main [options]

select filter: f="fw1_seed_1.rules" 

select modes:  m="Classification", "Update", or "Validation" (Default: classification)

select output path and filename.csv: o="Output/64k_fw1_seed_1.csv"

select classifiers: c="PartitionSort,PriorityTuple". It is possible to run multiple classifiers. (Classifiers: "PartitionSort", "PriorityTuple", "PTSS", "HyperCuts", "HyperSplit", "SmartSplit", "TupleMerge", "ByteCuts", "CutTSS", "CutSplit", "TabTree", "NPTree", "TCAM", "All")

You can also use technique="PartitionSort" instead of c=...

By default the program auto-generates a packet trace from the ruleset when p="Auto".
Use PacketCount=<n> to control how many packets are generated.

You can run multiple selected techniques concurrently in Classification mode with:

- Parallel=1
- TechniqueThreads=<n>

If Parallel=1 is set and TechniqueThreads is omitted, the driver uses one worker per selected technique. CSV rows still stay in the requested technique order.

This parallelism is inside a single `./main` invocation. Running two separate top-level benchmark processes at the same time can still conflict for SmartSplit, because that external repo reuses shared build/output files in its workspace.

Externally vendored techniques currently integrated under External/ are:

- SmartSplit
- TupleMerge
- ByteCuts
- CutTSS
- CutSplit
- TabTree
- NPTree

You can override any vendored workspace path with:

- SmartSplit.Repo=<path>
- TupleMerge.Repo=<path>
- ByteCuts.Repo=<path>
- CutTSS.Repo=<path>
- CutSplit.Repo=<path>
- TabTree.Repo=<path>
- NPTree.Repo=<path>

NPTree-specific knobs:

- NPTree.MaxRulesPerNode=<n>
- NPTree.Mode=Specific|Broadest

For mixed native + external benchmarks, the driver automatically disables Shuffle to preserve consistent rule priority semantics across file-based external backends.

Classification mode now reports:

- construction time
- classification time
- classifier memory stats
- classification accuracy against exact brute-force ground truth on a configurable packet sample

Use AccuracyPackets=<n> to control the number of packets used for exact accuracy checking.
The default is 10,000 packets. Use AccuracyPackets=-1 to validate all packets in the trace.

Try now (no space between = sign):

./main f="fw1_seed_1.rules" technique="PartitionSort" m="Classification" PacketCount=100000 AccuracyPackets=10000 o="Output/64k_fw1_seed_1.csv"

Parallel multi-technique example:

./main f="fw1_seed_1.rules" technique="PartitionSort,ByteCuts,SmartSplit,NPTree" m="Classification" PacketCount=100000 AccuracyPackets=10000 Parallel=1 TechniqueThreads=4 o="Output/parallel_fw1_seed_1.csv"

External examples:

./main f="fw1_seed_1.rules" technique="ByteCuts" m="Classification" PacketCount=100000 AccuracyPackets=10000 o="Output/bytecuts_fw1_seed_1.csv"

./main f="fw1_seed_1.rules" technique="CutTSS" m="Classification" PacketCount=100000 AccuracyPackets=10000 o="Output/cuttss_fw1_seed_1.csv"

./main f="fw1_seed_1.rules" technique="TabTree" m="Classification" PacketCount=100000 AccuracyPackets=10000 o="Output/tabtree_fw1_seed_1.csv"

./main f="fw1_seed_1.rules" technique="NPTree" m="Classification" PacketCount=100000 AccuracyPackets=10000 NPTree.MaxRulesPerNode=16 NPTree.Mode=Specific o="Output/nptree_fw1_seed_1.csv"

SynthClass Python prototype:

- Python package: `synthclass/`
- Entry point: `train_synthclass.py`
- PPO dependency file: `requirements-synthclass.txt`

The Python side builds a composition tree with three node types:

- routing nodes
- terminal nodes
- bypass nodes

Terminal nodes benchmark the chosen classifier by calling the unified `./main` driver on the local rule subset and local packet trace. The reward is:

- `-(alpha * mean_latency + beta * memory_bytes + gamma * build_time_ms)`

Heuristic smoke test, no extra Python dependencies required:

```bash
python3 train_synthclass.py \
  --controller heuristic \
  --train-rulesets fw1_seed_1.rules \
  --episodes 1 \
  --packets-per-ruleset 256 \
  --portfolio PartitionSort,NPTree \
  --output-dir Output/synthclass_smoke
```

That writes:

- `training_history.jsonl`
- `run_summary.json`
- `final_tree.json`
- `final_tree_nodes.jsonl`

To print live per-node choices while the composition tree is being built, add:

- `--log-tree-decisions`

PPO training flow:

```bash
python3 -m pip install -r requirements-synthclass.txt
python3 train_synthclass.py \
  --controller ppo \
  --train-rulesets Rulesets \
  --eval-rulesets /path/to/heldout_rulesets \
  --episodes 100 \
  --batch-size 4 \
  --eval-interval 10 \
  --packets-per-ruleset 512 \
  --portfolio PartitionSort,PriorityTuple,HyperCuts,HyperSplit,ByteCuts,CutSplit,TabTree,NPTree,TCAM \
  --output-dir Output/synthclass_ppo \
  --save-checkpoint
```

Supervised leaf-classifier training flow:

1. Build a leaf-level dataset by partitioning each ruleset into composition-tree leaves and benchmarking every technique in the portfolio on every leaf:

```bash
python3 build_supervised_leaf_dataset.py \
  --rulesets Rulesets/1k_2k_4k_8k/1k_1 \
  --packets-per-ruleset 256 \
  --portfolio PartitionSort,PriorityTuple,HyperCuts,HyperSplit,ByteCuts,CutSplit,TabTree,NPTree,TCAM \
  --output-dir Output/supervised_leaf_dataset
```

That writes:

- `leaf_dataset.jsonl`
- `leaf_dataset.csv`
- `leaf_dataset_metadata.json`
- `dataset_summary.json`

2. Train the neural network that predicts latency, memory, and build time for every technique on each leaf:

```bash
python train_supervised_leaf_model.py \
  --dataset Output/supervised_leaf_dataset/leaf_dataset.jsonl \
  --metadata Output/supervised_leaf_dataset/leaf_dataset_metadata.json \
  --output-dir Output/supervised_leaf_model \
  --epochs 50 \
  --batch-size 256
```

That writes:

- `leaf_selector_model.pt`
- `training_history.jsonl`
- `training_summary.json`

Phased evaluation across different ruleset-size folders is also supported. Each listed eval folder stays active for `--eval-phase-length` episodes, and `evaluation_history.jsonl` records the active phase label for every eval round:

```bash
python train_synthclass.py \
  --controller ppo \
  --train-rulesets Rulesets/8k_1 \
  --eval-phase-rulesets Rulesets/1k_1 Rulesets/2k_1 Rulesets/4k_1 Rulesets/8k_1 Rulesets/16k_1 Rulesets/32k_1 Rulesets/64k_1 \
  --eval-phase-length 100 \
  --episodes 700 \
  --eval-interval 10 \
  --packets-per-ruleset 256 \
  --output-dir Output/synthclass_size_sweep
```

To analyze ruleset structure by size bucket and average endpoint/overlap statistics across all files in each folder:

```bash
python3 analyze_ruleset_size_stats.py \
  --size-folders Rulesets/1k_2k_4k_8k/1k_1 Rulesets/1k_2k_4k_8k/2k_1 Rulesets/1k_2k_4k_8k/4k_1 Rulesets/1k_2k_4k_8k/8k_1 Rulesets/16k_1 Rulesets/32k_1 Rulesets/64k_1 \
  --output-dir Output/ruleset_size_stats
```

That writes:

- `per_ruleset_statistics.csv`
- `per_size_statistics.csv`

To compare SynthClass averaged packet-classification latency against other techniques from a per-file runtime CSV:

```bash
python plot_latency_comparison.py \
  --synthclass-summary Output/synthclass_size_sweep/plots/grouped_evaluation_summary.csv \
  --technique-results "Output/ruleset_size_stats/New_Results - Sheet1.csv" \
  --output-dir Output/ruleset_size_stats/comparison_plots
```

That writes:

- `latency_comparison_summary.csv`
- `latency_comparison_bar.png`

The default portfolio is intentionally practical rather than maximal. SmartSplit and TupleMerge can still be added through `--portfolio`, but they make RL episodes much slower, and SmartSplit also remains unsafe across multiple separate top-level benchmark processes that run concurrently.

Note: 

In the code, we set to run repeatedly 10 times during classification or updates and then report the average. 

HybridCuts repository inspection was also done, but that repo only exposes construction statistics and does not implement packet-trace classification in its current form, so it is not wired into the unified classification benchmark yet.

You can find rulesets that we used in experiment in Rulesets folder.

You can customize your own classifier. See BruteForce.h as an example. Note that deletion function requires the strict ordering of rule rearrangement as in BruteForce.h. Make sure that you test correctness by running Validation mode. 

Please contact me if you have any question. 

Sorrachai Yingchareonthawornchai

Michigan State University

yingchar[at]cse.msu.edu 

Nov 21, 2016


Acknowledgement:
MITree implementation is developed based on the raw red-black tree implementation from

http://web.mit.edu/~emin/Desktop/ref_to_emin/www.old/source_code/red_black_tree/index.html

[Online; Jan, 2016]
