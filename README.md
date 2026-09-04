# LLM-Based Network Traffic Modification Benchmark

## Thesis context

This benchmark was developed as part of a Master’s thesis at KTH Royal
Institute of Technology exploring the intersection of Artificial Intelligence
(AI), Large Language Models (LLMs), and Cybersecurity.

## Overview

This repository provides a reproducible benchmark for evaluating whether Large
Language Models can modify malicious network traffic so that a rule- and
inspector-based Network Intrusion Detection System detects less of the original
attack evidence.

The benchmark uses labelled CICIDS2017 traffic, bounded LLM-generated
modifications, deterministic traffic reconstruction, and paired PRE/POST
evaluation with Snort 3. It evaluates detector behaviour rather than claiming
that the modified traffic preserves the original malicious functionality.

## Benchmark workflow

The implemented pipeline:

1. Selects labelled malicious flows and their packets.
2. Converts the selected PCAP into a structured packet representation.
3. Groups related packets and assigns editable targets.
4. Constructs bounded and traceable Prompt Units.
5. Executes LLM inference using vLLM.
6. Validates and materialises authorised modifications.
7. Reconstructs a complete POST PCAP.
8. Executes Snort over the PRE and POST captures.
9. Compares detector events and computes evasion metrics.
10. Audits every physical packet difference against accepted modification
    evidence.

Missing, rejected, or invalid model outputs preserve the corresponding original
traffic. This prevents inference failures or packet loss from being interpreted
as successful detector evasion.

## Design principles

- **Controlled comparisons:** experiments might vary selected factors while
  retaining the remaining conditions where possible.
- **Bounded model authority:** the LLM may modify only explicitly authorised
  fields or canonical payload ranges.
- **Fail-closed processing:** incompatible, incomplete, or inconsistent
  artefacts stop the relevant pipeline stage.
- **End-to-end traceability:** versioned contracts connect source packets,
  Prompt Units, model proposals, reconstructed traffic, and detector outcomes.
- **Complete packet preservation:** PRE and POST captures retain the same packet
  population and ordering.
- **Joint evaluation:** evasion, retained or mutated detection, displaced
  detection, and newly induced alerts are analysed separately.

## Repository structure

```text
10_Pipeline/
└── Pipeline Steps 11–25 and shared contracts

30_Executions/
├── 01_Pipeline1/             # Local execution of Steps 11–15
├── 02_LLM_Inference_GPU/     # GPU execution and calibration for Steps 16–17
└── 03_Pipeline2/             # Local execution of Steps 18–25

90_Testing_Legacy/
└── Superseded exploratory implementations
```

The active workflow is divided into three execution segments:
- Pipeline 1: Steps 11–15, from experiment setup to modification-unit
  planning.
- GPU inference: Steps 16–17, from Prompt Unit construction to validated LLM
  outputs.
- Pipeline 2: Steps 18–25, from modification materialisation to detector
  metrics and packet-level auditing.
Operational instructions for Steps 16 and 17 are available in
30_Executions/02_LLM_Inference_GPU/README.

## Scope and limitations

The benchmark measures technical detector evasion under a fixed traffic
population, detector configuration, ruleset, model, and experimental policy.
Its results should not be interpreted as universal NIDS evasion or as evidence
that modified traffic still executes the original malicious action.
