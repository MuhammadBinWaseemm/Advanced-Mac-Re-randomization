# Advanced MAC Randomization Architecture (SAS-J + MIRAGE-Lite)

This repository contains the `ns-3` implementation of an advanced privacy-preserving MAC address randomization framework for IEEE 802.11 Wi-Fi networks. It is designed to defeat sophisticated passive tracking adversaries who utilize Timing Correlation, Traffic Flow Analysis, and Sequence Number Tracking to deanonymize users.

---

# Core Security Mechanisms

This architecture is built on three deeply integrated defense layers:

## 1. SAS-J (Stochastic Address Synchronization with Jitter)

Defeats Timing Correlation attacks. Replaces deterministic MAC rotation intervals (e.g., fixed 30s) with a cryptographically derived pseudo-random interval bounded between 15s and 45s. Synchronization between the Station (STA) and Access Point (AP) is achieved mathematically via the shared PTK, eliminating the need for over-the-air handshakes.

## 2. MIRAGE-Lite (Dual-MAC Flow Fragmentation)

Defeats Traffic Flow Analysis (IAT) attacks. Derives two mathematically linked virtual MAC addresses per rotation cycle and dispatches outgoing packets using a deterministic round-robin algorithm. This splits a continuous behavioral stream into two statistically independent fragments, cutting the attacker's flow correlation success rate in half.

## 3. PN-H (Sequence Number Obfuscation)

Defeats Monotonic Counter Linkage. Dynamically offsets the standard IEEE 802.11 Sequence Number prior to transmission, forcing the over-the-air sequence number (PN-H) to restart exactly at `0` upon every rotation. The AP flawlessly reverses this offset upon reception to prevent TCP/upper-layer queue desynchronization (achieving 0.00% packet loss).

---

# Performance Impact

Through extensive ns-3 simulations, this architecture reduces the adversary's total tracking kill-chain success rate from **100% to 1.25%**, while maintaining:

* **0.00%** Packet Loss
* **0.00%** Throughput Degradation
* **< 0.05ms** Latency Overhead (O(1) Hash Map AP Resolution)

---

# Repository Structure & Installation Guide

To run this simulation on a Linux machine, copy the repository files into the corresponding directories inside your root `ns-3` folder (e.g., `ns-3.41/` or `ns-3.42/`).

---

## 1. Core Algorithm Implementation

Place the following files into the Wi-Fi module model directory:

### Destination

```bash
ns-3.xx/src/wifi/model/
```

### Files to Copy

```bash
mac-rerandomization-manager.cc
mac-rerandomization-manager.h
```

### Additional Step

Manually add `mac-rerandomization-manager.cc` to the `CMakeLists.txt` file inside the `src/wifi/` directory so the compiler builds the new module.

---

## 2. Network Simulation Script

Place the simulation topology script into the `scratch` directory.

### Destination

```bash
ns-3.xx/scratch/
```

### File to Copy

```bash
wisec24-mac-randomization.cc
```

---

## 3. Python Evaluation Script

Place the evaluation script into the root directory of your `ns-3` installation.

### Destination

```bash
ns-3.xx/
```

### File to Copy

```bash
evaluate_metrics.py
```

---

# How to Run

## 1. Navigate to the ns-3 Root Directory

Open a Linux terminal and move to the root directory of your `ns-3` installation.

```bash
cd ~/ns-3.xx/
```

---

## 2. Configure and Build ns-3

Reconfigure and build `ns-3` so it compiles the newly added Wi-Fi C++ models.

```bash
./ns3 configure
./ns3 build
```

---

## 3. Run the MAC Randomization Simulation

Execute the simulation from the `scratch` directory.

```bash
./ns3 run scratch/wisec24-mac-randomization
```

---

## 4. Evaluate Metrics and Generate Graphs

After the simulation completes, XML and PCAP files will be generated in the root directory. Run the Python evaluation script to analyze the output and generate graphs.

```bash
python3 evaluate_metrics.py
```
