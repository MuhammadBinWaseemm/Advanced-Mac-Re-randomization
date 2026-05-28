# Advanced MAC Randomization Architecture (SAS-J + MIRAGE-Lite)
This repository contains the `ns-3` implementation of an advanced privacy-preserving MAC address randomization framework for IEEE 802.11 Wi-Fi networks. It is designed to defeat sophisticated passive tracking adversaries who utilize Timing Correlation, Traffic Flow Analysis, and Sequence Number Tracking to deanonymize users.
## Core Security Mechanisms
This architecture is built on three deeply integrated defense layers:
1. **SAS-J (Stochastic Address Synchronization with Jitter)**
   Defeats Timing Correlation attacks. Replaces deterministic MAC rotation intervals (e.g., fixed 30s) with a cryptographically derived pseudo-random interval bounded between 15s and 45s. Synchronization between the Station (STA) and Access Point (AP) is achieved mathematically via the shared PTK, eliminating the need for over-the-air handshakes.
2. **MIRAGE-Lite (Dual-MAC Flow Fragmentation)**
   Defeats Traffic Flow Analysis (IAT) attacks. Derives two mathematically linked virtual MAC addresses per rotation cycle and dispatches outgoing packets using a deterministic round-robin algorithm. This splits a continuous behavioral stream into two statistically independent fragments, cutting the attacker's flow correlation success rate in half.
3. **PN-H (Sequence Number Obfuscation)**
   Defeats Monotonic Counter Linkage. Dynamically offsets the standard IEEE 802.11 Sequence Number prior to transmission, forcing the over-the-air sequence number (PN-H) to restart exactly at `0` upon every rotation. The AP flawlessly reverses this offset upon reception to prevent TCP/upper-layer queue desynchronization (achieving 0.00% packet loss).
## Performance Impact
Through extensive ns-3 simulations, we proved that this architecture drops the adversary's total tracking kill-chain success rate from **100% to 1.25%**, with:
*   **0.00%** Packet Loss
*   **0.00%** Throughput Degradation
*   **< 0.05ms** Latency Overhead (O(1) Hash Map AP resolution)
---
## Repository Structure & Installation Guide
To run this simulation on a Linux machine, you must copy the files from this repository into specific directories inside your root `ns-3` folder (e.g., `ns-3.41/` or `ns-3.42/`).
### 1. Core Algorithm Implementation
Place these two files into the Wi-Fi module's model directory:
*   **Destination:** `ns-3.xx/src/wifi/model/`
*   **Files to copy:** 
    *   `mac-rerandomization-manager.cc`
    *   `mac-rerandomization-manager.h`
*(Note: You will also need to manually add `mac-rerandomization-manager.cc` to the `CMakeLists.txt` file inside the `src/wifi/` directory so the compiler knows to build it).*
### 2. The Network Simulation Script
Place the simulation topology script into the scratch directory:
*   **Destination:** `ns-3.xx/scratch/`
*   **File to copy:** `wisec24-mac-randomization.cc`
### 3. The Python Evaluation Script
Place the data evaluation script into the root directory of your ns-3 installation:
*   **Destination:** `ns-3.xx/`
*   **File to copy:** `evaluate_metrics.py`
---
## How to Run
1. Navigate to the root directory of your `ns-3` installation in your Linux terminal:
   ```bash
   cd ~/ns-3.xx/
2. Reconfigure and build ns-3 so it compiles the new Wi-Fi C++ models:
bash


./ns3 configure
./ns3 build
3. Run the MAC Randomization simulation:
bash


./ns3 run scratch/wisec24-mac-randomization
4. Once the simulation completes, it will generate XML and PCAP files in your root directory. Run the Python script to analyze the data and generate the graphs:
bash


python3 evaluate_metrics.py
