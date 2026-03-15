# SR79-FW
A heuristics-driven IPS designed to bridge the gap between traditional rule-based filtering and ML-powered threat detection.

## Toolchain
1. Golang 1.21 or higher
2. Google's gopacket library (for packet capture).
3. libpcap-dev (!)

## Methodology
A self-sufficient IPS leveraging the power of machine learning creating a chokepoint between your system and the Internet.

#### Network Interface -> gopacket -> Classifiers -> Verdict

## Features
1. Combines a deterministic Rule-based Classifier with ThreatNet!, a custom Artificial Neural Network (ANN) for behavioral analysis.
2. Stateful Connection Tracking: Monitors active sessions to identify multi-stage attack patterns.

## Getting Started
### 1. Clone the repository.
>git clone https://github.com/km2795/sr79-fw.git
>cd sr79-fw

### 2. Checkout the latest commit 
>git checkout master

### 3. Setup configuration. 
>cp config.example.json config.json

### 4. Build the binary
> go build -o sr79-fw main.go

### 5. Run the IPS (you'd need elevated privileges to bind with the pcap library)
>sudo ./sr79-fw