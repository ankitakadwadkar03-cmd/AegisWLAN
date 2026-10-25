# NetShield — AegisWLAN

NetShield is a machine-learning-based Wi-Fi intrusion detection and security monitoring system. AegisWLAN is the independent repository for its ongoing development.

## Main Components

- Wi-Fi Network Scanning
- Signal Analysis and Vendor Lookup
- Live Packet Capture
- Feature Extraction
- Machine Learning Intrusion Detection
- Attack Classification
- PCAP Analysis and ML Testing
- Security Incidents, Evidence, and Reports
- Wi-Fi Network Recommendation and Classification

## Machine Learning Systems

### AWID3 Intrusion Detector
- Random Forest model
- Frozen 31-feature schema
- Packet-level intrusion detection
- PCAP and live-capture analysis

### Wi-Fi Recommendation System
- Separate ML subsystem
- Access-point quality classification and recommendation
- Dedicated model, feature schema, and inference service

## Technology Stack

- **Frontend:** React and Vite
- **Backend:** Python and Flask
- **Machine Learning:** scikit-learn
- **Database:** SQLite
- **Target platform:** Kali Linux

## Development Notes

The AWID3 intrusion detection model and its canonical 31-feature schema are preserved separately from the Wi-Fi recommendation subsystem.

AegisWLAN is maintained as an independent Git repository. The original `NetShield-ML-WIDS` repository remains separate.
