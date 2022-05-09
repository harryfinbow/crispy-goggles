# crispy-goggles

**Command and Control (C2) beaconing network testbed and real-time detection system.**

## Building the containers

### Real-time Detector

`docker build -t goggles/detector -f Dockerfile.detector .`

### Command and Control Server

`docker build -t goggles/server -f Dockerfile.server .`

### Benign Traffic Generator
`docker build -t goggles/benign -f Dockerfile.benign .`

### Compromised Devices
`docker build -t goggles/compromised -f Dockerfile.compromised .`

## Running the testbed
To run the testbed with the real-time traffic detector:

`docker compose up --scale tcpdump=0 --scale compromised=10 --scale benign=10`

To run the testbed to generate datasets:

`docker compose up --scale detector=0 --scale compromised=10 --scale benign=10`

