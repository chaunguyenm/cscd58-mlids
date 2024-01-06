# Intrusion Detection System with Machine Learning

A network intrusion detection system using machine learning approach to 
identify unknown attacks in contrast to signature-based system.

This project uses 
[CICFlowMeter](https://www.unb.ca/cic/research/applications.html) to 
analyze network traffic. The machine learning model is trained using 
[IPS/IDS dataset on AWS 
(CSE-CIC-IDS2018)](https://www.unb.ca/cic/datasets/ids-2018.html).

A simulation for testing purpose is developed using ```mininet```.

## Installation

Install [Docker](https://docs.docker.com/get-docker/).

Clone the repository to local machine. The Docker images to run this 
project are located in ```src```.

```bash
git clone https://github.com/chaunguyenm/cscd58-mlids.git
```

In ```src```, build and run the Docker images.

```bash
docker-compose up
```
