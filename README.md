# Netflower: Analyse a network interface and show live bandwidth usage for every IP
![Demo](./docs/screenshots/netflower.png)

## Features
- Analyse bandwidth usage for network interface
- Split in TCP and UDP
- Send data to logstash (-l)
- Send data to file (-o)

## Prerequisites
To run Netflower, you'll need the following:
- git
- python3
- pip3

## Install 
Install dependencies from requirements.txt
```
git clone [this repository]
pip3 install -r requirements.txt
```

##  Usage
```
usage: netflower.py [-h] -i INTERFACE [-l LOGSTASH_CONFIG] [-o OUTPUT]

optional arguments:
  -h, --help            show this help message and exit
  -i INTERFACE, --interface INTERFACE
                        Interface to listen on
  -l LOGSTASH_CONFIG, --logstash_config LOGSTASH_CONFIG
                        Logstash configuration host/port in JSON format,
                        example: {"host":"localhost","port":5000}
  -o OUTPUT, --output OUTPUT
                        Write total,up,download usage to file

```

##  Example
```
sudo python3 netflower/netflower.py -i wlp2s0 # display bandwidth usage for wlp2s0 interface
```

# License
GNU AFFERO GENERAL PUBLIC LICENSE
