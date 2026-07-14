# LAN Scout

LAN Scout is a simple Python tool that scans a local network for active devices and checks which common ports are open.

I built it to practice Python, networking, CIDR ranges, sockets, and multithreading.

## Features

* Finds devices that respond to ping
* Attempts to find device hostnames
* Checks common TCP ports
* Supports custom port lists
* Uses multiple threads for faster scans
* Saves results as JSON or CSV
* Uses only the Python standard library

## Usage

Basic scan:

```
python lan_scout.py 192.168.1.0/24
```

Scan specific ports:

```
python lan_scout.py 192.168.1.0/24 -p 22,80,443
```

Change the number of threads:

```
python lan_scout.py 192.168.1.0/24 -t 32
```

Save the results:

```
python lan_scout.py 192.168.1.0/24 -o results.json
```

You can also combine the options:

```
python lan_scout.py 192.168.1.0/24 -t 32 -p 22,80,443 -o results.csv
```

## Testing

Run the included tests with:

```
python -m unittest test_lan_scout.py -v
```

## Requirements

* Python 3.10 or newer

## Note

Only scan networks you own or have permission to scan.
