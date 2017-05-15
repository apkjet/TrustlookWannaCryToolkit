# Trustlook WannaCry Ransomware Scanner

The Wannacry Scanner to help system admin to scan your network for vulnerable windows systems. 

## Install

This tool need to python 2.7 to run, and install the related package with:
```
pip install -r requirements.txt
```

## Usage

```
Trustlook WannaCry Ransomware Scanner
Check out our blog https://blog.trustlook.com/ for udpate

To install SEcurity Path From Microsoft:

For general windows system, download at:
https://technet.microsoft.com/en-us/library/security/ms17-010.aspx

For Windows XP, 2003, Vista and Windows 8 system, download at:
http://www.catalog.update.microsoft.com/Search.aspx?q=KB4012598

Usage: wannacry_tlscan.py [options]

Options:
  -h, --help            show this help message and exit
  -t TIMEOUT, --timeout=TIMEOUT
                        timout in seconds, default 0.5
  -n NETWORK, --network=NETWORK
                        The scan network or host
                        192.168.0.100 for single host
                        192.168.0.100/24 for a network
```

### Single host scan
`python wannacry_tlscan.py -n 192.168.1.123`

output

```
start to scan host 192.168.1.123
192.168.1.123 - system is vulnerable
```

### Single a network
`python wannacry_tlscan.py -n 192.168.1.0/24 -t 1`

output

```
start to scan network 192.168.1.0/24 for 254 hosts...
192.168.1.123 - system is vulnerable
```

## Tech details and update
Please check out Trustlook blog at [https://blog.trustlook.com/](https://blog.trustlook.com/)


## Install SEcurity Path From Microsoft

### For general windows system, download at:
[https://technet.microsoft.com/en-us/library/security/ms17-010.aspx](https://technet.microsoft.com/en-us/library/security/ms17-010.aspx)

### For Windows XP, 2003, Vista and Windows 8 system, download at:
[http://www.catalog.update.microsoft.com/Search.aspx?q=KB4012598](http://www.catalog.update.microsoft.com/Search.aspx?q=KB4012598)