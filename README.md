# RUSHB-Protocol
Created a multi-client UDP server that uses a HTTP-like stop-and-wait protocol in conjunction with some ideas of RDT (Reliable Data Transfer) protocols.
The server responds to GET requests from the client with the data from the requested file.

Requires scapy 

RUSHBSvr.py  
Usage: python3 RUSHBSvr.py  
Output: Port used.  

RUSHBSampleClient.py
Usage: python3 RUSHBSampleClient.py client_port server_port [-v verbose] [-m mode] [-o output]
For example, if you want to run your client on port 11111, your server port number is assigned at 54376, you want to see the payload sent or received, with associated timeline:
python3 RUSHBSampleClient.py 11111 54376 -v 3 -m SIMPLE

There are some behaviours mode you can use with [-m mode]:

SIMPLE = [Send GET, ... work normally until the rest of the packets]

NAK = [Send GET, Send NAK, ... work normally until the rest of the packets]

MULTI_NAK = [Send GET, Send NAK, Send NAK, Send NAK, ... work normally until the rest of the packets]

TIMEOUT = [Send GET, Drop the DAT received, ... work normally until the rest of the packets]

MULTI_TIMEOUT = [Send GET, Drop the DAT received, Send NAK, Drop the DAT received, ... work normally until the rest of the packets]

INVALID_SEQ = [Send GET, Send packet with an invalid seq#, ... work normally until the rest of the packets]

INVALID_ACK = [Send GET, Send packet with an invalid ack#, ... work normally until the rest of the packets]

INVALID_FLAGS = [Send GET, Send packet with an invalid flag#, ... work normally until the rest of the packets]

CHECKSUM = [Send GET with CHK, ... work normally until the rest of the packets]

INVALID_CHECKSUM_VAL = [Send GET with CHK but use faulty checksum value, ... work normally until the rest of the packets]

INVALID_CHECKSUM_FLAG = [Send GET with CHK, Send packet with CHK not set, ... work normally until the rest of the packets]