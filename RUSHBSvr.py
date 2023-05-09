#!/usr/bin/env python3
import socket
import math
import os.path
import time
from struct import *

def carry_around_add(a, b):
    c = a + b
    return (c & 0xffff) + (c >> 16)

def bin_append(a, b):
    return bin((a << len(bin(b)[2:])) + b)

def calc_checksum(message):
    byte_str =  message
    checksum = 0

    if len(byte_str) % 2 == 1:
        byte_str += b'\0'

    for i in range(0, len(byte_str), 2):
        part_sum = byte_str[i] + (byte_str[i + 1] << 8)
        checksum = carry_around_add(checksum, part_sum)

    return ~checksum & 0xffff

def main():
    connect()  



def connect():
    local_ip = "127.0.0.1"
    local_port = 0
    

    server_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM | socket.SOCK_NONBLOCK)
    server_socket.bind((local_ip, local_port))    
    print(server_socket.getsockname()[1], flush=True)
    
    process(server_socket)

class Client:
    def __init__(self, address):
        self.address = address
        self.seq_num = 0
        self.data_num = 0
        self.chunked_packets = []
        self.naks = 0
        self.valid_flags = "0010000"
        self.start_time = time.time()

    def reset_timer(self):
        self.start_time = time.time()

    def timer(self):
        return time.time() - self.start_time

    def change_seq_num(self, num):
        self.seq_num += num
    
    def change_data_num(self, num):
        self.data_num += num 

    def set_chunked_packets(self, packets):
        self.chunked_packets = packets

    def inc_naks(self):
        self.naks += 1

    def set_valid_flags(self, flags):
        self.valid_flags = flags

    def get_address(self):
        return self.address

    def get_seq_num(self):
        return self.seq_num 
    
    def get_data_num(self):
        return self.data_num
    
    def get_chunked_packets(self):
        return self.chunked_packets
    
    def get_next_packet(self):
        return self.chunked_packets[self.data_num]

    def get_naks(self):
        return self.naks

    def get_valid_flags(self):
        return self.valid_flags

def process(server_socket):
    MAX_PACKET_SIZE = 1500
    BODY_INDEX = 5
    SEQ_NUM_INDEX = 0
    ACK_NUM_INDEX = 1
    CHECKSUM_INDEX = 2
    FLAG_INDEX = 3
    VERSION_INDEX = 4
    address = None
    message = None
    clients = {}

    while True:
        timeout = False
        try:
            for client in clients.values():
                time_passed = client.timer()
                if time_passed > 4.0:
                    address = client.get_address()
                    raise socket.timeout

            message, address = server_socket.recvfrom(MAX_PACKET_SIZE)
            if address not in clients:
                clients[address] = Client(address)
        except socket.timeout:
            if address is not None and address in clients:
                timeout = True
            else: 
                continue
        except socket.error:
            continue
        print("address: " + str(address))
        cli = clients[address]

        data = unpack('!HHHBB1464s', message)
        header = data[0:BODY_INDEX]
        body = data[BODY_INDEX].decode().rstrip('\x00')  
        #print("body:" + body)
        client_sequence_num = int(header[SEQ_NUM_INDEX])
        client_ack_num = int(header[ACK_NUM_INDEX])
        bin_flags = format(round(header[FLAG_INDEX] / 2), 'b').rjust(7, "0")
        ack, nak, get, dat, fin, chk, enc = [int(x) for x in 
                list(bin_flags)]
        
        if  (nak and bin_flags == ("01" + cli.get_valid_flags()[2:])) or timeout:
            cli.inc_naks()
            cli.change_data_num(-1)
            if not cli.get_seq_num():
                cli.change_seq_num(1)
            if cli.get_data_num() < 0:
                cli.change_data_num(1)
            else:
                server_socket.sendto(cli.get_next_packet(), address)
                cli.reset_timer()
                cli.change_data_num(1)
            cli.set_valid_flags("10" + cli.get_valid_flags()[2:])
            continue
            
         

        if header[FLAG_INDEX] % 2 == 1 or header[VERSION_INDEX] != 2 or (chk and calc_checksum(data[BODY_INDEX]) != header[CHECKSUM_INDEX]) or client_sequence_num > (cli.get_seq_num() + 1 + cli.get_naks()) or client_ack_num != cli.get_seq_num() or (bin_flags != cli.get_valid_flags() and (cli.get_seq_num() or bin_flags != "0010010")):
            #print(cli.get_valid_flags())
            continue
        
        

        if get:
            cli.set_chunked_packets(pack_data(body, cli.get_seq_num(),
                    client_sequence_num, chk))

            if cli.get_chunked_packets() == -1:
                del clients[address]
            else:
                #print(address)
                server_socket.sendto(cli.get_next_packet(), address)
                cli.reset_timer()
                cli.change_data_num(1)
                cli.change_seq_num(1)
                if chk:
                    cli.set_valid_flags("1001010")
                else:
                    cli.set_valid_flags("1001000") 

        if dat and ack:
            default_flag = "0000100"
            checksum = 0
            if chk:
                default_flag = "0000110"
                checksum = calc_checksum("".encode())
                
            if cli.get_data_num() >= len(cli.get_chunked_packets()):
                cli.change_seq_num(1)
                server_socket.sendto(pack("!HHHH1464s", cli.get_seq_num(),
                        0, int(checksum), int(default_flag + 6 * "0" 
                        + "010", 2), "".encode()), address)
                cli.reset_timer()
                if chk:
                    cli.set_valid_flags("1000110")
                else:
                    cli.set_valid_flags("1000100")
            else:
                cli.change_seq_num(1)
                server_socket.sendto(cli.get_next_packet(), address)
                cli.reset_timer()
                cli.change_data_num(1)

                if chk:
                    cli.set_valid_flags("1001010")
                else:
                    cli.set_valid_flags("1001000")
        
        if fin and ack:
            default_flag = "1000100"
            checksum = 0
            if chk:
                default_flag = "1000110"
                checksum = calc_checksum("".encode())
            cli.change_seq_num(1)
            server_socket.sendto(pack("!HHHH1464s", cli.get_seq_num(),
                    client_sequence_num, int(checksum), int(default_flag + 6 * "0" 
                    + "010", 2), "".encode()), address)
            
            del clients[address]
            #print("194")

        


def pack_data(filename, server_sequence_num, client_sequence_num, chk):
    chunk_size = 1464
    data_flag = 0b1000
    chk_flag = 0b10
    reserved = "000000"
    version_code = "010"
    data = ""
    chk_sum = 0
    flag = 0b0000000
    
    
    if chk:
        flag = data_flag | chk_flag
    else:
        flag = data_flag
    
    
    requested_file = ""
    if os.path.exists(filename):
        requested_file = open(filename, "r")
    else:
        return -1
    chunked_data = []


    while True:
        data = requested_file.read(chunk_size)
        if not data:
            chunked_data[-1] = chunked_data[-1][:-1]
            break
        chunked_data.append(data)
    
    requested_file.close()

    chunked_packets = []

    for data in chunked_data:
        if chk:
            chk_sum = calc_checksum(data.encode())
            
                

        server_sequence_num += 1
        #print(pack('!HHHH1464s', server_sequence_num,  
         #       client_sequence_num, int(chk_sum), int(flag * math.pow(2, 
          #      len(reserved) + len(version_code)) + int(version_code, 2)),
           #     data.encode()))
        #print(data)
        chunked_packets.append(pack('!HHHH1464s', server_sequence_num,  
                0, int(chk_sum), int(flag * math.pow(2, 
                len(reserved) + len(version_code)) + int(version_code, 2)),
                data.encode()))

    return chunked_packets


    

if __name__ == "__main__":
    main()
