#!/usr/bin/env python3
# -*- coding: UTF-8 -*-

import argparse
import socket
import os
import sys
import struct
import time
import random
import traceback # useful for exception handling
import threading

def setupArgumentParser() -> argparse.Namespace:
        parser = argparse.ArgumentParser(
            description='A collection of Network Applications developed for SCC.203.')
        parser.set_defaults(func=ICMPPing, hostname='lancaster.ac.uk')
        subparsers = parser.add_subparsers(help='sub-command help')
        
        parser_p = subparsers.add_parser('ping', aliases=['p'], help='run ping')
        parser_p.set_defaults(timeout=4)
        parser_p.add_argument('hostname', type=str, help='host to ping towards')
        parser_p.add_argument('--count', '-c', nargs='?', type=int,
                              help='number of times to ping the host before stopping')
        parser_p.add_argument('--timeout', '-t', nargs='?',
                              type=int,
                              help='maximum timeout before considering request lost')
        parser_p.set_defaults(func=ICMPPing)

        parser_t = subparsers.add_parser('traceroute', aliases=['t'],
                                         help='run traceroute')
        parser_t.set_defaults(timeout=4, protocol='icmp')
        parser_t.add_argument('hostname', type=str, help='host to traceroute towards')
        parser_t.add_argument('--timeout', '-t', nargs='?', type=int,
                              help='maximum timeout before considering request lost')
        parser_t.add_argument('--protocol', '-p', nargs='?', type=str,
                              help='protocol to send request with (UDP/ICMP)')
        parser_t.set_defaults(func=Traceroute)
        
        parser_pt = subparsers.add_parser('paris-traceroute', aliases=['pt'],
                                         help='run paris-traceroute')
        parser_pt.set_defaults(timeout=4, protocol='icmp')
        parser_pt.add_argument('hostname', type=str, help='host to traceroute towards')
        parser_pt.add_argument('--timeout', '-t', nargs='?', type=int,
                              help='maximum timeout before considering request lost')
        parser_pt.add_argument('--protocol', '-p', nargs='?', type=str,
                              help='protocol to send request with (UDP/ICMP)')
        parser_pt.set_defaults(func=ParisTraceroute)

        parser_w = subparsers.add_parser('web', aliases=['w'], help='run web server')
        parser_w.set_defaults(port=8080)
        parser_w.add_argument('--port', '-p', type=int, nargs='?',
                              help='port number to start web server listening on')
        parser_w.set_defaults(func=WebServer)

        parser_x = subparsers.add_parser('proxy', aliases=['x'], help='run proxy')
        parser_x.set_defaults(port=8000)
        parser_x.add_argument('--port', '-p', type=int, nargs='?',
                              help='port number to start web server listening on')
        parser_x.set_defaults(func=Proxy)

        args = parser.parse_args()
        return args


class NetworkApplication:

    def checksum(self, dataToChecksum: str) -> str:
        csum = 0
        countTo = (len(dataToChecksum) // 2) * 2
        count = 0

        while count < countTo:
            thisVal = dataToChecksum[count+1] * 256 + dataToChecksum[count]
            csum = csum + thisVal
            csum = csum & 0xffffffff
            count = count + 2

        if countTo < len(dataToChecksum):
            csum = csum + dataToChecksum[len(dataToChecksum) - 1]
            csum = csum & 0xffffffff

        csum = (csum >> 16) + (csum & 0xffff)
        csum = csum + (csum >> 16)
        answer = ~csum
        answer = answer & 0xffff
        answer = answer >> 8 | (answer << 8 & 0xff00)

        answer = socket.htons(answer)

        return answer

    def printOneResult(self, destinationAddress: str, packetLength: int, time: float, ttl: int, destinationHostname=''):
        if destinationHostname:
            print("%d bytes from %s (%s): ttl=%d time=%.2f ms" % (packetLength, destinationHostname, destinationAddress, ttl, time))
        else:
            print("%d bytes from %s: ttl=%d time=%.2f ms" % (packetLength, destinationAddress, ttl, time))

    def printAdditionalDetails(self, packetLoss=0.0, minimumDelay=0.0, averageDelay=0.0, maximumDelay=0.0):
        print("%.2f%% packet loss" % (packetLoss))
        if minimumDelay > 0 and averageDelay > 0 and maximumDelay > 0:
            print("rtt min/avg/max = %.2f/%.2f/%.2f ms" % (minimumDelay, averageDelay, maximumDelay))

    def printMultipleResults(self, ttl: int, destinationAddress: str, measurements: list, destinationHostname=''):
        latencies = ''
        noResponse = True
        for rtt in measurements:
            if rtt is not None:
                latencies += str(round(rtt, 3))
                latencies += ' ms  '
                noResponse = False
            else:
                latencies += '* ' 

        if noResponse is False:
            print("%d %s (%s) %s" % (ttl, destinationHostname, destinationAddress, latencies))
        else:
            print("%d %s" % (ttl, latencies))

class ICMPPing(NetworkApplication):

    def receiveOnePing(self, icmpSocket, destinationAddress, ID, timeout):
        # 1. Wait for the socket to receive a reply
        print(f"this is the timeout{timeout}")
        start = time.time()
        while True:
            
            try:
                reply= icmpSocket.recv(1024)
                break
            
            except socket.timeout:
                return
            
        if reply:
            
            time_received = time.time()
             

        # 2. Once received, record time of receipt, otherwise, handle a timeout
        # 3. Compare the time of receipt to time of sending, producing the total network delay
        delay = (time_received - start)*1000
        #print(f'time received IS {time_received}, time start = {start}')
        # 4. Unpack the packet header for useful information, including the ID
        icmp_header = reply[20:28] #the part of the reply from index 20 - 27 is where the header information is located inmc
        type, code, checksum, p_id, seq = struct.unpack('BBHHH',icmp_header)
            
        # 5. Check that the ID matches between the request and reply
        print(f"p_id = {p_id} ID = {ID}")
        if p_id == ID:
            #print(f'id IS {ID} and PID {p_id}')
            return(delay)
        # 6. Return total network delay
        pass

    def sendOnePing(self, icmpSocket, destinationAddress, ID):
        # 1. Build ICMP header
        
        icmp_header = struct.pack("BBHHH",8,0,0,ID,1) #the format of the header from wireshark

        # 2. Checksum ICMP packet using given function
        my_checksum = self.checksum(icmp_header)
        # 3. Insert checksum into packet
        icmp_header = struct.pack("BBHHH",8,0,my_checksum,ID,1)
        # 4. Send packet using socket
        icmpSocket.sendto(icmp_header,(destinationAddress,1))
        # 5. Record time of sending
        sending_time = time.time()
        pass

    def doOnePing(self, destinationAddress, timeout):
        # 1. Create ICMP socket
        icmp_socket = socket.socket(socket.AF_INET,socket.SOCK_RAW,socket.IPPROTO_ICMP)
        # 2. Call sendOnePing function
        ID = random.randint(1,10000)
        self.sendOnePing(icmp_socket,destinationAddress,ID)
        # 3. Call receiveOnePing function
        total_delay = self.receiveOnePing(icmp_socket,destinationAddress, ID, timeout) 
        # 4. Close ICMP socket
        icmp_socket.close()
        # 5. Return total network delay
        return total_delay
        pass


            

    

    def __init__(self, args):   
        counter = 0
        print('Ping to: %s...' % (args.hostname))
        # 1. Look up hostname, resolving it to an IP address
        ip_address = socket.gethostbyname(args.hostname)

        # 2. Call doOnePing function, approximately every second
        while True:

            time =  self.doOnePing(ip_address,1)
        # 3. Print out the returned delay (and other relevant details) using the printOneResult method
            self.printOneResult(ip_address,50,time, 150, 'lancaster.ac.uk') # Example use of printOneResult - complete as appropriate
            counter+=1
            if counter == 6:
                break
            

        # 4. Continue this process until stopped


class Traceroute(NetworkApplication):

    def printAdditionalDetails(self, packetLoss=0.0, minimumDelay=0.0, averageDelay=0.0, maximumDelay=0.0):
        print("%.2f%% packet loss" % (packetLoss))
        if minimumDelay > 0 and averageDelay > 0 and maximumDelay > 0:
            print("rtt min/avg/max = %.2f/%.2f/%.2f ms" % (minimumDelay, averageDelay, maximumDelay))




    def printOneResult(self, destinationAddress: str, packetLength: int, time: float, ttl: int, destinationHostname=''):
        if destinationHostname:
            print("%d bytes from %s (%s): ttl=%d time=%.2f ms" % (packetLength, destinationHostname, destinationAddress, ttl, time))
        else:
            print("%d bytes from %s: ttl=%d time=%.2f ms" % (packetLength, destinationAddress, ttl, time))

    def receiveOnePing(self, icmpSocket, destinationAddress, ID, timeout):
        # 1. Wait for the socket to receive a reply
        
        print(f"this is timeout =  {timeout}")
        start = time.time()
        
        try:
            reply,address= icmpSocket.recvfrom(1024)
            
               
        except socket.timeout:
            print("*")
            packet_loss = True
            return(4,None,0,packet_loss)
            
        if reply:
            time_received = time.time()
             

        # 2. Once received, record time of receipt, otherwise, handle a timeout
        # 3. Compare the time of receipt to time of sending, producing the total network delay
        delay = (time_received - start)*1000
        #print(f'time received IS {time_received}, time start = {start}')
        # 4. Unpack the packet header for useful information, including the ID
        destination = reply[16:20]
        destination_address = socket.inet_ntoa(destination)
        #print(f"destination ip = {destination_address}")
        id2= reply[52:54]
        icmp_header = reply[20:28] #the part of the reply from index 20 - 27 is where the header information is located inmc
        type, code, checksum, p_id, seq = struct.unpack('BBHHH',icmp_header)
        
        if(type ==11):

            id_2,= struct.unpack('H',id2)

            
            

        else:
            id_2 = p_id
       
        print(f"id = {id_2} and ID = {ID}")
        packet_loss = False
       
        
        if(type == 11 and id_2 == ID):

            
            
            return(delay,address[0],0,packet_loss)
        
        elif type == 0:
            return(delay,address[0],1,packet_loss)
        print(f"this does not work")
        pass

    def sendOnePing(self, icmpSocket, destinationAddress, ID):
        # 1. Build ICMP header
        
        icmp_header = struct.pack("BBHHH",8,0,0,ID,1) #the format of the header from wireshark

        # 2. Checksum ICMP packet using given function
        my_checksum = self.checksum(icmp_header)
        icmp_header = struct.pack("BBHHH",8,0,my_checksum,ID,1)
        # 3. Insert checksum into packet
        # 4. Send packet using socket        icmp_header = struct.pack("BBHHH",8,0,my_checksum,ID,1)

        icmpSocket.sendto(icmp_header,(destinationAddress,1))
        # 5. Record time of sending
        sending_time = time.time()
        pass

    def doOnePing(self, destinationAddress, timeout, ttl):
        # 1. Create ICMP socket
        try:

            icmpSocket = socket.socket(socket.AF_INET,socket.SOCK_RAW,socket.IPPROTO_ICMP)
            icmpSocket.setsockopt(socket.SOL_IP, socket.IP_TTL, ttl)
            icmpSocket.settimeout(timeout)
        except socket.error as e:
            raise
        # 2. Call sendOnePing function
        ID = random.randint(1,10000)
        self.sendOnePing(icmpSocket,destinationAddress,ID)
        # 3. Call receiveOnePing function
        total_delay, address, info, packet_loss= self.receiveOnePing(icmpSocket,destinationAddress, ID, timeout) 
        # 4. Close ICMP socket
        icmpSocket.close()
        # 5. Return total network delay
        return total_delay,address,info,packet_loss
        pass
    
    def printMultipleResults(self, ttl: int, destinationAddress: str, measurements: list, destinationHostname=''):
        latencies = ''
        noResponse = True
        for rtt in measurements:
            if rtt is not None:
                latencies += str(round(rtt, 3))
                latencies += ' ms  '
                noResponse = False
            else:
                latencies += '* ' 

        if noResponse is False:
            print("%d %s (%s) %s" % (ttl, destinationHostname, destinationAddress, latencies))
        else:
            print("%d %s" % (ttl, latencies))





    def __init__(self, args):
        
        print('Traceroute to: %s...' % (args.hostname))
        ip_address = socket.gethostbyname(args.hostname)
        
        # 2. Create ICMP socket
        

        # 3. Begin a for loop that increments the TTL from 0 to 30
        for ttl in range(1,31):
            # 4. Set the TTL value
            #print(f"TTL = {ttl}")
            results = []
            packets = []
            for i in range(0,3):

                try:

                    times,address,info,packet_loss= self.doOnePing(ip_address,args.timeout,ttl)
                    #address_name = socket.gethostbyaddr(address)
                except TypeError:
                    times = 0
                    adress = None


                #print(f"ip_address = {address}, ")
                results.append(times)
                packets.append(packet_loss)
                #
                #self.printOneResult(address,50,times,ttl,address)
            
            print(f"address = {address}")   
            if times == None:
                
                print("*******")
            try:
                address_name = socket.gethostbyaddr(address)
                name_final = address_name[0]
            except:
                
                name_final = None      
            if info ==1:
                name_final = socket.gethostbyaddr(ip_address)[0]

            counter1 = 0
             
            for boolean in packets:
                
                if boolean == False:
                    counter1+=1
            packetloss = (3-counter1)/3

            min_delay = min(results)
            max_delay = max(results)
            average_delay = sum(results)/len(results)  
            

            self.printMultipleResults(ttl,address,results,name_final)
            self.printAdditionalDetails(packetloss,min_delay,average_delay,max_delay)
            if address == ip_address:
                break
            
            
            
       
                

class ParisTraceroute(NetworkApplication):
    
    def sendOnePing(self, udpSocket, destinationAddress, ID):
        # 1. Build UDP
        packetData = ID.to_bytes(2,'big')
        sPort = 33457
        dPort = 33456
        
        #length = 8 + (len(packetData))
        #checksum = 0
        #udp_header = struct.pack("!HHHH",sPort,dPort,length,checksum) #the format of the header from wireshark

        # 2. Checksum UDP packet using given function
        my_checksum = self.checksum(packetData)
        #udp_header = struct.pack("!HHHH",sPort,dPort,length,my_checksum)
        # 3. Insert checksum into packet
        # 4. Send packet using socket        icmp_header = struct.pack("BBHHH",8,0,my_checksum,ID,1)

        udpSocket.sendto(packetData,(destinationAddress,dPort))
        # 5. Record time of sending
        sending_time = time.time()
        pass

    def sendOnePingICMP(self, icmpSocket, destinationAddress, ID):

        # 1. Build ICMP header
        
        icmp_header = struct.pack("BBHHH",8,0,0,ID,1) #the format of the header from wireshark

        # 2. Checksum ICMP packet using given function
        my_checksum = self.checksum(icmp_header)
        icmp_header = struct.pack("BBHHH",8,0,my_checksum,ID,1)
        # 3. Insert checksum into packet
        # 4. Send packet using socket        icmp_header = struct.pack("BBHHH",8,0,my_checksum,ID,1)

        icmpSocket.sendto(icmp_header,(destinationAddress,1))
        # 5. Record time of sending
        sending_time = time.time()
        pass

    def doOnePing(self, destinationAddress, timeout, ttl, protocol):
        # 1. Create ICMP socket
        if protocol == 'udp':

            try:

                udpSocket = socket.socket(socket.AF_INET,socket.SOCK_DGRAM,socket.IPPROTO_UDP)
                udpSocket.setsockopt(socket.SOL_IP, socket.IP_TTL, ttl)
                #udpSocket.settimeout(timeout)
            except socket.error as e:
                raise
            # 2. Call sendOnePing function
            ID = random.randint(1,10000)
            
            self.sendOnePing(udpSocket,destinationAddress,ID)
            # 3. Call receiveOnePing function
            total_delay,address,info,packet_loss= self.receiveOnePing(destinationAddress, ID, timeout) 
            # 4. Close ICMP socket
            udpSocket.close()
            # 5. Return total network delay
            return total_delay,address,info,packet_loss
            pass
        elif protocol == 'icmp':
            try:

                icmpSocket = socket.socket(socket.AF_INET,socket.SOCK_RAW,socket.IPPROTO_ICMP)
                icmpSocket.setsockopt(socket.SOL_IP, socket.IP_TTL, ttl)
                icmpSocket.settimeout(timeout)
            except socket.error as e:
                raise
        # 2. Call sendOnePing function
            ID = random.randint(1,10000)
            self.sendOnePingICMP(icmpSocket,destinationAddress,ID)
            # 3. Call receiveOnePing function
            total_delay, address, info, packet_loss= self.receiveOnePingICMP(destinationAddress, ID, timeout) 
            # 4. Close ICMP socket
            icmpSocket.close()
            # 5. Return total network delay
            return total_delay,address,info,packet_loss
            pass
    

    def receiveOnePingICMP(self, destinationAddress, ID, timeout):
        # 1. Wait for the socket to receive a reply
        try:

            icmpSocket = socket.socket(socket.AF_INET,socket.SOCK_RAW,socket.IPPROTO_ICMP)
            #icmpSocket.setsockotp(socket.SOL_IP, socket.IP_TTL, ttl)
            icmpSocket.settimeout(timeout)
            
        except socket.error as e:
            raise
        
        start = time.time()
        
        try:
            reply,address= icmpSocket.recvfrom(4080)
            
               
        except socket.timeout:
            print("***")
            packet_loss = True
            return(4, None,0,packet_loss)
            
        if reply:
            time_received = time.time()

        


        packet_loss = False
        # 2. Once received, record time of receipt, otherwise, handle a timeout
        # 3. Compare the time of receipt to time of sending, producing the total network delay
        delay = (time_received - start)*1000
        #print(f'time received IS {time_received}, time start = {start}')
        # 4. Unpack the packet header for useful information, including the ID
        #destination = reply[16:20]
        #destination_address = socket.inet_ntoa(destination)
        #print(f"destination ip = {destination_address}")
       
        id2= reply[52:54]
        icmp_header = reply[20:28] #the part of the reply from index 20 - 27 is where the header information is located inmc
        type, code, checksum, p_id, seq = struct.unpack('BBHHH',icmp_header)
        
        if(type ==11):

            id_2,= struct.unpack('H',id2)

            
            

        else:
            id_2 = p_id
       
        print(f"id = {id_2} and ID = {ID}")
        packet_loss = False
       
        
        if(type == 11 and id_2 == ID):

            
            
            return(delay,address[0],0,packet_loss)
        
        elif type == 0:
            return(delay,address[0],1,packet_loss)
        print(f"this does not work")
        pass
        
       
        
        


            
    def receiveOnePing(self, destinationAddress, ID, timeout):
        # 1. Wait for the socket to receive a reply
        try:

            icmpSocket = socket.socket(socket.AF_INET,socket.SOCK_RAW,socket.IPPROTO_ICMP)
            #icmpSocket.setsockotp(socket.SOL_IP, socket.IP_TTL, ttl)
            icmpSocket.settimeout(timeout)
            
        except socket.error as e:
            raise
        
        start = time.time()
        
        try:
            reply,address= icmpSocket.recvfrom(4080)
            
               
        except socket.timeout:
            print("***")
            packet_loss = True
            return(4, None,0,packet_loss)
            
        if reply:
            time_received = time.time()

        


        packet_loss = False
        # 2. Once received, record time of receipt, otherwise, handle a timeout
        # 3. Compare the time of receipt to time of sending, producing the total network delay
        delay = (time_received - start)*1000
        #print(f'time received IS {time_received}, time start = {start}')
        # 4. Unpack the packet header for useful information, including the ID
        #destination = reply[16:20]
        #destination_address = socket.inet_ntoa(destination)
        #print(f"destination ip = {destination_address}")
        icmp_header = reply[20:28] #the part of the reply from index 20 - 27 is where the header information is located inmc
        type, code, checksum, p_id, seq = struct.unpack('BBHHH',icmp_header)
        
        
       
        
        if(type == 11):
            
            
            return(delay,address[0],0,packet_loss)
        
        elif type == 0 or type == 3:
            return(delay,address[0],1,packet_loss)
        
        pass

    def printMultipleResults(self, ttl: int, destinationAddress: str, measurements: list, destinationHostname=''):
        latencies = ''
        noResponse = True
        for rtt in measurements:
            if rtt is not None:
                latencies += str(round(rtt, 3))
                latencies += ' ms  '
                noResponse = False
            else:
                latencies += '* ' 

        if noResponse is False:
            print("%d %s (%s) %s" % (ttl, destinationHostname, destinationAddress, latencies))
        else:
            print("%d %s" % (ttl, latencies))

    def __init__(self, args):
        
        print('Paris raceroute to: %s...' % (args.hostname))
        ip_address = socket.gethostbyname(args.hostname)
        print(f"protocol = {args.protocol}")
        # 2. Create ICMP socket
        

        # 3. Begin a for loop that increments the TTL from 0 to 30
        for ttl in range(1,31):
            # 4. Set the TTL value
            #print(f"TTL = {ttl}")
            results = []
            packets = []
            for i in range(0,3):

                try:

                    times,address,info,packet_loss= self.doOnePing(ip_address,args.timeout,ttl,args.protocol)
                    #address_name = socket.gethostbyaddr(address)
                except TypeError:
                    print("type error")
                    times = 0
                    adress = None


                #print(f"ip_address = {address}, ")
                results.append(times)
                packets.append(packet_loss)
                #
                #self.printOneResult(address,50,times,ttl,address)
            
               
            if times == None:
                
                print("*******")
            try:
                address_name = socket.gethostbyaddr(address)
                name_final = address_name[0]
            except:
                
                name_final = None      
            if info ==1:
                name_final = socket.gethostbyaddr(ip_address)[0]

            counter1 = 0
             
            for boolean in packets:
                
                if boolean == False:
                    counter1+=1
            packetloss = ((3-counter1)/3)*100

            min_delay = min(results)
            max_delay = max(results)
            average_delay = sum(results)/len(results)  
            

            self.printMultipleResults(ttl,address,results,name_final)
            self.printAdditionalDetails(packetloss,min_delay,average_delay,max_delay)
            if address == ip_address:
                break
            
            



    
            



class WebServer(NetworkApplication):

    def handleRequest(self,tcpSocket):
        print("wrong 1")
        # 1. Receive request message from the client on connection socket
        client_request = tcpSocket.recv(10000) #1024 because that is the maximum amount of bytes of data that can be received by the socket
        
        # 2. Extract the path of the requested object from the message (second part of the HTTP header)
        request_parse = client_request.split()[1]
        
        # 3. Read the corresponding file from disk
        f = open(request_parse[1:])
        # 4. Store in temporary buffer
        response = f.read()
        f.close()
        # 5. Send the correct HTTP response error
        encodedTxt = 'HTTP/1.0 200 OK\r\n\r\n'.encode()
        tcpSocket.send(encodedTxt)
        # 6. Send the content of the file to the socket
        print("wrong2")
        #for i in range (0,len(response)):

        response = response.encode()

        tcpSocket.send(response)
        # 7. Close the connection socket
        tcpSocket.close()
        #pass

    def __init__(self, args):
        print('Web Server starting on port: %i...' % (args.port))
        # 1. Create server socket
       

        ServerSocket = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
            #print("erorr")
            # 2. Bind the server socket to server address and server port
        serverAddress = ("localhost")
        ServerSocket.bind((serverAddress,args.port))
            # 3. Continuously listen for connections to server socket
        ServerSocket.listen(1)
        while True:
            print("erorr")
            Socket,address = ServerSocket.accept()
            print("errorrrrrr")
            self.handleRequest(Socket)
            print("errorrrrrr2")
        # 4. When a connection is accepted, call handleRequest function, passing new connection socket (see https://docs.python.org/3/library/socket.html#socket.socket.accept)
        # 5. Close server socket
        ServerSocket.close()
       



   
class Proxy(NetworkApplication):

    cache = {}
    def handle_request(self,connection_sockt):
        
        
        request = connection_sockt.recv(1024).decode()
        try:
            caches_ = False
            host = request.split()[1].split('/')[2]
            port = 80
            if ':' in host:
                port = int(host.split(':')[1])
                host = host.split(':')[0]

            try:
                if host in self.cache:

                    caches_ = True
                response = self.cache[host]
                print(response)
                for i in range(0, len(response), 1024):
                    connection_sockt.send(response[i:i+1024])
                    
                
                connection_sockt.close()
                
                
            except KeyError:
                pass
            if caches_ == False:

                proxy_sockt = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

                proxy_sockt.settimeout(5)

                proxy_sockt.connect((host, port))


                proxy_sockt.send(bytes(request, "utf-8"))
                response = b""
                while True:
                    try:
                        data = proxy_sockt.recv(1024)
                        
                        if not data:
                            break
                        response += data
                    except socket.timeout:
                        break

                for i in range(0, len(response), 1024):
                    connection_sockt.send(response[i:i+1024])

                proxy_sockt.close()
                connection_sockt.close()

                if host not in self.cache:
                    self.cache[host] = response
                    for x in self.cache:
                        print(x)
                    for y in self.cache:
                        print(self.cache[y])


        except IndexError:
            connection_sockt.close()

    def __init__(self, args):
        print('Web Proxy starting on port: %i...' % (args.port))
        port = args.port
        serverSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        serverSocket.bind(('', args.port))
        serverSocket.listen(1)
        while 1:

            ConnectionSocket, addr = serverSocket.accept()
            t1 = threading.Thread(target = self.handle_request ,args = (ConnectionSocket,))
            #t1.setDaemon(True)
            t1.start()

if __name__ == "__main__":
    args = setupArgumentParser()
    args.func(args)