#!/usr/bin/python
import socket
import sys
import threading

sckt = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server_address = ('10.0.0.29', 9999)
sckt.connect((server_address))


def client_send():
    while True:
        message = raw_input("Text: ")
        sckt.send(message)


def client_recv():
    while True:
        reply = sckt.recv(1024)
        print "received", repr(reply)


thread_send = []
thread_rcv = []
num_threads = 10

for loop_1 in range(num_threads):
    thread_send.append(threading.Thread(target=client_send))
    thread_send[-1].start()

for loop_2 in range(num_threads):
    thread_rcv.append(threading.Thread(target=client_recv))
    thread_rcv[-1].start()