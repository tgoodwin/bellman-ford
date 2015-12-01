"""
bfnode.py by Tim Goodwin
CSEE4119
Programming Assignment 3
u got it here
"""

import socket
import select
import sys
import signal
import json
import threading

RECV_BUFFER = 4096
TIME_OUT = 1800 # change this to the time specified on command line

neighbors = {}
routing_table = {}
active_links = {}
old_links = []
last_active = {}

recvSock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)#UDP listening socket

def main():
    if (len(sys.argv) < 3):
        print "usage: bfnode.py <localport> <timeout> <[id_addr1 port1 weight1...]>"
        sys.exit()

    localport = int(sys.argv[1])
    recvSock.bind('', localport)
    message, addr = recvSock.recvfrom(RECV_BUFFER)
    #HANDLE MESSAGE(message, addr)

    time_out = int(sys.argv[2])

    for i in range(3, len(sys.argv) - 1, 3)
        neighbor_id = argv[i] + ":" + argv[i + 1]
        routing_table[neighbor_id] = {} #empty dictionary
        routing_table[neighbor_id]['cost']= float(argv[i + 2])
        active_links[neighbor_id] = float(argv[i + 2])

        neighbors[neighbor_id] = {} #store a routing table here later

    print "client started at " + str(socket.gethostbyname(socket.gethostname())) + "on " + str(localport)
    #update_timer()
    #node_timer()
    prompt()

    while 1:
        socket_list = [sys.stdin, recvSock]
        #try:
        read_sockets, write_sockets, error_sockets = select.select(socket_list,[],[], time_out)
        #except select.error, e:
        #    break
    #    except socket.error, e:
    #        break

        for sock in read_socekts:

            """ message received through listening socket """
            if sock = recvSock:
                data, addr = recvSock.recvfrom(RECV_BUFFER) #datagram socket
                #msg = json.loads(data)
                sender = addr[0] + ":" + addr[1] #(ip_addr:port)
                msg_handler(message, sender)
                #command_handler(cmd)

            """ user entered COMMAND on console """
            else:
                data = sys.stdin.readline().strip()
                cmd_handler(data)

                return


#--------- END OF MAIN ------------

def cmd_handler(command): #for command line input
    words = command.split()
    command_word = words[0].rstrip()

    if command_word == "LINKDOWN":
        linkdown(words[1], words[2])
    elif command_word == "LINKUP":
        linkup(words[1], words[2])
    elif command_word == "SHOWRT":
        show_rt()
    elif command_word == "CLOSE":
        close()
    else:
        prompt()

def prompt():
    print >> sys.stdout, "> "
    sys.stdout.flush()

def msg_handler(message, addr):
    words = message.split()
    #if msg = a distance vector
        #run bellman-ford on own distance vector
            #if different, transmit_dv(distance_vector)
            #if not, continue
    #if receive routing table update
        #stuff
    #elif receive 'linkdown'
        #stuff
    #elif receive 'linkup'
        #stuff
    #elif receive 'close'
        #stuff
    return

def close_handler(signum, frame):
    print "signal " + str(signum) + " called, closing down."
    sys.exit()

def init_neighbors(input_list):
    for e in input_list:


def transmit_dv(dv, neighbor_list):
    return

def linkdown(ip_addr, port):
    return
    # delete node from active_neighbor dictionary

def linkup(ip_addr, port): #handle a cost parameter somehow too
    return
    # if ip_addr, port in neighbors (regardless of infinite cost or not)
        #change cost from infinity to previous value, use dict here to remember old values.
    #else
        #create new neighbor, add this address to neighbor list with cost

def show_rt():
    return

def close():
    return

if __name__ == "__main__":
    main()
