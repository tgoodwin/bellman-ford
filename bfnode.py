"""
bfnode.py by Tim Goodwin
CSEE4119
Programming Assignment 3
u got it here
"""

import sys
import socket
import select
import json
import threading
import time
import datetime
import copy
import os
import base64

RECV_BUFFER = 4096

neighbors = {}     # maps neighbor nodes to the neighbor node's routing table
neighbor_socks = []
routing_table = {} # maps node_id to each node's dictionary.
                   # each dictionary value holds 2 keys: 'cost' and 'next'
my_links = {}      # maps neighbor_id to edge cost for every link in topography
old_links = {}     # maps previously active neighbor nodes to their link costs
active_hist = {}   # for the timer
link_downs = []    # node pairs where link has been taken offline by either node

# UDP read socket
recvSock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
recvSock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

# UDP write socket, this is technically redundant.
sendSock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

def main():
    if (len(sys.argv) < 3):
        print "usage: bfnode.py <localport> <timeout> <[id_addr1 port1 weight1...]>"
        sys.exit()

    localport = int(sys.argv[1])
    recvSock.bind(('', localport))

    # This is who you are  -------------------------
    host = socket.gethostbyname(socket.gethostname())
    self_node = (host, str(sys.argv[1]))
    # ----------------------------------------------

    # this is how long you last
    time_out = int(sys.argv[2])

    #initialize links from command line input
    if ((len(sys.argv) - 3) % 3) != 0:
        print "invalid link inputs (each link requires 3 parameters)."
        sys.exit()

    for i in range(3, len(sys.argv) - 1, 3):

        # test against use of 'localhost' or other hostname mappings
        neighbor_ip = socket.gethostbyname(sys.argv[i])
        neighbor_id = (neighbor_ip, int(sys.argv[i + 1]))

        print "adding: " + str(neighbor_id)

        routing_table[neighbor_id] = {} #initialize empty dictionary
        routing_table[neighbor_id]['cost']= float(sys.argv[i + 2])
        routing_table[neighbor_id]['next'] = neighbor_id
        my_links[neighbor_id] = float(sys.argv[i + 2])

        neighbors[neighbor_id] = {} # initialize a routing table here

    print "bfnode.py started on " + str(localport)
    timer_update(time_out)
    #node_timer()

    #for thing in sorted(routing_table.keys()): #not necessarily sorted
    #    print thing

    prompt()

    while 1:
        socket_list = [sys.stdin, recvSock]
        #try:
        read_sockets, write_sockets, error_sockets = select.select(socket_list,[],[])

        #except select.error, e:
        #    break
    #    except socket.error, e:
    #        break

        for sock in read_sockets:

            # update received through listening socket
            if sock == recvSock:
                data, addr = recvSock.recvfrom(RECV_BUFFER) #datagram socket
                if data:
                    msg = json.loads(data)
                #    addr = (ip_addr, port)
                    msg_handler(msg, addr)
                else:
                    print "NO DATA, this connection broke."

            # user entered COMMAND on console
            else:
                data = sys.stdin.readline().rstrip()
                if len(data) > 0:
                    data_list = data.split()
                    cmd_handler(data_list)
                else:
                    sys.stdout.flush()
                prompt()

#------------------------------ END OF MAIN ---------------------------------

def prompt():
    sys.stdout.flush()
    print "> ",
    sys.stdout.flush()

def update_neighbor(): #send this node's routing table to all neighbors
    print '\n'
    for neighbor in neighbors:
        addr, port = neighbor

        send_dict = dict({
        'type': 'update', 'rt': {}
        })

        for node in routing_table: #our own routing table
            send_dict['rt'][str(node)] = copy.deepcopy(routing_table[node])
            #using copy.deepcopy to keep this code thread-safe

            if node != neighbor and routing_table[node]['next'] == neighbor:
                send_dict['rt'][str(node)]['cost'] = float('inf')

        send_addr = (addr, int(port))
        print "sending to: " + str(send_addr)
        recvSock.sendto(json.dumps(send_dict), send_addr)
    #
    #end of loop

def timer_update(timeout_interval):
    update_neighbor()
    threading.Timer(timeout_interval, timer_update, [timeout_interval]).start()

# check to see if nodes have "timed out"
def node_checker(timeout_interval):
    for neighbor in copy.deepcopy(neighbors):
        if neighbor in active_hist:
            if ((int(time.time()) - active_hist[neighbor]) > (3*timeout_interval)):
                if routing_table[neighbor]['cost'] != float('inf'):
                    routing_table[neighbor]['cost'] = float('inf') #death
                    routing_table[neighbor]['next'] = ("","") #nobody

                    del neighbors[neighbor]

                #reinitialize our table
                for node in routing_table:
                    if node in neighbors:
                        routing_table[node]['cost'] = my_links[node]
                        routing_table[node]['next'] = node
                    else:
                        routing_table[node]['cost'] = float('inf')
                        routing_table[node]['next'] = ""


def send_neighbor(sock, send_dict):
    for neighbor in neighbors:
        ip, port = neighbor
        sock.sendto(json.dumps(send_dict), (ip, int(port)))

def cmd_handler(args): #for command line input

    if args[0] == "LINKDOWN":
        if len(args) == 3:
            linkdown(args[1], args[2])
        else:
            print "incorrect number of args for 'LINKDOWN' command."
            #prompt()

    elif args[0] == "LINKUP":
        if len(args) == 3:
            linkup(args[1], args[2])
        else:
            print "incorrect number of args for 'LINKUP' command."
        #    prompt()

    elif args[0] == "SHOWRT":
        show_rt(routing_table)


    elif args[0] == "CLOSE":
        close()


def msg_handler(rcv_data, addr):
    table_changed = False
    t_now = int(time.time())
    print "received message from " + str(addr)

    # --------------------- Received table update ---------------------------- #
    if rcv_data['type'] == "update":
        active_hist[addr] = t_now
        if routing_table.has_key(addr):
            if routing_table[addr]['cost'] == float('inf'):
                routing_table[addr]['cost'] = my_links[addr]
                routing_table[addr]['next'] = addr
                neighbors[addr] = {} #clear out old entry
                neighbors[addr] = rcv_data['routing_table']
                #THIS WILL MAKE ERROR
                #store local copy of this node's table
                table_changed = True

                for node in rcv_data['routing_table']:
                    if node != self_node:
                        if node not in routing_table:
                            routing_table[node] = {
                            'cost': float('inf'),
                            'next': ("","")
                            }
                            table_changed = True
                        # BELLMAN FORD ALGORITHM
                        for node in routing_table:
                            old_cost = routing_table[node]['cost']
                            if node in neighbors[addr]:
                                new_cost = routing_table[addr]['cost'] + neighbors[addr][node]['cost']

                                if new_cost < old_cost:
                                    routing_table[node]['cost'] = new_cost
                                    routing_table[node]['next'] = addr
                                    table_changed = True

                if table_changed == True:
                    update_neighbor()
                    table_changed = False
        else:
            print str(addr) + " is not in RT????"

    # ----- RECEIVED LINKUP MESSAGE ------- #
    if rcv_data['type'] == "linkup":
        active_hist[addr] = t_now
        #stuff
    # ----- RECEIVED LINKDOWN MESSAGE ------- #
    if rcv_data['type'] == "linkdown":
        active_hist[addr] = t_now
        #stuff
        #stuff
    # ----- RECEIVED CLOSE MESSAGE ------- #
    if rcv_data['type'] == "close":
        active_hist[addr] = t_now
        #stuff
    return

def close_handler(signum, frame):
    print "signal " + str(signum) + " called, closing down."
    sys.exit()

def transmit_dv(dv, neighbor_list):
    return

# ---------------------------------------------------------------
#                  - METHODS FOR USER COMMANDS -
# ---------------------------------------------------------------

def linkdown(ip_addr, port):
    global self_node
    global neighbors
    node_id = (str(ip_addr), str(port))
    if node_id not in neighbors:
        print "this node is not a neighbor."
    else:
        old_links[node_id] = my_links[node_id]
        del neighbors[node_id] #not ur neighbor anymore

        #reinitialize this node's routing table
        for node in routing_table:
            if routing_table[node]['next'] == node_id:
                if node in neighbors: #if immediately adjacent

                    routing_table[node]['cost'] = my_links[node]
                    routing_table[node]['next'] = node #self
                    #no longer pathing through 'node_id' cause it's offline

                else:
                    routing_table[node]['cost'] = float('inf')
                    #cannot reach it cause not an immediate neighbor
                    routing_table[node]['next'] = ("","")
                    #remove node_id from our knowledge of its knowledge

        # ---- - - - - - - - - -
    #    pair = (self_node, node_id)
    #    link_downs.append(pair)

    #    send_dict = {'type': 'linkdown', 'pair': pair, }
    #    send_neighbor(recvSock, send_dict)


def linkup(ip_addr, port):
    node_id = (str(ip_addr) ,str(port))
    if node_id not in old_links:
        print "[Error] This link does not exist."

    else:
        routing_table[node_id]['cost'] = old_links[node_id]
        del old_links[node_id]

        routing_table[node_id]['next'] = node_id #as is the case in the beginning
        neighbors[node_id] = {} # reinitialize routing table for this node

        #if (node_id, self_node)  in linkdowns
            #linkdowns.remove(node_id, self_node)
        #elif (self_node, node_id) in linkdowns
            #linkdowns.remove(self_node, node_id)

        send_dict = {}
            #type: 'linkup'
            #pair: '(self_node, node_id)'
            #weight: 'weight'

    #    send_neighbor(recvSock, send_dict)

    return
    # if ip_addr, port in neighbors (regardless of infinite cost or not)
        #change cost from infinity to previous value, use dict here to remember old values.
    #else
        #create new neighbor, add this address to neighbor list with cost

def show_rt(routin_table):
    print "SIZE " + str(len(routin_table))
    t_log = time.strftime('%H:%M:%S', time.localtime(time.time()))
    print str(t_log) + " Distance vector list is:"

    for node in routing_table:
        destination = str(node[0]) + ":" + str(node[1])
        print "1: " + str(routing_table[node]['next'][0])
        print "2: " + str(routing_table[node]['next'][1])
        link = str(routing_table[node]['next'][0]) + ":" + str(routing_table[node]['next'][1])
        print "Destination = " + str(destination) + ", Cost = " + str(routing_table[node]['cost']) + ", Link = " + '(' + link + ')'

def close():
    global self_node
#    send_dict = {'type': 'close', 'target': self_node}
#    send_neighbor(recvSock, send_dict)
    sys.exit()

if __name__ == "__main__":
    main()
