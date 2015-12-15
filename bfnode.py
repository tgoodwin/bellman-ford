"""
bfnode.py by Tim Goodwin
CSEE4119
Programming Assignment 3
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
import signal

RECV_BUFFER = 4096
INFINITY = float('inf')
self_id = ""
closed = False
neighbors = {}      # maps neighbor nodes to the neighbor node's routing table
routing_table = {}  # maps node_id to each node's dictionary.
                    # each dictionary value holds 2 keys: 'cost' and 'next'
adjacent_links = {} # maps neighbor_id to edge cost for every link in topography
old_links = {}      # maps previously active neighbor nodes to their link costs
active_hist = {}    # for the timer
dead_links = []     # node pairs for link taken offline by either node

# UDP read socket
recvSock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

def main():
    global self_id
    if (len(sys.argv) < 3):
        print "usage: bfnode.py <localport> <timeout> <[id_addr1 port1 weight1...]>"
        sys.exit()

    localport = int(sys.argv[1])
    recvSock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    recvSock.bind(('', localport))
    signal.signal(signal.SIGINT, close_handler)
    host = socket.gethostbyname(socket.gethostname())
    self_id = str(host) + ":" + sys.argv[1]
    time_out = int(sys.argv[2])

    #initialize links from command line input
    if ((len(sys.argv) - 3) % 3) != 0:
        print "invalid link inputs (each link requires 3 parameters)."
        sys.exit()

    for i in range(3, len(sys.argv) - 1, 3):
        # test against use of 'localhost' or other hostname mappings
        n_ip = socket.gethostbyname(sys.argv[i])
        neighbor_id = str(n_ip) + ":" + sys.argv[i + 1]
        routing_table[neighbor_id] = {} #initialize empty dictionary

        routing_table[neighbor_id]['cost'] = float(sys.argv[i + 2])
        routing_table[neighbor_id]['next'] = neighbor_id
        adjacent_links[neighbor_id] = float(sys.argv[i + 2])
        neighbors[neighbor_id] = {} # initialize a routing table here

    print "bfnode.py started on " + str(localport)
    timer_update(time_out)
    node_checker(time_out)
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
            if sock == recvSock:
                data, addr = recvSock.recvfrom(RECV_BUFFER)
                if data:
                    msg = json.loads(data)
                    msg_handler(msg, addr)
                else:
                    print "NO DATA, this connection broke. dang."
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
    sys.stdout.write('> ')
    sys.stdout.flush()

def update_neighbor(): #send this node's routing table to all neighbors
    for neighbor in copy.deepcopy(neighbors): # string ID's in format "<ip>:<port>"
        temp = neighbor.split(':')
        addr = (temp[0], int(temp[1]))

        send_dict = {'type': 'update', 'routing_table': {}, }
        rt_copy = copy.deepcopy(routing_table)
        for node in rt_copy: #our own routing table
            send_dict['routing_table'][node] = rt_copy
            #using copy.deepcopy to keep this code thread-safe

            #-- POISONED REVERSE --#
            if node != neighbor and rt_copy[node]['next'] == neighbor:
                send_dict['routing_table'][node]['cost'] = INFINITY

        recvSock.sendto(json.dumps(send_dict), addr)

def timer_update(timeout_interval):
    update_neighbor()
    t = threading.Timer(timeout_interval, timer_update, [timeout_interval])
    t.setDaemon(True)
    t.start()

# check to see if nodes have "timed out"
def node_checker(timeout_interval):
    for neighbor in copy.deepcopy(neighbors):
        if neighbor in active_hist:
            t_threshold = (3 * timeout_interval)
            if ((int(time.time()) - active_hist[neighbor]) > t_threshold):
                print "Dead node found: " + str(neighbor)
                if routing_table[neighbor]['cost'] != INFINITY:
                    routing_table[neighbor]['cost'] = INFINITY
                    routing_table[neighbor]['next'] = "n/a"
                    del neighbors[neighbor]

                    # reinitialize table
                    for node in routing_table:
                        if node in neighbors:
                            routing_table[node]['cost'] = adjacent_links[node]
                            routing_table[node]['next'] = node
                        else:
                            routing_table[node]['cost'] = INFINITY
                            routing_table[node]['next'] = "n/a"
                    send_dict = { 'type': 'close', 'target': neighbor }

                    for neighbor in neighbors:
                        temp = neighbor.split(':')
                        recvSock.sendto(json.dumps(send_dict), (temp[0], int(temp[1])))

                else:
                    update_neighbor()

    t = threading.Timer(1, node_checker, [timeout_interval])
    t.setDaemon(True)
    t.start()

def cmd_handler(args):

    if args[0] == "LINKDOWN":
        if len(args) == 3:
        #    try:
        #        ip = socket.gethostbyname(args[1])
        #        linkdown(ip, args[2])
        #    except:
            linkdown(args[1], args[2])

        else:
            print "[ERROR] incorrect number of args for 'LINKDOWN' command."

    elif args[0] == "LINKUP":
        if len(args) == 3:
            linkup(args[1], args[2])
        else:
            print "[ERROR] incorrect number of args for 'LINKUP' command."

    elif args[0] == "SHOWRT":
        show_rt(routing_table)

    elif args[0] == "CLOSE":
        close()

def msg_handler(rcv_data, tuple_addr):
    global self_id
    table_changed = False
    t_now = int(time.time())
    addr = str(tuple_addr[0]) + ":" + str(tuple_addr[1])

    # ------------------ received table update ---------------------- #
    if rcv_data['type'] == 'update':
    #    print "DEBUG: [received UPDATE message from %s]" % str(tuple_addr)
        active_hist[addr] = t_now

        # update our existing neighbor table for this address
        if addr in neighbors:
        #    print "update from neighbor: " + str(addr)
            neighbors[addr] = rcv_data['routing_table']

        if addr in routing_table:
            # known node comes online, not necessarily neighbor
            if routing_table[addr]['cost'] == INFINITY:
                routing_table[addr]['cost'] = adjacent_links[addr]
                routing_table[addr]['next'] = addr
                table_changed = True
                # online node was a former neighbor
                if addr in adjacent_links:
                    neighbors[addr] = rcv_data['routing_table']

        # node in network, not necessarily an immediate neighbor
        # up to this point unknown to us
        #print "my table: " + str(routing_table)
        #print "received table:" + str(rcv_data['routing_table'])

        # they know us but we don't know them yet
        elif rcv_data['routing_table'].has_key(self_id):
            routing_table[addr] = {} #new entry
            routing_table[addr]['cost'] = rcv_data['routing_table'][self_id]['cost'] #ERROR HERE
            routing_table[addr]['next'] = addr
            table_changed = True

            # new node enters the network as immediate neighbor
            if rcv_data['routing_table'][self_id]['next'] == self_id:
                neighbors[addr] = rcv_data['routing_table']
                adjacent_links[addr] = rcv_data['routing_table'][self_id]['cost']
        else:
                print "Should not happen. Potential error in usage."
                sys.exit()

        for node in rcv_data['routing_table']:
            if node != self_id:

                # discover a new node that entered network regardless of if this node has contacted us directly
                if node not in routing_table:
                    print node + " was NOT in routing table before"
                    routing_table[node] = {
                    'cost': INFINITY,
                    'next': "n/a"
                    }
                    table_changed = True

                # --- BELLMAN FORD ALGORITHM ---
                for dest in routing_table:
                    old_cost = routing_table[dest]['cost']
                    #if addr in neighbors: if dest in neighbors[addr]:???
                    # errrorr in node check thread
                    if addr in neighbors and dest in neighbors[addr]:
                        new_cost = routing_table[addr]['cost'] + neighbors[addr][dest]['cost']

                        if new_cost < old_cost:
                            routing_table[dest]['cost'] = new_cost
                            routing_table[dest]['next'] = addr
                            table_changed = True

            if table_changed:
                update_neighbor()
                table_changed = False

    # ------------ RECEIVED LINKUP MESSAGE -------------- #
    elif rcv_data['type'] == 'linkup':
        print "DEBUG: [received LINKUP message from %s]" % str(tuple_addr)
        link_known = False
        active_hist[addr] = t_now
        pair = rcv_data['pair']
        temp = pair.split(',')
        alt_pair = str(temp[1]) + "," + str(temp[0])

        if pair in dead_links:
            dead_links.remove(pair)
            link_known = True
        elif alt_pair in dead_links:
            dead_links.remove(alt_pair)
            link_known = True

        if link_known:
            print "removed from dead_links :)"
            if temp[0] == addr and temp[1] == self_id: # someone sent to ME
            #    del old_links[addr]
                routing_table[addr]['cost'] = old_links[addr]
                routing_table[addr]['next'] = addr
                neighbors[addr] = {} # reinitialize their table
                print "ok passing on linkup"
                del old_links[addr]
                send_dict = { 'type': 'linkup', 'pair': pair, }
                tell_neighbor(recvSock, send_dict)
        else:
            update_neighbor()

    # ------------ RECEIVED LINKDOWN MESSAGE -------------- #
    elif rcv_data['type'] == 'linkdown':
        print "DEBUG: [received LINKDOWN message from %s]" % str(tuple_addr)
        active_hist[addr] = t_now
        link_known = False
        pair = rcv_data['pair']
        print "link taken down: " + str(pair)

        if pair in dead_links:
            print "updating neighbor, nothing new."
            update_neighbor() # nothing new
        else:
            dead_links.append(pair)
            temp = pair.split(',')
            if temp[0] == addr and temp[1] == self_id: #relevant to this node
                print "LINKDOWN RECEIPT WORKING"
                old_links[addr] = adjacent_links[addr]
                routing_table[addr]['cost'] = INFINITY
                routing_table[addr]['next'] = "n/a"
                if addr in neighbors:
                    del neighbors[addr]
            #else: linkdown pair not one of my adjacent links
                # wait for neighbor's routing table updates

            for node in routing_table:
                if node in neighbors:
                    routing_table[node]['cost'] = adjacent_links[node]
                    routing_table[node]['next'] = node

                else:
                    routing_table[node]['cost'] = INFINITY
                    routing_table[node]['next'] = "n/a"

            send_dict = { 'type': 'linkdown', 'pair': pair, }

            tell_neighbor(recvSock, send_dict)

    # ------------ RECEIVED CLOSE MESSAGE --------------------- #
    elif rcv_data['type'] == 'close': #this works fine for some reason

        print "DEBUG: [received CLOSE message from %s]" % str(tuple_addr)
        active_hist[addr] = t_now
        close_node = rcv_data['target']
        if routing_table[close_node]['cost'] != INFINITY:
            routing_table[close_node]['cost'] = INFINITY
            routing_table[close_node]['next'] = "n/a"

            if close_node in neighbors:
                del neighbors[close_node]

        #reinitialize routing table
            for node in routing_table:
                if node in neighbors:
                    routing_table[node]['cost'] = adjacent_links[node]
                    routing_table[node]['next'] = node
                else:
                    routing_table[node]['cost'] = INFINITY
                    routing_table[node]['next'] = "n/a"

                    send_dict = { 'type': 'close', 'target': close_node, }
                    tell_neighbor(recvSock, send_dict)

        else:
            update_neighbor()

def close_handler(signum, frame):
    #print "signal " + str(signum) + " called, closing down."
    #close()
    sys.exit("signal " + str(signum) + " called, closing down.")

# ---------------------------------------------------------------
#                  - METHODS FOR USER COMMANDS -
# ---------------------------------------------------------------

def linkdown(ip_addr, port):
    global self_id
    node_id = str(ip_addr) + ":" + str(port)
    print "linkdown: " + node_id + '\n'
    for n in neighbors: print n
    if node_id not in neighbors:
        print "[ERROR] %s is not a neighbor." % node_id
    else:
        cost = adjacent_links[node_id]
        print "cost of offline link: " + str(cost)
        old_links[node_id] = cost #this is not working
        print "in dict: " + str(old_links[node_id])

        # reinitialize this node's routing table
        for node in routing_table:
            if routing_table[node]['next'] == node_id:
                if node in neighbors: #if immediately adjacent
                    routing_table[node]['cost'] = adjacent_links[node]
                    routing_table[node]['next'] = node #self
                    #no longer pathing through 'node_id' cause it's offline

                else:
                    routing_table[node]['cost'] = INFINITY
                    routing_table[node]['next'] = "n/a"

        pair_key = str(self_id) + "," + str(node_id)
        dead_links.append(pair_key)
        send_dict1 = { 'type': 'linkdown', 'pair': pair_key }
        tell_neighbor(recvSock, send_dict1)
        del neighbors[node_id]

def linkup(ip_addr, port):
    global self_id
    node_id = str(ip_addr) + ":" + str(port)
    if node_id not in old_links:
        print "[Error] This link does not exist."

    else:
        routing_table[node_id]['cost'] = old_links[node_id]
        del old_links[node_id]
        routing_table[node_id]['next'] = node_id
        neighbors[node_id] = {} # reinitialize routing table for this node
                                # and wait for it to report to us
        pair_one = self_id + "," + node_id
        pair_two = node_id + "," + self_id

        if (pair_one)  in dead_links:
            dead_links.remove(pair_one)
        elif (pair_two) in dead_links:
            dead_links.remove(pair_two)

        send_dict2 = { 'type': 'linkup', 'pair': pair_one, }
        tell_neighbor(recvSock, send_dict2)

def show_rt(routin_table):
    print "SIZE " + str(len(routin_table))
    t_log = time.strftime('%H:%M:%S', time.localtime(time.time()))
    print str(t_log) + " [%s] Distance vector list is:" % self_id
    for node in routing_table:
        link = routing_table[node]['next']
        print "Destination = (" + str(node) + "), Cost = " + str(routing_table[node]['cost']) + ", Link = " + '(' + link + ')'

    print "NEIGHBORS: "
    for n in neighbors:
        print n
    print "---"
    print "DOWN NEIGHBORS"
    for d in old_links:
        print d

def tell_neighbor(sock, payload):
    #print "\nSENDING THIS TYPE: " + str(payload['type'])
    package = json.dumps(payload)
    for neighbor in neighbors:
        temp = neighbor.split(":")
        sock.sendto(package, (temp[0], int(temp[1])))

def close():
    global self_id
    global closed
    if not closed:
        send_dict = { 'type': 'close', 'target': self_id, }
    #    tell_neighbor(recvSock, send_dict)
        closed = True
    sys.exit()

if __name__ == "__main__":
    main()
