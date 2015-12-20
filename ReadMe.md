#Bellman-Ford
#####Timothy Goodwin,  December 2015

######A distributed, dynamic network routing algorithm implemented here in Python for truly scalable optimal-path computations. Instances of bfclient.py communicate with each other over UDP, each using a single datagram socket.

>When constructing the network topology via command line input, ensure that the IP address input for any given node is the same as what would be retuned by `socket.gethostbyname(socket.gethostname())` on that node's machine. This function call can be system dependent. See point 4(a) below for details.

###1. Description of data formats, internal data structures used by each node

  Nodes are uniquely identified by a <ip_addr, port> tuple. This program represents these node identifiers, named 'node_id', as a string with the following format:
  `<ip_adress>:<port>`

  `self_id` is a node_id string with the host and port the bfclient instance is running on.

  `neighbors = {}` maps neighbor nodes to the neighbor node's routing table

  `routing_table = {}` maps node_id to each node_id's respective dictionary.

  `routing_table[node_id]`
  Each node dictionary value holds 2 keys, 'cost' and 'link'.
  The 'cost' key maps to a float type, which represents a positive edge weight.
  The 'link' key maps to a node_id which represents the "first hop" node taken by the host node to reach the node_id destination.

  `adjacent_links = {}` maps neighbor_id to edge cost for every link in topography

  `old_links = {}` maps previously active neighbor nodes to their link costs

  `active_hist = {}` maps a neighbor's node_id to the last time activity was received from that  neighbor. This is used by the node_timer thread.

  `dead_links = []` node pairs for link taken offline by either node in the pair.

###2. Description of inter-node messages and protocol structure

  The bfclient nodes communicate by sending JSON formatted strings over UDP. Each message is initially sent by one node to all its neighbors. The neighbors transmit this message to their set of neighbors and thus throughout the network.

  The actual protocol messages are dictionaries named "send_dict" throughout this program. They are comprised of the following types:

_update_
   - This message's ``'type'` key maps to the string `'update'`. The message's `'routing_table'` key maps to a routing table identical in structure to locally stored tables. When it's first sent: to neighbors upon initialization, as well as at periodic intervals by a timer thread. It's the table updates in this message that are used by the Bellman-Ford algorithm. The periodic updates allow the algorithm to converge.

_linkup_
  - The linkup message's `'type'` key is the string `'linkup'`. The `'pair'` key maps to another string in the format of `"node_id,node_id"` where node_id is a string with structure described in part (1). When it's first sent: upon a `'LINKUP'` command from stdin. These are used to restore a previously offline link between two nodes.

_linkdown_
  - The linkdown message's `'type'` key is the string `'linkdown'`. The `'pair'` key maps to a string in the same formatting as the `'linkup'` messsage. When it's first sent: upon a `'LINKDOWN'` command from stdin. Used to take down a link between two adjacent nodes (the edge cost is set to infinity).

_close_
  - The close message's `'type'` key is the string `'close'`. The message has a `'target'` key which maps to a `node_id` representing the node that is going offline. When it's first sent: by the `node_timer` thread after discovering that a given neighbor has been inactive for more than 3 times the timeout interval.

###3. Description of threads used

_timer update thread_
  - `timer_update` sed to send periodic distance-vector updates to neighbors at an interval specified by the user input.

_node timer thread_
  - `node_timer` runs every second to check for nodes that have "expired" and should then be considered offline. This thread sends messages of 'close' type.

  - Thread methods use deepcopy to ensure that a dictionary they are iterating through doesn't change size during iteration.

###4. Peculiarities in this implementation with respect to the assignment:

**_[IMPORTANT]_**
Since this program does not take a host ip address on the command line, I use
`host = socket.gethostbyname(socket.gethostname())`
to store an ip address for the host. This is what ultimately determines the node's `self_id` string.
This program works under the assumption that the above function call returns the same IP address as seen by other nodes on the network.
If nodes do not seem to be responding, try a topology on the same machine/IP address.
A node's conception of its own IP address will be displayed at the top of the routing table via the SHOWRT command.
This IP address must be identical to this node's IP address as displayed in any different node's routing table for all other nodes in the topology.

- I only use one UDP socket per bfclient instance. The assignment calls for a 'read only socket' and a 'set of sockets' to 'write to', but since UDP sockets are connectionless, there is no need for each neighbor to have an individual socket. Rather, messages are sent to neighbors iteratively through a single socket.

- I do not store node identifiers as actual tuple objects, but rather as    strings that are separated by a ":". This decision decision was made to simplify the use of JSON for inter-node communication, as well as to reflect the way the assignment specifies to represent nodes in the routing table.

- When a node is unreachable, i.e. its edge cost is infinity, the 'link' parameter of the routing table is represented as the string `"n/a"`.

- I have implemented __Poisoned Reverse__ in the `update_neighbor()` method.

- I have also implemented a `TWEET` command that broadcasts a message to all other reachable nodes in the network. Just in case you need to tweet. Just type "TWEET" onto the command line followed by your text content.
