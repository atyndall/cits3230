/// This file implements the functionality of our mobile nodes.

#include <cnet.h>
#include <inttypes.h>
#include <stdlib.h>
#include <string.h>

#include "dll_wifi.h"
#include "mapping.h"
#include "network.h"
#include "walking.h"

#define NL_WINDOW_SIZE (20)
#define MAX_DESTINATIONS (20)
#define MAX_SENDERS (20)
#define MAX_QUEUED_PACKETS (2 * MAX_DESTINATIONS * NL_WINDOW_SIZE)

#define NL_RESEND_WINDOW_TIMER EV_TIMER6
#define NL_RESEND_TIMEOUT (20000)

// a sliding-window send queue corresponding to one destination node
struct send_queue {
  // the packets in this queue
  struct nl_packet packets[2*NL_WINDOW_SIZE];
  
  // for each packet in the queue, true iff it exists (false if it is an empty queue position)
  bool packet_active[2*NL_WINDOW_SIZE];

  // for each packet in the queue, true iff it has been acked
  bool packet_acked[2*NL_WINDOW_SIZE];

  // the address of the destination of these packets
  CnetAddr dest_addr;
  
  // the index of the beginning of the send window
  int window_start;
  
  //the index of the next packet to send
  int next_seqno;

  // true iff this queue is active
  bool queue_active;
};

// a sliding-window receive queue corresponding to one source node
struct recv_queue {
  // the packets in this queue
  struct nl_packet packets[2*NL_WINDOW_SIZE];
  
  // for each packet in the queue, true iff it exists (false if it is an empty queue position)
  bool packet_arrived[2*NL_WINDOW_SIZE];

  // for each packet in the queue, true iff it has been sent to the app layer already
  bool sent_to_app_layer[2*NL_WINDOW_SIZE];

  // the address of the source node of the packets in this queue
  CnetAddr send_addr;

  // the index of the first element in the receiving window
  int window_start;

  // true iff this queue is active (false if it has not been initialised)
  bool queue_active;
};

// struct for a queue of send_queue structs
struct output_queue {
  //the queue of queues
  struct send_queue queue[MAX_QUEUED_PACKETS];
  
  // for each packet in the queue, true iff it exists (false if it is an empty queue position)
  bool entry_active[MAX_QUEUED_PACKETS];
  
  // index of the head of the queue
  int head;
};

// queue of ACK packets to send (all ACKs are sent before new data packets are sent)
struct ack_queue {
  // the ACK packets waiting to be sent
  struct nl_packet packets[MAX_QUEUED_PACKETS];

  // for each packet in the queue, true iff it exists (false if it is an empty queue position)
  bool entry_active[MAX_QUEUED_PACKETS];
  
  // index of the head of the queue
  int head;
};

// the ack queue for this node (see the struct definition)
static struct ack_queue ack_queue;

// each mobile node has an sending sliding-window queue for each destination to which it sends packets.
// when a packet is gotten from the app layer, that packet is added to the end of the corresponding
// queue (for its destination node), then that queue is added to this queue; when the DLL is ready
// to receive a packet for transmission, the queue at the front of this queue is examined and the
// next packet to send from that queue (determined by the rules of selecive-repeat ARQ) is sent.
static struct output_queue out_queue;

// when a packet is sent from a send queue, that queue is added to this list:
// after a waiting period, that queue is added back onto the end of the output queue
static struct output_queue resend_queue;

// list of all the sending queues for this node
static struct send_queue send_queue_list[MAX_DESTINATIONS];

// each mobile node has a receive queue for each sender from which it accepts
// packets. this is the node's list of receive queues.
static struct recv_queue recv_queue_list[MAX_SENDERS];

// Mobile nodes can only have WLAN links, so we always use the WiFi data link
// layer.
static struct dll_wifi_state **dll_states;


/// Called when this mobile node receives a frame on any of its physical links.
///
static EVENT_HANDLER(physical_ready)
{
  //printf("physical_ready\n");

  // First we read the frame from the physical layer.
  char frame[DLL_MTU];
  size_t length	= sizeof(frame);
  int link;

  CHECK(CNET_read_physical(&link, frame, &length));

  // Now we forward this information to the data link layer, if it exists.
  if (link > nodeinfo.nlinks || dll_states[link] == NULL)
    return;
  
  dll_wifi_read(dll_states[link], frame, length);

  //printf("physical_ready RETURN\n");
}


// instruct each wifi DLL to determine if it is ready to accept a packet, and report back
void check_dll_ready()
{
  for (int link = 1; link <= nodeinfo.nlinks; ++link) {
    if (linkinfo[link].linktype == LT_WLAN) {
      dll_wifi_check_ready(dll_states[link]);
    }
  }
}

//add a sending queue to the end of the list of queues to deal with when the DLL is ready
void add_queue_to_out_queue(struct send_queue *queue_to_add)
{
  //printf("adding queue to out_list\n");

  int i;
  int first_inactive_index = 0;
  bool found_inactive = false;
  for(i = out_queue.head; i < MAX_QUEUED_PACKETS + out_queue.head; i++) 
  {
    if(!out_queue.entry_active[i % MAX_QUEUED_PACKETS])
    {
      found_inactive = true;
      first_inactive_index = i % MAX_QUEUED_PACKETS;
      break;
    }
  }
  
  if(found_inactive)
  {
    out_queue.queue[first_inactive_index] = *queue_to_add;
    out_queue.entry_active[first_inactive_index] = true;
  } else {
    printf("MOBILE ERROR: out_queue full\n");
    return;
  }
}

// add a sending queue to the list of queues to be added back on to the out_queue
void add_queue_to_resend_queue(struct send_queue *queue_to_add)
{
  int i;
  int first_inactive_index = 0;
  bool found_inactive = false;
  for(i = resend_queue.head; i < MAX_QUEUED_PACKETS + resend_queue.head; i++) 
  {
    if(!resend_queue.entry_active[i % MAX_QUEUED_PACKETS])
    {
      found_inactive = true;
      first_inactive_index = i % MAX_QUEUED_PACKETS;
      break;
    }
  }
  
  if(found_inactive)
  {
    resend_queue.queue[first_inactive_index] = *queue_to_add;
    resend_queue.entry_active[first_inactive_index] = true;
  } else {
    printf("MOBILE ERROR: resend_queue full\n");
    return;
  }
  
  CHECK(CNET_start_timer(NL_RESEND_WINDOW_TIMER, NL_RESEND_TIMEOUT, first_inactive_index));
}

// called when the selective-repeat ARQ timeout expires for the queue at the head of the
// resend queue: causes the unacked packets in that queue's window to be resent
EVENT_HANDLER(resend_window)
{
  int index = data;

  if(resend_queue.entry_active[index])
  {
    struct send_queue send_queue = resend_queue.queue[index];

    send_queue.next_seqno = send_queue.window_start;

    add_queue_to_out_queue(&send_queue);
    
    resend_queue.entry_active[index] = false;
 
    check_dll_ready();
  }
}

/// Caled when a DLL is ready to accept a packet; determines the next packet to send and passes it to that DLL for transmission
static void dll_ready(int link) 
{
  printf("dll_ready\n");

  //deal with the ack queue before handling the packet output queue
  if(ack_queue.entry_active[ack_queue.head])
  {
    struct nl_packet packet = ack_queue.packets[ack_queue.head];

    ack_queue.head = (ack_queue.head + 1) % MAX_QUEUED_PACKETS;
	
    uint16_t packet_length = NL_PACKET_LENGTH(packet);
  
    //finally, actually pass the packet to the DLL that claimed to be ready to accept it
    //printf("sending ACK on link %i for node %i\n", link, packet.dest);
    dll_wifi_write(dll_states[link], dll_states[link]->assoc_record.associated_ap, (char *)&packet, packet_length);
    
    check_dll_ready();
    return;
  }

  if(out_queue.entry_active[out_queue.head])
  {
    //send from the queue corresponding to the first entry in the output list
    struct send_queue send_queue = out_queue.queue[out_queue.head];

    int packet_number_to_send = send_queue.next_seqno;
	
    if(!send_queue.packet_active[send_queue.next_seqno])
    {
      //no packets to send to this destination, try the next one
      out_queue.entry_active[out_queue.head] = false;
      out_queue.head = (out_queue.head + 1) % MAX_QUEUED_PACKETS;
      dll_ready(link);
      return;
    }

    if(send_queue.next_seqno != (send_queue.window_start + NL_WINDOW_SIZE) % (2 * NL_WINDOW_SIZE))
    {
      // send the next packet in the send window
      send_queue.next_seqno = (send_queue.next_seqno + 1) % (2 * NL_WINDOW_SIZE);
      add_queue_to_out_queue(&send_queue);
    } else {
      // all packets in the send window have been sent,
      // so, wait a while, then add this queue back onto
      // the output list and transmit the window again
      printf("MOBILE: resending queue\n");
      add_queue_to_resend_queue(&send_queue);
    }

    out_queue.entry_active[out_queue.head] = false;
    out_queue.head = (out_queue.head + 1) % MAX_QUEUED_PACKETS;
    
    if(!send_queue.packet_acked[packet_number_to_send])
    {
      // send the next packet in the queue
      struct nl_packet packet = send_queue.packets[packet_number_to_send];
	
      uint16_t packet_length = NL_PACKET_LENGTH(packet);
  
      //finally, actually pass the packet to the DLL that claimed to be ready to accept it
      printf("MOBILE: sending packet on link %i for node %i with seqno: %i\n", link, packet.dest, packet.seq_no);
      
      dll_wifi_write(dll_states[link], dll_states[link]->assoc_record.associated_ap, (char *)&packet, packet_length);
    }
    check_dll_ready();	
  } else {
    printf("MOBILE: currently no queued data packets\n");
  }

  //printf("dll_ready RETURN\n");
}

// examines the specified receiving queue for new in-order packets that have not yet been sent to the app layer,
// passes those packets to the app layer, then moves the start of the receiving window up to the index of the
// first un-acked packet in the queue
void refresh_recv_queue(struct recv_queue *recv_queue)
{
  //printf("refresh_recv_queue\n");
  int i;
  for(i = recv_queue->window_start; i < recv_queue->window_start + NL_WINDOW_SIZE; i++)
  {
    if(recv_queue->packet_arrived[i % (2 * NL_WINDOW_SIZE)])
    {
      if(!recv_queue->sent_to_app_layer[i % (2 * NL_WINDOW_SIZE)])
      {
        recv_queue->sent_to_app_layer[i % (2 * NL_WINDOW_SIZE)] = true;

        size_t payload_length = recv_queue->packets[i % (2 * NL_WINDOW_SIZE)].length;
        CHECK(CNET_write_application(&(recv_queue->packets[i % (2 * NL_WINDOW_SIZE)].data), &payload_length));
        
        printf("MOBILE: sent data to application layer from node: %i\n", recv_queue->send_addr);
      }
    } 
    else 
    {
      break;
    }
  }
  recv_queue->window_start = i;
}

// sends an ACK for a received packet, specified by the queue that it is in
// and it's sequence number, then asks the DLL to report whether it is ready
// to accept a new packet for transmission
void ack_packet(struct recv_queue *recv_queue, int seq_no)
{
  //printf("ack_packet\n");

  refresh_recv_queue(recv_queue);

  struct nl_packet packet = (struct nl_packet){
    .src = nodeinfo.address,
  };

  NL_PACKET_KIND kind = NL_ACK;
  packet.kind = kind;

  struct nl_ack_info info;
  info.seq_no = seq_no;
  info.window_start = recv_queue->window_start;  
  
  memcpy(packet.data, &info, sizeof(struct nl_ack_info));
  packet.length = sizeof(struct nl_ack_info);

  packet.checksum = 0;  
  packet.checksum = CNET_crc32((unsigned char *)&packet, NL_PACKET_LENGTH(packet));

  int first_inactive_index = 0;
  bool found_inactive = false;
  int i;
  for(i = ack_queue.head; i < ack_queue.head + MAX_QUEUED_PACKETS; i++)
  {
    if(!ack_queue.entry_active[i % MAX_QUEUED_PACKETS])
    {
      found_inactive = true;
      first_inactive_index = i;
      break;
    }
  }

  if(!found_inactive)
  {
    printf("MOBILE ERROR: no room in ack queue\n");
    return;
  }

  ack_queue.entry_active[first_inactive_index] = true;
  ack_queue.packets[first_inactive_index] = packet;

  check_dll_ready();
}

// Called when we receive data from one of our data link layers, and handles the packet.
void up_from_dll(int link, const char *data, size_t length)
{
  //printf("up_from_dll\n");

  if (length > sizeof(struct nl_packet)) {
    printf("MOBILE ERROR: %zu is larger than a nl_packet! ignoring.\n", length);
    return;
  }
  
  // Treat this frame as a network layer packet.
  struct nl_packet packet;
  memset(&packet, 0, sizeof(packet));
  memcpy(&packet, data, length);
  
  printf("MOBILE: Received packet from dll on link %d from node %" PRId32
         " for node %" PRId32 " with seqno: %i.\n", link, packet.src, packet.dest, packet.seq_no);
  
  uint32_t checksum = packet.checksum;
  packet.checksum = 0;
  
  if (CNET_crc32((unsigned char *)&packet, sizeof(packet)) != checksum) {
    printf("\tChecksum failed.\n");
    return;
  }

  packet.checksum = checksum;
  
  if (packet.dest != nodeinfo.address) {
    //printf("\tThat's not for me.\n");
    return;
  }
    
  // place this packet in the receiving window, then see what's up
  bool found = false;
  int recv_queue_index;  
  int i;
  for(i = 0; i < MAX_SENDERS; i++)
  {
    if(recv_queue_list[i].queue_active && recv_queue_list[i].send_addr == packet.src)
    {
      found = true;
      recv_queue_index = i;
      break;
    }
  }

  if(!found)
  {
    bool found_inactive = false;

    for(i = 0; i < MAX_SENDERS; i++)
    {  
      if(!recv_queue_list[i].queue_active)
      {
        found_inactive = true;
        recv_queue_index = i;
        break;
      }
    }

    //printf("creating new recv_queue for sender %i, with index %i\n", packet.src, recv_queue_index);

    if(!found_inactive)
    {
      printf("MOBILE ERROR: too many senders");
      return;
    }

    struct recv_queue new_queue;
    new_queue.queue_active = true;
    new_queue.send_addr = packet.src;
    new_queue.window_start = 0;
    recv_queue_list[recv_queue_index] = new_queue;
    for(i = 0; i < NL_WINDOW_SIZE; i++)
    {
      new_queue.packet_arrived[i] = false;
      recv_queue_list[recv_queue_index].sent_to_app_layer[i] = false;
    }


  }
  
  if(recv_queue_list[recv_queue_index].packet_arrived[packet.seq_no] && recv_queue_list[recv_queue_index].packets[packet.seq_no].checksum != checksum)
  {      
    recv_queue_list[recv_queue_index].sent_to_app_layer[packet.seq_no] = false;
  }

  memcpy(&recv_queue_list[recv_queue_index].packets[packet.seq_no], &packet, sizeof(struct nl_packet));
  recv_queue_list[recv_queue_index].packet_arrived[packet.seq_no] = true;

  ack_packet(&(recv_queue_list[recv_queue_index]), packet.seq_no);

  //printf("up_from_dll RETURN\n");
}

// place an outgoing packet on the correct sending queue for that destination,
// then places that queue on the main output queue for this node. finally
// asks the DLL to report whether it is ready to accept a packet
void queue_packet(CnetAddr dest, struct nl_packet *packet) 
{
  //printf("queue_packet\n");
  
  //printf("queueing packet for node: %i\n", packet->dest);

  // see if there exists a queue for this destination
  bool found = false;
  int dest_queue_index;
  int i;
  for(i = 0; i < MAX_DESTINATIONS; i++) 
  {
    if(send_queue_list[i].queue_active && send_queue_list[i].dest_addr == dest)
    {
      found = true;
      dest_queue_index = i;
      break;
    }
  } 
  
  int first_inactive_index = 0;
  bool found_inactive = false;

  // if no queue exists for this destination address, make one and add it to the list
  if(!found)
  {
    //printf("No queue for this destination, creating...\n");
    struct send_queue new_queue;
    new_queue.queue_active = true;
    new_queue.window_start = 0;
    new_queue.next_seqno = 0;
    new_queue.dest_addr = dest;

    for(i = 0; i < 2*NL_WINDOW_SIZE; i++)
    {
      new_queue.packet_active[i] = false;
    }
    for(i = 0; i < MAX_DESTINATIONS; i++) 
    {
      if(!send_queue_list[i].queue_active)
      {
      first_inactive_index = i;
      found_inactive = true;
      break;
      }
    }
	
    if(found_inactive)
    {
      send_queue_list[i] = new_queue;
      dest_queue_index = i;
    } else {
      printf("MOBILE ERROR: too many output destinations on this node\n"); 
      return;
    }
  }
  
  //printf("adding packet to queue\n");
  //add the packet to the end of the corresponding destination queue
  first_inactive_index = 0;
  found_inactive = false;
  for(i = send_queue_list[dest_queue_index].window_start; i < (send_queue_list[dest_queue_index].window_start + 2*NL_WINDOW_SIZE); i++)
  {
    if(!send_queue_list[dest_queue_index].packet_active[i % (2*NL_WINDOW_SIZE)])
    {
      found_inactive = true;
      first_inactive_index = i % (2*NL_WINDOW_SIZE);
      break;
    }
  }
  
  if(found_inactive) {
    memcpy(&(send_queue_list[dest_queue_index].packets[first_inactive_index]), packet, sizeof(struct nl_packet));
    send_queue_list[dest_queue_index].packets[first_inactive_index].seq_no = first_inactive_index;
    
    //the seqno may have changed, so recompute the checksum
    send_queue_list[dest_queue_index].packets[first_inactive_index].checksum = 0;
    send_queue_list[dest_queue_index].packets[first_inactive_index].checksum = CNET_crc32((unsigned char *)&send_queue_list[dest_queue_index].packets  
      [first_inactive_index], sizeof(send_queue_list[dest_queue_index].packets[first_inactive_index]));
    
    send_queue_list[dest_queue_index].packet_active[first_inactive_index] = true;
    send_queue_list[dest_queue_index].packet_acked[first_inactive_index] = false;
  } else {
    printf("MOBILE ERROR: too many output packets for this destination on this node\n");
    return;
  }
  
  add_queue_to_out_queue(&(send_queue_list[dest_queue_index]));

  check_dll_ready();

  //printf("queue_packet RETURN\n");
}

// Called when this mobile node's application layer has generated a new
// message, builds a packet around it, and queues that packet up to be
// passed to the DLL
EVENT_HANDLER(application_ready)
{
  //printf("application_ready\n");

  struct nl_packet packet = (struct nl_packet){
    .src = nodeinfo.address,
    .length = NL_MAXDATA
  };

  NL_PACKET_KIND kind = NL_DATA;
  packet.kind = kind;
  
  CHECK(CNET_read_application(&packet.dest, packet.data, &packet.length));
  
  packet.checksum = 0;
  packet.checksum = CNET_crc32((unsigned char *)&packet, sizeof(packet));
  
  printf("MOBILE: Generated message for % " PRId32 ". Queueing...\n",
         packet.dest);

  queue_packet(packet.dest, (struct nl_packet *)&packet);

  //printf("application_ready RETURN\n");
}

// tell all WLAN DLLs to probe for APs; called regularly by a timer
EVENT_HANDLER(send_probe)
{
   //printf("send_probe\n");

   for (int link = 1; link <= nodeinfo.nlinks; ++link) {
     if (linkinfo[link].linktype == LT_WLAN) {
       dll_wifi_probe(dll_states[link]);
     }
   } 
  CNET_start_timer(WIFI_PROBE_TIMER, (CnetTime)WIFI_PROBE_PERIOD, 0);
  CNET_start_timer(WIFI_REASSOCIATE_TIMER, (CnetTime)WIFI_REASSOCIATE_PERIOD, 0);

  //printf("send_probe RETURN\n");
}

// called some time after a WLAN probe is sent, and instructs the Wifi DLL
// to associate with the best AP, given the probe responses
EVENT_HANDLER(reassociate)
{
  //printf("reassociate\n");

  for (int link = 1; link <= nodeinfo.nlinks; ++link) {
    if (linkinfo[link].linktype == LT_WLAN) {
      dll_wifi_reassociate(dll_states[link]);
    }
  }

  //printf("reassociate RETURN\n");
}

/// called when the WLAN backoff timer expires, and the Wifi NIC can
/// now resume transmission
EVENT_HANDLER(mobile_wifi_backon) {
  int link = data;
  dll_wifi_backon(dll_states[link]);
}

// called on node boot; initialises queue datastructures
void init_queues() {
  int i;
  for(i = 0; i < MAX_QUEUED_PACKETS; i++) 
  {
    struct send_queue new_queue;
    new_queue.queue_active = false;
    out_queue.queue[i] = new_queue;
  } 
  out_queue.head = 0;

  for(i = 0; i < MAX_QUEUED_PACKETS; i++) 
  {
    struct send_queue new_queue;
    new_queue.queue_active = false;
    resend_queue.queue[i] = new_queue;
  } 
  resend_queue.head = 0;

  for(i = 0; i < MAX_SENDERS; i++) 
  {
    struct recv_queue new_queue;
    new_queue.queue_active = false;
    recv_queue_list[i] = new_queue;
  } 

  for(i = 0; i < MAX_DESTINATIONS; i++)
  {
    struct send_queue new_queue;
    new_queue.queue_active = false;
    send_queue_list[i] = new_queue;
  }

  for(i = 0; i < MAX_QUEUED_PACKETS; i++) 
  {
    ack_queue.entry_active[i] = false;
  }
  ack_queue.head = 0;
}

// does nothing for a mobile node; just need a valid new_association_fn_ty to pass to the dll_wifi_new_state function
void do_nothing(CnetNICaddr *mobile_nicaddr, CnetAddr mobile_addr){}

// Called when this mobile node is booted up.
void reboot_mobile()
{
  // We require each node to have a different stream of random numbers.
  CNET_srand(nodeinfo.time_of_day.sec + nodeinfo.nodenumber);

  // Setup our data link layer instances.
  dll_states = calloc(nodeinfo.nlinks + 1, sizeof(struct dll_wifi_state *));
  
  for (int link = 1; link <= nodeinfo.nlinks; ++link) {
    if (linkinfo[link].linktype == LT_WLAN) {
      dll_states[link] = dll_wifi_new_state(link,
                                            up_from_dll,
                                            false, /* is_ds */
                                            dll_ready,
                                            do_nothing);
    }
  }
  
  // Provide the required event handlers. (-1 means the data attribute doesn't matter)
  CHECK(CNET_set_handler(EV_PHYSICALREADY, physical_ready, -1));
  CHECK(CNET_set_handler(EV_APPLICATIONREADY, application_ready, -1));
  CHECK(CNET_set_handler(WIFI_PROBE_TIMER, send_probe, -1));
  CHECK(CNET_set_handler(WIFI_REASSOCIATE_TIMER, reassociate, -1));
  CHECK(CNET_set_handler(WIFI_BACKOFF_TIMER, mobile_wifi_backon, -1));
  CHECK(CNET_set_handler(NL_RESEND_WINDOW_TIMER, resend_window, -1));

  // Initialize mobility.
  init_walking();
  start_walking();

  // Initialize queues.
  init_queues();

  // Prepare to talk via our wireless connection.
  CNET_set_wlan_model(my_WLAN_model);

  //probe pretty soon after initiating (but with a random offset, to prevent all nodes
  //from deterministically probing at the same time after simulation start)
  CNET_start_timer(WIFI_PROBE_TIMER, (CnetTime)(CNET_rand() % 500000), 0);
  
  // Start the applicaton layer
  CNET_enable_application(ALLNODES);
  
  //printf("reboot_mobile() complete.\n");
  printf("Address of this node: %" PRId32 ".\n", nodeinfo.address);
}
