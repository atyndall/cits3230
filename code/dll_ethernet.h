/// This file declares the external interface to our Ethernet data link layer.

#ifndef DLL_ETHERNET_H
#define DLL_ETHERNET_H

#include "dll_shared.h"

#include <cnet.h>
#include <stdint.h>

#define ETHER_BROADCAST_ADDR_STRING ("ff:ff:ff:ff:ff:ff")
#define ROUTING_TABLE_ROWS (20)
#define ETH_MAXDATA 1500
#define ETH_MINFRAME 64

#define ETHER_BACKOFF_TIMER EV_TIMER7
#define ETHER_CARRIER_SENSE_TIMER EV_TIMER8

#define ETHER_QUEUE_LENGTH (100)
#define ETHER_CARRIER_SENSE_TIME (800)
#define ETHER_SLOT_TIME (1500)

/// This struct specifies the format of an Ethernet frame. When using Ethernet
/// links in cnet, the first part of the frame must be the destination address.
///
struct eth_frame {
  // Ethernet address of the destination (receiver).
  CnetNICaddr dest;
  
  // Ethernet address of the source (sender).
  CnetNICaddr src;
  
  // For our protocol the type field will indicate the length of the payload.
  char type[2];
  
  // Data must be the last field, because we will truncate the unused area when
  // sending to the physical layer.
  char data[ETH_MAXDATA];
};

// an internal queue held by an Ethernet DLL of frames to send
struct ether_queue {
  // the frames waiting to be sent
  struct eth_frame frame_queue[ETHER_QUEUE_LENGTH];
  
  // for each frame, true iff it exists (false if it is an empty queue position)
  bool active[ETHER_QUEUE_LENGTH];
  
  // for each frame, the number of send attempts
  int send_attempts[ETHER_QUEUE_LENGTH];
  
  // the index of the head of this queue
  int head;
};

struct routing_table_entry {
  // the MAC address of the destination
  CnetNICaddr mobile_nic_addr;

  // the node number of the destination
  CnetAddr mobile_num_addr;
  
  // the NIC address of the AP associated with the destination
  CnetNICaddr ap_nic_addr;
  
  // the time at which the corresponding association was formed, as per this node's clock
  CnetTime local_create_time;
  
  // true if this entry exists (false if should be considered an empty rable row)
  bool active;
};

/// This struct type will hold the state for one instance of the Ethernet data
/// link layer. The definition of the type is not important for clients.
///
struct dll_eth_state {
  // The link that this instance of the Ethernet protocol is associated with.
  int link;
  
  // A pointer to the function that is called to pass data up to the next layer.
  up_from_dll_fn_ty nl_callback;
  
  // if routing is enabled, holds the routing table for the DLL
  struct routing_table_entry routing_table[ROUTING_TABLE_ROWS];
  
  // the main queue of outgoing ethernet frames for that DLL
  struct ether_queue data_queue;
  
  // priority queue of outgoing frames (cleared before the main
  // queue is dealt with). used for routing information packets
  // if routing is enabled.
  struct ether_queue priority_queue;
  
  // true if this ethernet DLL is backed off due to CSMA/CD
  bool backed_off;
  
  // true if this ethernet DLL still needs to send the most
  // recent frame (as it has collided in previous attempts).
  // false if a new frame is to be sent.
  bool resend_frame;
};

#define ETH_HEADER_LENGTH (offsetof(struct eth_frame, data))

/// Create a new state for an instance of the Ethernet data link layer.
///
struct dll_eth_state *dll_eth_new_state(int link, up_from_dll_fn_ty callback);

/// Delete the given dll_eth_state. The given state pointer will be invalid
/// following a call to this function.
///
void dll_eth_delete_state(struct dll_eth_state *state);

/// Write a frame to the given Ethernet link.
///
void dll_eth_write(struct dll_eth_state *state,
                   CnetNICaddr dest,
                   const char *data,
                   uint16_t length,
                   bool priority);

/// Called when a frame has been received on the Ethernet link. This function
/// will retrieve the payload, and then pass it to the callback function that
/// is associated with the given state struct.
///
void dll_eth_read(struct dll_eth_state *state,
                  const char *data,
                  size_t length);


// see dll_ethernet.c for explanations of these functions                  
void broadcast_routing_info(int link);

void dll_eth_send_next_frame(struct dll_eth_state *state);

void dll_eth_carrier_sense(struct dll_eth_state *state);

void dll_eth_handle_collision(struct dll_eth_state *state);

void dll_eth_backon(struct dll_eth_state *state);

#endif // DLL_ETHERNET_H
