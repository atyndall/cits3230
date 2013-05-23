/// This file declares data types and values for our network layer.

#ifndef NETWORK_H
#define NETWORK_H

#include <cnet.h>
#include <stddef.h>
#include <stdint.h>


// the maximum length of a network layer frame
#define NL_MAXDATA 1024

//defines the three types of network layer packet: data, acknowledgement, and routing information (used if routing is enabled)
typedef enum { NL_DATA,
               NL_ACK,
               NL_ROUTING_INFO } NL_PACKET_KIND;

/// This struct defines the format for a network layer packet.
struct nl_packet {
  /// The node that this packet is destined for.
  CnetAddr dest;
  
  /// The node that this packet was created by.
  CnetAddr src;
  
  /// Checksum for this packet.
  uint32_t checksum;
  
  /// Length of this packet's payload.
  size_t length;

  /// the kind of packet (see above)
  NL_PACKET_KIND kind;

  /// sequence number of the packet (for selective-repeat ARQ)
  int seq_no;
  
  /// The payload of this packet.
  char data[NL_MAXDATA];
};

/// This struct is passed with a NL ACK packet, and holds information about the acknowledgement
struct nl_ack_info {
  // the sequence number of the packet that is being acknowledged
  int seq_no;

  // the index of the start of the receiver's receive window
  int window_start;
};

// if routing is enabled, an array of these structs are passed with a routing info packet
// (of NL_PACKET_KIND NL_ROUTING_INFO), and each one holds information about one routing 
// record (routing table row)
struct routing_info_entry {
  // the MAC address of the destination
  CnetNICaddr mobile_nic_addr;

  // the numerical address of the destination
  CnetAddr mobile_num_addr;
  
  // the NIC address of the AP associated with the destination
  CnetNICaddr ap_nic_addr;
  
  // the amount of time since the corresponding association was formed, at the time of formation of the packet
  CnetTime age;
  
  // true iff this record is active (should be ignored by receiver if false)
  bool active;
};

// Determines the number of bytes used by a packet (the number of bytes used
// by the header plus the number of bytes used by the payload).
//
#define NL_PACKET_LENGTH(PKT) (offsetof(struct nl_packet, data) + PKT.length)

#endif // NETWORK_H
