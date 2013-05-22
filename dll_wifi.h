/// This file declares the external interface to our WiFi data link layer.

#ifndef DLL_WIFI_H
#define DLL_WIFI_H

#include "dll_shared.h"

#include <cnet.h>
#include <stdint.h>

#define WIFI_MAXDATA (2312)
#define WIFI_MAX_AP_RECORDS (100)
#define WIFI_BROADCAST_ADDR_STRING ("ff:ff:ff:ff:ff:ff")
#define WIFI_MAX_ASSOCIATED_CLIENTS (100)
#define WIFI_INITIAL_CHECKSUM_VALUE ((uint32_t)0)
#define WIFI_APP_LAYER_START_DELAY (2000000)

#define WIFI_PROBE_PERIOD (500000) //how often to probe for APs
#define WIFI_REASSOCIATE_PERIOD (1000000) //how long to wait after probing before reassociation
#define WIFI_RTS_CTS_PERIOD (15000) // how long to ask other nodes to refrain from sending when an rts/cts is issued

#define WIFI_PROBE_TIMER EV_TIMER2
#define WIFI_REASSOCIATE_TIMER EV_TIMER3
#define WIFI_BACKOFF_TIMER EV_TIMER4
#define WIFI_RESEND_TIMER EV_TIMER5
#define WIFI_APP_LAYER_START EV_TIMER7

#define WIFI_RTS_RESEND_ATTEMPTS 1000 // how many times to make an RTS before dropping the frame
#define WIFI_FRAME_QUEUE_LENGTH 100 


//#define WIFI_RESEND_PERIOD 510 // how long to wait before attempting to resend if backed-off due to rts/cts
//#define WIFI_RTS_RESEND_PERIOD 510 // how long to wait for a CTS after an RTS is sent before re-sending the RTS
//#define WIFI_RTS_RESEND_TIMER EV_TIMER6
//#define WIFI_RTS_RESEND_TIMER_ID 6 // ID for the WIFI_RTS_RESEND_TIMER, because the API doesn't seem to say how to get it from the timer itself



/// This enum specifies the various types of WLAN frame used for DLL control
typedef enum { WIFI_DATA, 
               WIFI_PROBE, 
               WIFI_PROBE_RESPONSE, 
               WIFI_ASSOCIATE_REQUEST,
               WIFI_ASSOCIATE_CONFIRM,
               WIFI_DISASSOCIATE_NOTICE,		   
               WIFI_RTS, 
               WIFI_CTS }   WIFI_FRAME_KIND;

// information sent with a wifi probe frame
struct wifi_probe_info {
  // MAC address of the mobile node which is sending the probe
  CnetNICaddr mobile_addr;
  
  // time at which the probe was sent
  CnetTime send_timestamp;
};

// information sent with a response to a wifi probe frame
struct wifi_probe_response_info {
  // MAC address of the responding AP
  CnetNICaddr ap_addr;
  
  // time at which the probe frame which is being responded to was sent
  CnetTime send_timestamp;
};

// information sent with a wifi association request frame
struct wifi_assoc_request_info {
  // MAC address of the node which is requesting association
  CnetNICaddr mobile_addr;
  
  // Node address of the requesting node (not the cnet node number; the cnet address)
  CnetAddr node_number;
};

// information which is sent with an RTS or CTS frame
struct wifi_rts_cts_info {
  // MAC address of the requesting node
  CnetNICaddr send_addr;
  
  // MAC address of the node receiving the request
  CnetNICaddr recv_addr;
  
  // amount of time other nodes are requested to back-off for
  CnetTime backoff_period;
};

// for a mobile node, holds information about the associated AP
struct wifi_mobile_assoc_record {
  // MAC address of the associated AP
  CnetNICaddr associated_ap;
  
  // true iff this association record is currently valid
  bool valid;
};

// for an AP, holds information about one associated mobile node
struct wifi_ap_assoc_record {
  // MAC address of the associated client
  CnetNICaddr associated_client;
  
  // Actual node number of the requesting node
  CnetAddr client_node_number;
  
  // time at which this association was confirmed (by this node's clock)
  CnetTime association_time;
  
  // true if this association is currently valid
  bool valid;
};


// for a mobile node, hold probe information about one AP
struct wifi_ap_record {
  // MAC address of the AP
  CnetNICaddr ap_nic_addr;
  
  // measured RTT to this AP at time of last probe
  CnetTime latest_rtt;
  
  // measured signal strength for this AP at time of last probe
  double latest_sig_strength;
  
  // true if this record was up-to-date at the time of the last probe
  bool up_to_date;
};

/// This struct specifies the format of the control section of a WiFi frame.
struct wifi_control {
  unsigned from_ds : 1;
  WIFI_FRAME_KIND kind;
};

/// This struct specifies the format of a WiFi frame.
///
struct wifi_frame {
  // Control section.
  struct wifi_control control;
  
  // Number of bytes in the payload.
  uint16_t length;
  
  // Address of the receiver.
  CnetNICaddr dest;
  
  // Address of the transmitter.
  CnetNICaddr src;
  
  // CRC32 for the entire frame.
  uint32_t checksum;
  
  // Data must be the last field, because we will truncate the unused area when
  // sending to the physical layer.
  char data[WIFI_MAXDATA];
};

struct wifi_frame_data {
  char data[WIFI_MAXDATA];
};

// struct to represent a queue of outgoing wifi frames
struct wifi_frame_queue {

  // for each frame, a pointer to its data
  struct wifi_frame_data data[WIFI_FRAME_QUEUE_LENGTH];
  
  // for each frame, its length field
  uint16_t length[WIFI_FRAME_QUEUE_LENGTH];

  // for each frame, its wifi frame kind
  WIFI_FRAME_KIND kind[WIFI_FRAME_QUEUE_LENGTH];

  // for each frame, it's destination MAC address
  CnetNICaddr dest[WIFI_FRAME_QUEUE_LENGTH];
 
  //for each frame, whether it will require a CTS to be sent
  bool require_cts[WIFI_FRAME_QUEUE_LENGTH];
  
  // for each queue position, true iff that position is considered to be non-empty
  bool active[WIFI_FRAME_QUEUE_LENGTH];
  
  // the index of the head of the queue
  int head;
};

typedef void (*new_association_fn_ty)(CnetNICaddr *mobile_nicaddr, CnetAddr mobile_addr);

/// This struct type will hold the state for one instance of the WiFi data
/// link layer. The definition of the type is not important for clients.
///
struct dll_wifi_state {
  // The link that this instance of the WiFi protocol is associated with.
  int link;
  
  // A pointer to the function that is called to pass data up to the next layer.
  up_from_dll_fn_ty nl_callback;
  
  // A pointer to the function that is called when this DLL is ready to accept a frame from the NL.
  dll_notify_ready_fn_ty nl_ready;
  
  // A pointer to the function that, for an AP, is called to inform the NL of a new association with a mobile node
  new_association_fn_ty new_assoc_callback;
  
  // True iff this node is part of the DS (i.e. an access point).
  bool is_ds;

  // true iff the link is not backed-off due to RTS/CTS
  bool can_send;

  // if this node is a mobile, records the characteristics of probed APs
  struct wifi_ap_record ap_record_table[WIFI_MAX_AP_RECORDS];

  // if this node is an AP, records the associated mobiles
  struct wifi_ap_assoc_record assoc_records[WIFI_MAX_ASSOCIATED_CLIENTS];

  // if this node is a mobile, records the associated AP
  struct wifi_mobile_assoc_record assoc_record;

  // frame waiting for CTS
  struct wifi_frame cached_frame;
  
  // frames waiting to be transmitted
  struct wifi_frame_queue frame_queue;
 
  // length of the waiting frame
  size_t cached_frame_length;
  
  // true iff the cached frame is still waiting for a CTS
  bool waiting_for_cts;

  // the number of times this node has attempted to send a RTS for the current cached frame
  int rts_resend_attempts;
};

/// Create a new state for an instance of the WiFi data link layer.
///
struct dll_wifi_state *dll_wifi_new_state(int link,
                                          up_from_dll_fn_ty callback,
                                          bool is_ds,
                                          dll_notify_ready_fn_ty nl_ready,
                                          new_association_fn_ty new_assoc_callback);


/// Delete the given dll_wifi_state. The given state pointer will be invalid
/// following a call to this function.
///
void dll_wifi_delete_state(struct dll_wifi_state *state);

/// Write a frame to the given WiFi link.
///
void dll_wifi_write(struct dll_wifi_state *state,
                    CnetNICaddr dest,
                    const char *data,
                    uint16_t length);

/// Called when a frame has been received on the WiFi link. This function will
/// retrieve the payload, and then pass it to the callback function that is
/// associated with the given state struct.
///
void dll_wifi_read(struct dll_wifi_state *state,
                   const char *data,
                   size_t length);

void dll_wifi_probe(struct dll_wifi_state *state);

void dll_wifi_reassociate(struct dll_wifi_state *state);

void dll_wifi_transmit(struct dll_wifi_state *state,
                       CnetNICaddr dest,
                       const char *data,
                       uint16_t length,
                       WIFI_FRAME_KIND kind,
                       bool require_cts);

void dll_wifi_resend(struct dll_wifi_state *state);

void dll_wifi_backon(struct dll_wifi_state *state);

void dll_wifi_rts_resend(struct dll_wifi_state *state);

void dll_wifi_check_ready(struct dll_wifi_state *state);

#endif // DLL_WIFI_H
