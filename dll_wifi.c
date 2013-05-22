/// This file implements our WiFi data link layer.

#include "dll_wifi.h"

#include <cnet.h>
#include <inttypes.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>


#define WIFI_HEADER_LENGTH (offsetof(struct wifi_frame, data))

/// Create a new state for an instance of the WiFi data link layer.
struct dll_wifi_state *dll_wifi_new_state(int link,
                                          up_from_dll_fn_ty callback,
                                          bool is_ds,
                                          dll_notify_ready_fn_ty nl_ready,
                                          new_association_fn_ty new_assoc_callback)
{
  // Ensure that the given link exists and is a WLAN link.
  if (link > nodeinfo.nlinks || linkinfo[link].linktype != LT_WLAN)
    return NULL;
  
  // Allocate memory for the state.
  struct dll_wifi_state *state = calloc(1, sizeof(struct dll_wifi_state));
  
  // Check whether or not the allocation was successful.
  if (state == NULL)
    return NULL;
  
  // Initialize the members of the structure.
  state->link = link;
  state->nl_callback = callback;
  state->is_ds = is_ds;
  state->can_send = true;
  state->nl_ready = nl_ready;
  state->new_assoc_callback = new_assoc_callback;
 
  if(is_ds) // AP-specific init
  {
    // clear the associated client records
    int i;
    for(i = 0; i < WIFI_MAX_ASSOCIATED_CLIENTS; i++)
    {
      struct wifi_ap_assoc_record rec;
      rec.valid = false;
      state->assoc_records[i] = rec;
    }
  } else {
    // clear the AP association
    state->assoc_record.valid = false;
  }
  
  for(int i = 0; i < WIFI_FRAME_QUEUE_LENGTH; i++)
  {
    state->frame_queue.active[i] = false;
  }

  printf("WIFI: init complete\n");
  
  return state;
}

/// Delete the given dll_wifi_state. The given state pointer will be invalid
/// following a call to this function.
void dll_wifi_delete_state(struct dll_wifi_state *state)
{
  if (state == NULL)
    return;
  
  // Free any dynamic memory that is used by the members of the state.
  free(state);
}

void print_nic(CnetNICaddr addr) {
  char str[17];
  CNET_format_nicaddr(str, addr);
  printf("NIC: %s\n", str);
}

void dll_wifi_queue_frame(struct dll_wifi_state *state, CnetNICaddr dest, char *data, uint16_t length, WIFI_FRAME_KIND kind, bool require_cts)
{
  bool found_inactive = false;
  int first_inactive_index = 0;
  for(int i = state->frame_queue.head; i < state->frame_queue.head + WIFI_FRAME_QUEUE_LENGTH; i++)
  {
    if(!state->frame_queue.active[i % WIFI_FRAME_QUEUE_LENGTH])
    {
      found_inactive = true;
      first_inactive_index = i % WIFI_FRAME_QUEUE_LENGTH;
      break;
    }
  }

  if(!found_inactive)
  {
    printf("WIFI ERROR: frame queue is full\n");
    return;
  }
  
  // ???????????
  
  printf("state->frame_queue.dest[first_inactive_index]:\n");
  print_nic(dest);
  memcpy(state->frame_queue.dest[first_inactive_index], dest, sizeof(CnetNICaddr));
  
  memcpy(state->frame_queue.data[first_inactive_index].data, data, length);
  
  state->frame_queue.length[first_inactive_index] = length;
  state->frame_queue.kind[first_inactive_index] = kind;
  state->frame_queue.require_cts[first_inactive_index] = require_cts;
  state->frame_queue.active[first_inactive_index] = true;
  
  dll_wifi_check_ready(state);
}

/// Send an RTS frame to a given destination
void dll_wifi_send_rts(struct dll_wifi_state *state, CnetNICaddr dest, CnetTime backoff_period)
{
  printf("dll_wifi_send_rts\n");

  WIFI_FRAME_KIND kind = WIFI_RTS;
  
  struct wifi_rts_cts_info info;
  memcpy(info.send_addr, linkinfo[state->link].nicaddr, sizeof(CnetNICaddr));
  memcpy(info.recv_addr, dest, sizeof(CnetNICaddr));
  info.backoff_period = backoff_period;

  CnetNICaddr broadcast_addr;
  CHECK(CNET_parse_nicaddr(broadcast_addr, WIFI_BROADCAST_ADDR_STRING)); 

  char dest_nicaddr_string[17];
  CNET_format_nicaddr(dest_nicaddr_string, dest);
  printf("\tWifi: sending RTS to: %s\n", dest_nicaddr_string);

  //send the actual RTS frame
  // ????????
  dll_wifi_transmit(state, dest, (char *)&info, sizeof(struct wifi_rts_cts_info), kind, false);
  
  //back-off for the specified period (another RTS will be sent after this period if the CTS has not arrived by then)
  state->can_send = false;
  
  if(state->rts_resend_attempts++ < WIFI_RTS_RESEND_ATTEMPTS)
  {
    CNET_start_timer(WIFI_BACKOFF_TIMER, backoff_period, state->link);
  }

  printf("dll_wifi_send_rts RETURN\n");
}


/// Send a CTS frame to a given destination
void dll_wifi_send_cts(struct dll_wifi_state *state, struct wifi_rts_cts_info info)
{
  printf("dll_wifi_send_cts\n");

  WIFI_FRAME_KIND kind = WIFI_CTS;

  CnetNICaddr broadcast_addr;
  CHECK(CNET_parse_nicaddr(broadcast_addr, WIFI_BROADCAST_ADDR_STRING));

  char dest_nicaddr_string[17];
  CNET_format_nicaddr(dest_nicaddr_string, info.send_addr);
  printf("\tWifi: sending CTS to: %s\n", dest_nicaddr_string);
  
  //send the actual CTS frame
  dll_wifi_transmit(state, broadcast_addr, (char *)&info, sizeof(struct wifi_rts_cts_info), kind, false); 

  printf("dll_wifi_send_cts RETURN\n");
}


/// Handle an incoming RTS frame
void dll_wifi_handle_rts(struct dll_wifi_state *state, struct wifi_rts_cts_info *info)
{
  printf("dll_wifi_handle_rts\n");

  char my_nicaddr[17];
  CNET_format_nicaddr(my_nicaddr, linkinfo[state->link].nicaddr);

  char recv_nicaddr[17];
  CNET_format_nicaddr(recv_nicaddr, info->recv_addr);

  char send_nicaddr[17];
  CNET_format_nicaddr(send_nicaddr, info->send_addr);

  // if this node is not involved in the RTS/CTS exchange, back-off for the specified period
  if(strcmp(my_nicaddr, recv_nicaddr) != 0 && strcmp(my_nicaddr, send_nicaddr) != 0)
  { 
    printf("got RTS but not involved, backing off\n");
    state->can_send = false;
    CNET_start_timer(WIFI_BACKOFF_TIMER, (CnetTime)info->backoff_period, state->link);
    return;
  }

  // if this node is the intended recipient of the RTS, and this node is not backed-off, respond with a CTS
  if(strcmp(my_nicaddr, recv_nicaddr) == 0 && state->can_send) 
  {
    dll_wifi_send_cts(state, *info);
  } else {
    printf("Wifi: got RTS but currently backed-off\n");
  }

  printf("dll_wifi_handle_rts RETURN\n");
}

/// Handle an incoming CTS frame
void dll_wifi_handle_cts(struct dll_wifi_state *state, struct wifi_rts_cts_info *info)
{
  printf("dll_wifi_handle_cts\n");

  char my_nicaddr[17];
  CNET_format_nicaddr(my_nicaddr, linkinfo[state->link].nicaddr);

  char send_nicaddr[17];
  CNET_format_nicaddr(send_nicaddr, info->send_addr);

  char recv_nicaddr[17];
  CNET_format_nicaddr(recv_nicaddr, info->recv_addr);
  printf("\tWifi: got CTS from: %s\n", recv_nicaddr);

  // if this CTS is not for this node, back-off for the specified period
  if(strcmp(my_nicaddr, send_nicaddr) != 0) 
  { 
    state->can_send = false;
    CNET_start_timer(WIFI_BACKOFF_TIMER, (CnetTime)info->backoff_period, state->link);
    return; 
  }

  // if this CTS is for this node, send the waiting frame if it hasn't already been sent, and end any back-off
  state->can_send = true;
  if(state->waiting_for_cts)
  {
    state->waiting_for_cts = false;
    CHECK(CNET_write_physical_reliable(state->link, &(state->cached_frame), &(state->cached_frame_length)));
    
    char dest_nicaddr[17];
    CNET_format_nicaddr(dest_nicaddr, state->cached_frame.dest);
    printf("WIFI: transmitting frame for node MAC: %s\n", dest_nicaddr);
  }

  printf("dll_wifi_handle_cts RETURN\n");
}

/// Attempt to associate with an AP
void dll_wifi_associate_request(struct dll_wifi_state *state,
                       CnetNICaddr dest_addr)
{
  printf("dll_wifi_associate_request\n");

  char dest_addr_string[17];
  CNET_format_nicaddr(dest_addr_string, (unsigned char *)dest_addr);
  printf("Wifi: requesting association from: %s\n", dest_addr_string);

  WIFI_FRAME_KIND kind = WIFI_ASSOCIATE_REQUEST;
  
  struct wifi_assoc_request_info info;
  memcpy(info.mobile_addr, linkinfo[state->link].nicaddr, sizeof(CnetNICaddr));
  info.node_number = nodeinfo.address;
  
  print_nic(dest_addr);
  dll_wifi_queue_frame(state, dest_addr, (char *)&info, sizeof(struct wifi_assoc_request_info), kind, true);

  printf("dll_wifi_associate_request RETURN\n");
}

/// send a disassociation notice frame to a previously-associated AP
void dll_wifi_disassociate(struct dll_wifi_state *state, CnetNICaddr dest_addr)
{
  printf("dll_wifi_disassociate\n");

  state->assoc_record.valid = false;

  char dest_addr_string[17];
  CNET_format_nicaddr(dest_addr_string, (unsigned char *)dest_addr);
  printf("Wifi: sending disassociation notice to: %s\n", dest_addr_string);

  WIFI_FRAME_KIND kind = WIFI_DISASSOCIATE_NOTICE;
  dll_wifi_queue_frame(state, dest_addr, (char *)(linkinfo[state->link].nicaddr), sizeof(CnetNICaddr), kind, true);

  printf("dll_wifi_disassociate RETURN\n");
}

/// As a mobile node, go through the gathered AP records, choose the best one and associate with it if it isn't already
void dll_wifi_reassociate(struct dll_wifi_state *state) 
{
  printf("dll_wifi_reassociate\n");
  printf("###########################\n");
  printf("###########################\n");
  printf("###########################\n");
  printf("###########################\n");
  printf("###########################\n");
  printf("###########################\n");
  printf("###########################\n");
  printf("###########################\n");

  // find the AP with the best signal strength for this node
  double best_dbm = 0;
  int best_index = 0;
  bool found = false;
  int i;
  for (i = 0; i < WIFI_MAX_ASSOCIATED_CLIENTS; i++)
  {
    if(state->ap_record_table[i].up_to_date) 
    {
      if(best_dbm == 0 || state->ap_record_table[i].latest_sig_strength > best_dbm)
      {
        best_dbm = state->ap_record_table[i].latest_sig_strength;
        best_index = i;
        found = true;
      }
    }
  }

  // if we have chosen an AP, attempt to associate with it if it isn't already associated
  if(found)
  {
    char best_ap[17];
    CNET_format_nicaddr(best_ap, state->ap_record_table[best_index].ap_nic_addr);
    char current_ap[17];
    CNET_format_nicaddr(current_ap, state->assoc_record.associated_ap);
    if(strcmp(best_ap, current_ap) != 0)
    {
      if(state->assoc_record.valid)
      {
        dll_wifi_disassociate(state, state->assoc_record.associated_ap);
      }
      printf("state->ap_record_table[best_index].ap_nic_addr:\n");
      print_nic(state->ap_record_table[best_index].ap_nic_addr);
      dll_wifi_associate_request(state, state->ap_record_table[best_index].ap_nic_addr); // OF INTEREST
    }
  }

  printf("dll_wifi_reassociate RETURN\n");
}

/// on receiving a disassiciation notice, clear the association record for the notifying node
void dll_wifi_handle_disassociation_notice(struct dll_wifi_state *state, CnetNICaddr *addr_ptr)
{
  printf("dll_wifi_handle_disassociation_notice\n");

  CnetNICaddr client_addr;
  memcpy(&client_addr, addr_ptr, sizeof(CnetNICaddr *));
  char client_addr_string[17];
  CNET_format_nicaddr(client_addr_string, client_addr);

  printf("Wifi: disassociated from %s\n", client_addr_string);
  
  int i;
  for (i = 0; i < WIFI_MAX_ASSOCIATED_CLIENTS; i++)
  {
    if((state->assoc_records)[i].valid) 
    {
      char record_addr_string[17];
      CNET_format_nicaddr(record_addr_string, (unsigned char *)(state->assoc_records[i].associated_client));
      if(strcmp(client_addr_string, record_addr_string) == 0) 
      {
        state->assoc_records[i].valid = false;
      }
    } 
  }

  printf("dll_wifi_handle_disassociation_notice RETURN\n");
}

/// As an AP, respond to an association request from a mobile node
void dll_wifi_associate_respond(struct dll_wifi_state *state, struct wifi_assoc_request_info *info)
{
  printf("dll_wifi_associate_respond\n");

  char client_addr_string[17];
  CNET_format_nicaddr(client_addr_string, (unsigned char *)info->mobile_addr);
  printf("Wifi: responding to association request from: %s, node number: %i\n", client_addr_string, info->node_number);

  bool found = false;
  int i;
  int min_empty_slot = WIFI_MAX_ASSOCIATED_CLIENTS;
  for (i = 0; i < WIFI_MAX_ASSOCIATED_CLIENTS; i++)
  {
    if((state->assoc_records)[i].valid) 
    {
      char record_addr_string[17];
      CNET_format_nicaddr(record_addr_string, (unsigned char *)(state->assoc_records[i].associated_client));
      if(strcmp(client_addr_string, record_addr_string) == 0) 
      {
	      // If this client is already in the association table, update the entry
        state->assoc_records[i].valid = true;
        state->assoc_records[i].association_time = nodeinfo.time_of_day.usec;
        memcpy(state->assoc_records[i].associated_client, info->mobile_addr, sizeof(CnetNICaddr));
        state->assoc_records[i].client_node_number = info->node_number;

        printf("state->assoc_records[i].client_node_number: %i\n", state->assoc_records[i].client_node_number);
              
        found = true;
	      break;
      }
    } 
    else if(i < min_empty_slot)
    {
      min_empty_slot = i;
    }
  }

  // If this client is not yet in the association table, add it to the first available slot
  if(!found && min_empty_slot < WIFI_MAX_ASSOCIATED_CLIENTS)
  {
    struct wifi_ap_assoc_record rec;
    memcpy(rec.associated_client, info->mobile_addr, sizeof(CnetNICaddr));
    rec.valid = true;
    rec.association_time = nodeinfo.time_of_day.usec;
    rec.client_node_number = info->node_number;
    state->assoc_records[min_empty_slot] = rec;

    printf("state->assoc_records[min_empty_slot].client_node_number: %i\n", state->assoc_records[min_empty_slot].client_node_number);
  }

  // If the association was successful, send an association confirmation to the client and inform the NL
  if(found || min_empty_slot < WIFI_MAX_ASSOCIATED_CLIENTS) 
  {
    WIFI_FRAME_KIND kind = WIFI_ASSOCIATE_CONFIRM;
    dll_wifi_queue_frame(state, info->mobile_addr, (char *)(linkinfo[state->link].nicaddr), sizeof(CnetNICaddr), kind, true);
    
    if(ENABLE_ROUTING) { state->new_assoc_callback(&(info->mobile_addr), info->node_number); }
  }

  printf("dll_wifi_associate_respond RETURN\n");
}

// Change the association record for this mobile node in response to an association confirmation frame
void dll_wifi_associate_record(struct dll_wifi_state *state, CnetNICaddr *addr_ptr)
{
  printf("dll_wifi_associate_record\n");

  CnetNICaddr ap_addr;
  memcpy(&ap_addr, addr_ptr, sizeof(CnetNICaddr *));
  char ap_addr_string[17];
  CNET_format_nicaddr(ap_addr_string, ap_addr);
  printf("Wifi: association confirmed from: %s\n", ap_addr_string);


  memcpy(state->assoc_record.associated_ap, ap_addr, sizeof(CnetNICaddr));
  state->assoc_record.valid = true;

  printf("dll_wifi_associate_record RETURN\n");
}

/// Write a data frame to the given WiFi link.
void dll_wifi_write(struct dll_wifi_state *state,
                       CnetNICaddr dest,
                       const char *data,
                       uint16_t length)
{
  printf("dll_wifi_write\n");

  WIFI_FRAME_KIND kind = WIFI_DATA;
  dll_wifi_queue_frame(state, dest, (char *)data, length, kind, true);

  printf("dll_wifi_write RETURN\n");
}

// send a wifi probe frame to discover APs and determine RTT and signal strength
void dll_wifi_probe(struct dll_wifi_state *state)
{
  printf("dll_wifi_probe\n");

  printf("\tWiFi: probing for APs.\n"); 

  struct wifi_probe_info info;
  memcpy(info.mobile_addr, linkinfo[state->link].nicaddr, sizeof(CnetNICaddr));
  info.send_timestamp = nodeinfo.time_of_day.usec;

  CnetNICaddr broadcast_addr;
  CHECK(CNET_parse_nicaddr(broadcast_addr, WIFI_BROADCAST_ADDR_STRING));
  
  size_t length = sizeof(struct wifi_probe_info);

  WIFI_FRAME_KIND kind = WIFI_PROBE;

  //clear the record table for the new entries
  int i;
  for(i = 0; i < WIFI_MAX_AP_RECORDS; i++)
  {
    struct wifi_ap_record new_ap_record;
    new_ap_record.up_to_date = false;
    state->ap_record_table[i] = new_ap_record;
  }

  dll_wifi_queue_frame(state, broadcast_addr, (char *)&info, length, kind, false);

  printf("dll_wifi_probe RETURN\n");
}

/// respond to a wifi probe request (as an AP)
void dll_wifi_probe_respond(struct dll_wifi_state *state, struct wifi_probe_info *info) 
{
  printf("dll_wifi_probe_respond\n");

  struct wifi_probe_response_info response_info;

  memcpy(response_info.ap_addr, linkinfo[state->link].nicaddr, sizeof(CnetNICaddr));
  response_info.send_timestamp = info->send_timestamp;

  size_t length = sizeof(struct wifi_probe_response_info);

  WIFI_FRAME_KIND kind = WIFI_PROBE_RESPONSE;
  
  printf("queueing probe response..\n");
  dll_wifi_queue_frame(state, info->mobile_addr, (char *)&response_info, length, kind, false);

  char mobile_addr_string[17];
  CNET_format_nicaddr(mobile_addr_string, (unsigned char *)info->mobile_addr);
  printf("\t Wifi: responded to probe request from %s\n", mobile_addr_string);

  printf("dll_wifi_probe_respond RETURN\n");
}

/// add a received probe response RTT record to the (recently cleared) AP table
void dll_wifi_update_ap_records(struct dll_wifi_state *state, struct wifi_probe_response_info *info, CnetTime recv_time)
{
  printf("dll_wifi_update_ap_records\n");

  CnetTime send_time = info->send_timestamp;
  CnetTime rtt = recv_time - send_time;
  double signal_dBm;
  CNET_wlan_arrival(state->link, &signal_dBm, NULL);

  struct wifi_ap_record rec;
  memcpy(rec.ap_nic_addr, info->ap_addr, sizeof(CnetNICaddr));
  rec.latest_rtt = rtt;
  rec.latest_sig_strength = signal_dBm;
  rec.up_to_date = true;

  int i;
  for(i = 0; i < WIFI_MAX_AP_RECORDS; i++)
  {
    if(!(state->ap_record_table[i].up_to_date))
    {
      state->ap_record_table[i] = rec;
      
      char ap_addr_string[17];
      CNET_format_nicaddr(ap_addr_string, (unsigned char *)info->ap_addr);
      printf("Wifi: updated AP record for %s with RTT: %ld, dBm: %f.\n", ap_addr_string, rtt, signal_dBm);
      break;
    }
  }

  printf("dll_wifi_update_ap_records RETURN\n");
}

/// Transmit some data over the WiFi link.
void dll_wifi_transmit(struct dll_wifi_state *state,
                       CnetNICaddr dest,
                       const char *data,
                       uint16_t length,
                       WIFI_FRAME_KIND kind,
                       bool require_cts)
{
  printf("dll_wifi_transmit\n");

  if (!data || length == 0 || length > WIFI_MAXDATA)
    return;
  
  // Create a frame and initialize the length field.
  struct wifi_frame frame = (struct wifi_frame){
    .control = (struct wifi_control){
      .from_ds = (state->is_ds ? 1 : 0),
      .kind = kind
    },
    .length = length
  };
 
  print_nic(dest);
  // Set the destination and source address.
  memcpy(frame.dest, dest, sizeof(CnetNICaddr));
  memcpy(frame.src, linkinfo[state->link].nicaddr, sizeof(CnetNICaddr));
  
  // Copy in the payload.
  memcpy(frame.data, data, length);
  
  // Set the checksum.
  frame.checksum = 0;
  frame.checksum = CNET_crc32((unsigned char *)&frame, sizeof(WIFI_HEADER_LENGTH + length));
  
  // Calculate the number of bytes to send.
  size_t frame_length = WIFI_HEADER_LENGTH + length;

  if(require_cts)
  {
    printf("resetting RTS resend attempts\n");
    state->rts_resend_attempts = 0;
    state->cached_frame = frame;
    state->cached_frame_length = frame_length;
    if(state-> can_send) 
    {
      state->can_send = false;
      state->waiting_for_cts = true;
      dll_wifi_send_rts(state, dest, WIFI_RTS_CTS_PERIOD);
    } else {
      state->waiting_for_cts = true;
    }
  } else {
    char dest_addr_string[17];
    CNET_format_nicaddr(dest_addr_string, (unsigned char *)frame.dest);

    printf("dll_wifi_transmit to dest: %s\n", dest_addr_string);
    CHECK(CNET_write_physical(state->link, &frame, &frame_length));
  }

  printf("dll_wifi_transmit RETURN\n");
}

// Notify the NL that this link is ready to accept a frame
void dll_wifi_notify_ready(struct dll_wifi_state *state)
{
  printf("dll_wifi_notify_ready\n");

  if(state->can_send) 
  {
    if(!state->is_ds || state->assoc_record.valid)
	  {
	    (*(state->nl_ready))(state->link);
	  }
  }

  printf("dll_wifi_notify_ready RETURN\n");
}

// check if this DLL is ready to accept a frame, and notify the upper layers if so
void dll_wifi_check_ready(struct dll_wifi_state *state)
{
  if(!state->waiting_for_cts && state->can_send)
  {
    if(state->frame_queue.active[state->frame_queue.head])
    {
      printf("WIFI: transmitting queued frame\n");
      int i = state->frame_queue.head;
      print_nic(state->frame_queue.dest[i]);
      dll_wifi_transmit(state, state->frame_queue.dest[i], state->frame_queue.data[i].data, state->frame_queue.length[i], state->frame_queue.kind[i], 
                        state->frame_queue.require_cts[i]); 
      
      state->frame_queue.active[i] = false;
      state->frame_queue.head = (state->frame_queue.head + 1) % WIFI_FRAME_QUEUE_LENGTH;
    } else {
      printf("WIFI: notifying ready\n");
      dll_wifi_notify_ready(state);
    }
  } else {
   printf("WIFI: not ready; waiting_for_cts: %i, can_send: %i\n", state->waiting_for_cts, state->can_send);
  }

  printf("dll_wifi_check_ready RETURN\n");
}

// End the back-off, then send an RTS for the waiting frame if there is one, otherwise prepare to accept a frame
void dll_wifi_backon(struct dll_wifi_state *state)
{
  printf("dll_wifi_backon\n");

  state->can_send = true;
  if(state->waiting_for_cts)
  {
    dll_wifi_send_rts(state, state->cached_frame.dest, WIFI_RTS_CTS_PERIOD);
  } else {
    dll_wifi_check_ready(state);
  }

  printf("dll_wifi_backon RETURN\n");
}

/// Called when a frame has been received on the WiFi link. This function will
/// retrieve the payload, and then pass it to the callback function that is
/// associated with the given state struct.
///
void dll_wifi_read(struct dll_wifi_state *state,
                   const char *data,
                   size_t length)
{
  printf("dll_wifi_read\n");

  printf("WiFi: read from link %d with length %zd\n", state->link, length);
  
  if (length > sizeof(struct wifi_frame)) {
    printf("\tFrame is too large!\n");
    return;
  }
  
  // Treat the data as a WiFi frame.
  struct wifi_frame *frame = (struct wifi_frame *)data;
  
  // Check the frame's checksum
  uint32_t checksum_value = frame->checksum;
  frame->checksum = 0;
  frame->checksum = CNET_crc32((unsigned char *)frame, sizeof(WIFI_HEADER_LENGTH + frame->length));
  if(checksum_value != frame->checksum) 
  {
    // drop the frame and let the client resend
    printf("Wifi: encountered invalid checksum\n", frame->checksum, checksum_value);
    return;
  }
 
  char dest_addr_string[17];
  CNET_format_nicaddr(dest_addr_string, (unsigned char *)frame->dest);

  char my_addr_string[17];
  CNET_format_nicaddr(my_addr_string, linkinfo[state->link].nicaddr);

  printf("\tWifi: received frame for dest: %s\n", dest_addr_string, my_addr_string);

  if (strcmp(dest_addr_string, my_addr_string) != 0  && strcmp(dest_addr_string, WIFI_BROADCAST_ADDR_STRING) != 0) 
  { 
    return; 
  }
  
  // Send the frame up to the next layer.
  switch(frame->control.kind)
  {
    case WIFI_DATA:
      printf("Frame type WIFI_DATA\n");
      if (state->nl_callback)
        (*(state->nl_callback))(state->link, frame->data, frame->length);
      break;

    case WIFI_PROBE:
      printf("Frame type WIFI_PROBE\n");
      if(state->is_ds) {
        dll_wifi_probe_respond(state, (struct wifi_probe_info *)&(frame->data));
      }
      break;

    case WIFI_PROBE_RESPONSE:
      printf("Frame type WIKI_PROBE_RESPONSE\n");
      if(!(state->is_ds)) {
	    long recv_time = nodeinfo.time_of_day.usec;
        dll_wifi_update_ap_records(state, (struct wifi_probe_response_info *)&(frame->data), recv_time);
      }
      break;

    case WIFI_ASSOCIATE_REQUEST:
      printf("Frame type WIFI_ASSOCIATE_REQUEST\n");
      if(state->is_ds) {
        dll_wifi_associate_respond(state, (struct wifi_assoc_request_info *)&(frame->data));
      }
      break;

    case WIFI_ASSOCIATE_CONFIRM:
      printf("Frame type WIFI_ASSOCIATE_CONFIRM\n");
      if(!(state->is_ds)) {
        dll_wifi_associate_record(state, (CnetNICaddr *)&(frame->data));
      }
      break;
	  
    case WIFI_DISASSOCIATE_NOTICE:
      printf("Frame type WIFI_DISASSOCIATE_NOTICE\n");
      if(state->is_ds) {
        dll_wifi_handle_disassociation_notice(state, (CnetNICaddr *)&(frame->data));
      }
      break;
	
    case WIFI_RTS:
      printf("Frame type WIFI_RTS\n");
      dll_wifi_handle_rts(state, (struct wifi_rts_cts_info *)&(frame->data));
      break;

    case WIFI_CTS:
      printf("Frame type WIFI_CTS\n");
      dll_wifi_handle_cts(state, (struct wifi_rts_cts_info *)&(frame->data));
      break;

    default:
      printf("WiFi: unsupported frame kind encountered.\n");  
  }

  printf("dll_wifi_read RETURN\n");
}
