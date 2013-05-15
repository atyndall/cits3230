/// This file implements our Ethernet data link layer.

#include "dll_ethernet.h"

#include <cnet.h>
#include <inttypes.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>

/// Create a new state for an instance of the Ethernet data link layer.
///
struct dll_eth_state *dll_eth_new_state(int link, up_from_dll_fn_ty callback)
{
  // Ensure that the given link exists and is a LAN link.
  if (link > nodeinfo.nlinks || linkinfo[link].linktype != LT_LAN)
    return NULL;
  
  // Allocate memory for the state.
  struct dll_eth_state *state = calloc(1, sizeof(struct dll_eth_state));
  
  // Check whether or not the allocation was successful.
  if (state == NULL)
    return NULL;
  
  // Initialize the members of the structure.
  state->link = link;
  state->nl_callback = callback;
  
  int i;
  for(i = 0; i < ETHER_QUEUE_LENGTH; i++)
  {
    state->data_queue.active[i] = false;
    state->priority_queue.active[i] = false;
    
    state->data_queue.head = 0;
    state->priority_queue.head = 0;
  }
  
  state->backed_off = false;
  state->resend_frame = false;
  
  return state;
}

/// Delete the given dll_eth_state. The given state pointer will be invalid
/// following a call to this function.
///
void dll_eth_delete_state(struct dll_eth_state *state)
{
  if (state == NULL)
    return;
  
  // Free any dynamic memory that is used by the members of the state.
  
  free(state);
}


// place a frame on the outgoing frame queue for this DLL. if priority is set to true,
// the frame is placed in the priority queue instead (used for routing information packets
// if routing is enabled)
void eth_queue_frame(struct dll_eth_state *state, struct eth_frame *frame, bool priority)
{
  struct ether_queue *queue;
  
  if(priority)
  {
    queue = &(state->priority_queue);
  } else {
    queue = &(state->data_queue);
  }

  int i;
  for(i = queue->head; i < ETHER_QUEUE_LENGTH + queue->head; i++)
  {
    if(!queue->active[i % ETHER_QUEUE_LENGTH])
    {
      queue->frame_queue[i] = *frame;
      queue->active[i] = true;
      queue->send_attempts[i] = 0;
      
      printf("ETH: queued frame at index %i, head: %i\n", i, queue->head);
      
      dll_eth_carrier_sense(state);
      return;
    }
  }
  printf("ETH ERROR: too many frames to fit in ethernet output queue\n");
}

// Called when this DLL is not backed off, and the channel has been sensed
// to be clear: resends the current frame, or sends the next frame in the queue
// (if the priority queue has any packets to send, these are handled first)
void dll_eth_send_next_frame(struct dll_eth_state *state)
{
  struct ether_queue *queue;
  
  if(state->priority_queue.active[state->priority_queue.head])
  {
    queue = &(state->priority_queue);
  } else {
    queue = &(state->data_queue);
  }
  
  if(!state->resend_frame && queue->send_attempts[queue->head] > 0) {
    printf("advancing head of queue to index %i; sent_attempts: %i\n", (queue->head + 1) % ETHER_QUEUE_LENGTH, queue->send_attempts[queue->head]);
    queue->active[queue->head] = false;
    queue->send_attempts[queue->head] = 0;
    queue->head = (queue->head + 1) % ETHER_QUEUE_LENGTH;
  }
  
  state->resend_frame = false;
  
  if(!queue->active[queue->head]) { 
    printf("ETH: no frames in queue\n");
    return;   
  }
  
  queue->send_attempts[queue->head]++;
  
  uint16_t data_len;
  memcpy(&data_len, queue->frame_queue[queue->head].type, sizeof(data_len));
  size_t length = data_len + ETH_HEADER_LENGTH;

  printf("ETH: attempting to send frame\n");
  CHECK(CNET_write_physical(state->link, (char *)&(queue->frame_queue[queue->head]), &length));

  dll_eth_carrier_sense(state);
}

// called when there is a collision of an outgoing frame. computes the backoff time
// and places this DLL into back-off mode
void dll_eth_handle_collision(struct dll_eth_state *state)
{
  printf("ETH: collision\n");

  state->backed_off = true;
  state->resend_frame = true;
  
  struct ether_queue *queue;
  
  if(state->priority_queue.active[state->priority_queue.head])
  {
    queue = &(state->priority_queue);
  } else {
    queue = &(state->data_queue);
  }
  
  int max_wait;
  if(queue->send_attempts[queue->head] <= 10)
  {
    max_wait = 2^(queue->send_attempts[queue->head]);
  } else if(queue->send_attempts[queue->head] <= 16)
  {
    max_wait = 1023;
  } else {
    queue->active[queue->head] = false;
    queue->send_attempts[queue->head] = 0;
    queue->head = (queue->head + 1) % ETHER_QUEUE_LENGTH;
    printf("ETH ERROR: too many frame retransmission attempts, dropped\n");
    return;
  }

  int wait_slots = CNET_rand() % (max_wait + 1);
  
  queue->send_attempts[queue->head]++;
  
  printf("ETH: starting backoff timer, wait: %i, link: %i\n", ((CnetTime)(wait_slots*ETHER_SLOT_TIME)), (int)(state->link));

  if(wait_slots == 0) 
  {
    dll_eth_backon(state);
  } else {
   CNET_start_timer(ETHER_BACKOFF_TIMER, (CnetTime)(wait_slots*ETHER_SLOT_TIME), (int)(state->link));
  }
}

// checks if the channel is clear and attempts to send the next frame if the channel is clear and this DLL
// is not backed-off. then schedules the next check if there are any packets left to send, and this DLL
// is not backed off
void dll_eth_carrier_sense(struct dll_eth_state *state)
{
  if (CNET_carrier_sense(state->link) == 0 && !state->backed_off)  
  {
    dll_eth_send_next_frame(state);
  } else {
    printf("ETH: not sending yet, carrier: %i, backed_off: %i\n", CNET_carrier_sense(state->link), (int)state->backed_off);
  }
  
  if((state->priority_queue.active[state->priority_queue.head] || state->data_queue.active[state->data_queue.head]) && !state->backed_off)
  {
    CNET_start_timer(ETHER_CARRIER_SENSE_TIMER, (CnetTime)ETHER_CARRIER_SENSE_TIME, state->link);
  } else {
    printf("ETH: not starting timer, backed_off: %i\n", (int)state->backed_off);
  }
}

// called when this DLL comes out of back-off mode
void dll_eth_backon(struct dll_eth_state *state)
{
  state->backed_off = false;
  dll_eth_carrier_sense(state);
}

/// Write a frame to the given Ethernet link.
///
void dll_eth_write(struct dll_eth_state *state,
                   CnetNICaddr dest,
                   const char *data,
                   uint16_t length,
                   bool priority)
{
  if (!data || length == 0)
    return;
  
  struct eth_frame frame;
  
  // Set the destination and source address.
  memcpy(frame.dest, dest, sizeof(CnetNICaddr));
  memcpy(frame.src, linkinfo[state->link].nicaddr, sizeof(CnetNICaddr));
  
  // Set the length of the payload.
  memcpy(frame.type, &length, sizeof(length));
  
  // Copy the payload into the frame.
  memcpy(frame.data, data, length);
  
  // Calculate the number of bytes to send.
  size_t frame_length = length + ETH_HEADER_LENGTH;
  if (frame_length < ETH_MINFRAME)
  frame_length = ETH_MINFRAME;


  char dest_nicaddr_string[17];
  CNET_format_nicaddr(dest_nicaddr_string, frame.dest);
  printf("ETH: queuing frame for dest MAC: %s\n", dest_nicaddr_string);
  
  eth_queue_frame(state, &frame, priority);
  
  dll_eth_carrier_sense(state);
  
  //CHECK(CNET_write_physical_reliable(state->link, &frame, &frame_length));
}

/// Called when a frame has been received on the Ethernet link. This function
/// will retrieve the payload, and then pass it to the callback function that
/// is associated with the given state struct.
///
void dll_eth_read(struct dll_eth_state *state,
                  const char *data,
                  size_t length)
{
  // printf("Ethernet: read frame of length %zd.\n", length);
  
  if (length > sizeof(struct eth_frame)) {
    // printf("\tFrame is too large!\n");
    return;
  }
  
  // Treat the data as an Ethernet frame.
  struct eth_frame *frame = (struct eth_frame *)data;
  
  // Extract the length of the payload from the Ethernet frame.
  uint16_t payload_length = 0;
  memcpy(&payload_length, frame->type, sizeof(payload_length));
  
  char frame_dest_string[17];
  CNET_format_nicaddr(frame_dest_string, frame->dest);
  
  char my_nicaddr_string[17];
  CNET_format_nicaddr(my_nicaddr_string, linkinfo[state->link].nicaddr);
  
  
  if(strcmp(frame_dest_string, my_nicaddr_string) != 0 && strcmp(frame_dest_string, ETHER_BROADCAST_ADDR_STRING) != 0) { return; }
  
  printf("ETH: got frame addressed to this node\n");
  
  // Send the frame up to the next layer.
  if (state->nl_callback)
    (*(state->nl_callback))(state->link, frame->data, payload_length);
}
