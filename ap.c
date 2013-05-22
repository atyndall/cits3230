/// This file implements the functionality of our access points.

#include <cnet.h>
#include <inttypes.h>
#include <stdlib.h>
#include <string.h>

#include "ap.h"
#include "dll_ethernet.h"
#include "dll_wifi.h"
#include "mapping.h"
#include "network.h"
#include "helpers.h"

#define WIFI_BUFFER_LENGTH (100)

/// This enumerates the possible types of data link layers used by an AP.
///
enum dll_type {
  DLL_UNSUPPORTED,
  DLL_ETHERNET,
  DLL_WIFI
};

/// This holds the data link layer type and state for a single link on an AP.
///
struct dll_state {
  enum dll_type type;
  
  union {
    struct dll_eth_state *ethernet;
    struct dll_wifi_state *wifi;
  } data;
};

// struct of packets waiting to be sent out on a wifi DLL
struct wifi_output_queue {
  // the packets waiting to be sent
  struct nl_packet packet_queue[WIFI_BUFFER_LENGTH];
  
  // for each packet, true iff it exists (false if it is an empty queue position)
  bool active[WIFI_BUFFER_LENGTH];
  
  // for each packet, the link it needs to be sent out on
  int link[WIFI_BUFFER_LENGTH];
  
  // for each packet, its length
  size_t length[WIFI_BUFFER_LENGTH];
  
  // for each packet, the destination MAC address
  CnetNICaddr dest[WIFI_BUFFER_LENGTH];
  
  // the index of the head of this queue
  int head;
};

/// This holds the data link layer information for all links on this AP.
///
static struct dll_state *dll_states = NULL;

/// the wifi frame output queue for this node
static struct wifi_output_queue wifi_out_queue;

/// Raised when one of our physical links has received a frame.
///
static EVENT_HANDLER(physical_ready)
{
  //printf("physical_ready\n");

  // First we read the frame from the physical layer.
  char frame[DLL_MTU];
  size_t length	= sizeof(frame);
  int link;

  CHECK(CNET_read_physical(&link, frame, &length));
  
  // Now we forward this information to the correct data link layer.
  if (link > nodeinfo.nlinks) {
    printf("AP: Received frame on unknown link %d.\n", link);
    return;
  }
  
  switch (dll_states[link].type) {
    case DLL_UNSUPPORTED:
      printf("AP: Received frame on unsupported link.\n");
      break;
    
    case DLL_ETHERNET:
      printf("AP: Received frame on Ethernet link %d.\n", link);
      dll_eth_read(dll_states[link].data.ethernet, frame, length);
      break;
    
    case DLL_WIFI:
      printf("AP: Received frame on WiFi link %d.\n", link);
      dll_wifi_read(dll_states[link].data.wifi, frame, length);
      break;
  }

  //printf("physical_ready RETURN\n");
}

// print this node's routing table to its output stream
void print_routing_table(int link)
{
  if(dll_states[link].type != DLL_ETHERNET) { return; }
  
  printf("\n---------------- %s ROUTING TABLE -----------------\n", linkinfo[link].linkname);
  printf("MOBILE MAC           AP MAC               MOBILE ADDR\n");
  
  int j;
  for(j = 0; j < ROUTING_TABLE_ROWS; j++)
  {
    if(!(dll_states[link].data.ethernet->routing_table[j].active)) { break; }
  
    char mobile_nic_string[17];
    CNET_format_nicaddr(mobile_nic_string, dll_states[link].data.ethernet->routing_table[j].mobile_nic_addr);
    
    char ap_nic_string[17];
    CNET_format_nicaddr(ap_nic_string, dll_states[link].data.ethernet->routing_table[j].ap_nic_addr);
    
    int mobile_num_addr = (int)(dll_states[link].data.ethernet->routing_table[j].mobile_num_addr);
    
    printf("%s    %s    %i\n", mobile_nic_string, ap_nic_string, mobile_num_addr);
  }
  printf("-----------------------------------------------------\n\n");
}

EVENT_HANDLER(print_routing_tables)
{
  for (int link = 0; link <= nodeinfo.nlinks; ++link) {
    print_routing_table(link);
  }
}

EVENT_HANDLER(print_associated_nodes)
{
  printf("\nASSOCIATIONS\n");
  for (int link = 0; link <= nodeinfo.nlinks; ++link) {
    if(dll_states[link].type == DLL_WIFI) {
      printf("  %s\n", linkinfo[link].linkname);
      int asci = 0;
      for (int assc = 0; assc <= WIFI_MAX_ASSOCIATED_CLIENTS; ++assc) {
        struct wifi_ap_assoc_record r = dll_states[link].data.wifi->assoc_records[assc];
        if (r.valid) {
          char mac[17];
          CNET_format_nicaddr(mac, r.associated_client);
          printf("    MAC: %s, addr: %d, time: %d\n", mac, r.client_node_number, r.association_time);
          asci++;
        }
      }
      if (asci == 0) {
        printf("    None\n");
      }
    }
  }
}

// print the contents of a routing info packet to this node's output stream
void print_routing_info_packet(struct nl_packet *packet)
{
  struct routing_info_entry info[ROUTING_TABLE_ROWS];
  memcpy(info, packet->data, ROUTING_TABLE_ROWS * sizeof(struct routing_info_entry));
  
  
  printf("\n--------------- ROUTING INFO PACKET ---------------\n");
  
  int j;
  for(j = 0; j < ROUTING_TABLE_ROWS; j++)
  {
    char mobile_nic_string[17];
    CNET_format_nicaddr(mobile_nic_string, info[j].mobile_nic_addr);
    
    char ap_nic_string[17];
    CNET_format_nicaddr(ap_nic_string, info[j].ap_nic_addr);
    
    int mobile_num_addr = (int)(info[j].mobile_num_addr);
    
    int active = (int)info[j].active;
    
    printf("%s    %s    %i    %i\n", mobile_nic_string, ap_nic_string, mobile_num_addr, active);
  }
  printf("-----------------------------------------------------\n\n");
}

// given a routing_info_entry struct, updates this node's routing table with the information
bool update_routing_info_entry(int link, struct routing_info_entry *info_ptr)
{
  //printf("update_routing_info_entry\n");
  
  bool ap_changed = false;

  struct routing_info_entry info;
  memcpy(&info, info_ptr, sizeof(struct routing_info_entry)); 

  int j;
  bool found_inactive;
  int first_inactive_index;
  bool found_match = false;
  for(j = 0; j < ROUTING_TABLE_ROWS; j++)
  {
    if(info.mobile_num_addr == dll_states[link].data.ethernet->routing_table[j].mobile_num_addr)
    {
      // if the new routing information for this mobile node is newer than the
      // currently recorded information, update the record with the new info
      // (clearly this does not account for the latency of the routing
      // information packet -- this doesn't really matter, as the delay is very
      // small compared to the frequency at which a mobile node could be
      // reasonably expected to associate and disassociate from the APs
      // (seconds vs milliseconds) - the additional overhead introduced
      // by attempting to sync the clocks would probably be worse than
      // the effect of the tiny probability of a temporarily incorrect
      // routing entry (which would merely prompt a repeat of the misdelivered
      // packet from the source node anyway))
      
      found_match = true;
      
      CnetTime new_local_create_time = nodeinfo.time_of_day.usec - info.age;
      
      char old_ap_nic_addr_string[17];
      CNET_format_nicaddr(old_ap_nic_addr_string, dll_states[link].data.ethernet->routing_table[j].ap_nic_addr);
      
      char new_ap_nic_addr_string[17];
      CNET_format_nicaddr(new_ap_nic_addr_string, info.ap_nic_addr);
      
      if(new_local_create_time > dll_states[link].data.ethernet->routing_table[j].local_create_time)
      {
        memcpy(dll_states[link].data.ethernet->routing_table[j].mobile_nic_addr, info.mobile_nic_addr, sizeof(CnetNICaddr));
        memcpy(dll_states[link].data.ethernet->routing_table[j].ap_nic_addr, info.ap_nic_addr, sizeof(CnetNICaddr));
        dll_states[link].data.ethernet->routing_table[j].local_create_time = new_local_create_time;
              
        // if the old recorded ap mac is the same as the new one, no need to update the mac      
        if(strcmp(old_ap_nic_addr_string, new_ap_nic_addr_string) != 0)
        {
          ap_changed = true;
        }
        
      }
      break;
    }
  } 
  if(!found_match)
  {
    found_inactive = false;
    first_inactive_index = 0;
    for(j = 0; j < ROUTING_TABLE_ROWS; j++)
    {
      if(!dll_states[link].data.ethernet->routing_table[j].active)
      {
        found_inactive = true;
        first_inactive_index = j;
        break;
      }
    }
    
    if(!found_inactive)
    {
      //printf("AP ERROR: too many destination nodes to fit in routing table, entry dropped\n");
      return false;
    }
    
    // add the entry to the routing table
    struct routing_table_entry entry;
    dll_states[link].data.ethernet->routing_table[first_inactive_index] = entry;
    memcpy(dll_states[link].data.ethernet->routing_table[first_inactive_index].mobile_nic_addr, info.mobile_nic_addr, sizeof(CnetNICaddr));
    dll_states[link].data.ethernet->routing_table[first_inactive_index].mobile_num_addr = info.mobile_num_addr;
    memcpy(dll_states[link].data.ethernet->routing_table[first_inactive_index].ap_nic_addr, info.ap_nic_addr, sizeof(CnetNICaddr));
    dll_states[link].data.ethernet->routing_table[first_inactive_index].local_create_time = nodeinfo.time_of_day.usec - info.age;
    dll_states[link].data.ethernet->routing_table[first_inactive_index].active = true;
    
    ap_changed = true;
  }
  
  
  return ap_changed;
  //printf("update_routing_info_entry RETURN\n");
}

// given an array of routing_info_entry structs (as extracted from a routing info packet),
// updates this node's routing table accordingly
void update_routing_info(int link, struct routing_info_entry *info_array_ptr)
{
  //printf("update_routing_info\n");

  // treat data as array of routing_info_entry structs
  struct routing_info_entry info[ROUTING_TABLE_ROWS];
  memset(info, 0, ROUTING_TABLE_ROWS * sizeof(struct routing_info_entry));
  memcpy(info, info_array_ptr, ROUTING_TABLE_ROWS * sizeof(struct routing_info_entry));
  
  bool ap_changed = false;
  
  int i;
  for(i = 0; i < ROUTING_TABLE_ROWS; i++)
  {
    if(info[i].active) 
    {
      //printf("updating table with packet info index: %i\n", i);
      if(update_routing_info_entry(link, &info[i]))
      {
        ap_changed = true;
      }
    }
  }
  
  print_routing_table(link);
  
  if(ap_changed)
  {
    broadcast_routing_info(link);
  }
  
  //printf("update_routing_info RETURN\n");
}

// broadcast a routing info packet to inform other nodes of the routing information held by this node
void broadcast_routing_info(int link)
{
  //printf("broadcast_routing_info\n");

  struct nl_packet packet = (struct nl_packet){
    .src = nodeinfo.address,
  };

  NL_PACKET_KIND kind = NL_ROUTING_INFO;
  packet.kind = kind;
  
  struct routing_info_entry info[ROUTING_TABLE_ROWS];
  
  int i;
  for(i = 0; i < ROUTING_TABLE_ROWS; i++)
  {
    struct routing_info_entry new_entry;
    info[i] = new_entry;
    
    if(dll_states[link].data.ethernet->routing_table[i].active)
    {
      //printf("adding entry to routing info packet (%i)\n", i);
      memcpy(info[i].mobile_nic_addr, dll_states[link].data.ethernet->routing_table[i].mobile_nic_addr, sizeof(CnetNICaddr));
      info[i].mobile_num_addr = dll_states[link].data.ethernet->routing_table[i].mobile_num_addr;
      memcpy(info[i].ap_nic_addr, dll_states[link].data.ethernet->routing_table[i].ap_nic_addr, sizeof(CnetNICaddr));
      info[i].age = nodeinfo.time_of_day.usec - dll_states[link].data.ethernet->routing_table[i].local_create_time;
      info[i].active = true;
    } else {
      info[i].active = false;
    }
  }
  
  memcpy(packet.data, info, ROUTING_TABLE_ROWS * sizeof(struct routing_info_entry));
  packet.length = ROUTING_TABLE_ROWS * sizeof(struct routing_info_entry);

  packet.checksum = 0;  
  packet.checksum = CNET_crc32((unsigned char *)&packet, NL_PACKET_LENGTH(packet));
  
  //printf("NL_PACKET_LENGTH(packet): %i\n", NL_PACKET_LENGTH(packet));
  
  CnetNICaddr broadcast_addr;
  CHECK(CNET_parse_nicaddr(broadcast_addr, ETHER_BROADCAST_ADDR_STRING));
  
  //printf("Sending routing info packet...\n");
  
  //print_routing_info_packet(&packet);
  
  dll_eth_write(dll_states[link].data.ethernet, broadcast_addr, (char *)&packet, NL_PACKET_LENGTH(packet), true);
  
  //printf("broadcast_routing_info RETURN\n");
}

// called when a mobile node assoiates with one of this node's wifi DLLs
void handle_new_association(CnetNICaddr *mobile_nicaddr, CnetAddr mobile_addr)
{
  //printf("handle_new_association\n");
  //printf("Updating routing table with new association..\n");
  for (int ether_link = 1; ether_link <= nodeinfo.nlinks; ++ether_link) 
  {
    if(dll_states[ether_link].type == DLL_ETHERNET) 
    {
      struct routing_info_entry r_info;
      memcpy(r_info.mobile_nic_addr, mobile_nicaddr, sizeof(CnetNICaddr));
      r_info.mobile_num_addr = mobile_addr;
      memcpy(r_info.ap_nic_addr, linkinfo[ether_link].nicaddr, sizeof(CnetNICaddr));
      r_info.age = (CnetTime)0;

      update_routing_info_entry(ether_link, &r_info);
      print_routing_table(ether_link);
      broadcast_routing_info(ether_link);
    }
  }
  
  //printf("handle_new_association RETURN\n");
}

void queue_wifi_pkt(int link, CnetNICaddr dest_nicaddr, char *data, size_t length)
{
  printf("Inserting pkt into queue (wifi_out_queue.head: %d)\n", wifi_out_queue.head);
  for(int j = 0; j < WIFI_BUFFER_LENGTH; j++)
  {
    int i = (j + wifi_out_queue.head) % WIFI_BUFFER_LENGTH;
    if(!wifi_out_queue.active[i])
    {
      memcpy(&(wifi_out_queue.packet_queue[i]), data, sizeof(struct nl_packet));
      wifi_out_queue.link[i] = link;
      wifi_out_queue.length[i] = length;
      memcpy(wifi_out_queue.dest[i], dest_nicaddr, sizeof(CnetNICaddr));
      wifi_out_queue.active[i] = true;
      return;
    }
  }
  //printf("ERROR: not enough room in outgoing wifi buffer; dropped\n");
}

// initialises this node's routing table
void init_routing_table(int link)
{
  if(dll_states[link].type != DLL_ETHERNET) { return; }
  
  int i;
  for(i = 0; i < ROUTING_TABLE_ROWS; i++)
  {
    dll_states[link].data.ethernet->routing_table[i].active = false;
  }
}

// instruct each wifi DLL to determine if it is ready to accept a packet, and report back
void check_wifi_dll_ready()
{
  for (int link = 1; link <= nodeinfo.nlinks; ++link) {
    if (linkinfo[link].linktype == LT_WLAN) {
      dll_wifi_check_ready(dll_states[link].data.wifi);
    }
  }
}

static void wifi_dll_ready(int link) 
{
  if(dll_states[link].type != DLL_WIFI) { return; }
  
  if(!wifi_out_queue.active[wifi_out_queue.head]) { return; }
  
  //printf("\tSending on WiFi link %d\n", wifi_out_queue.dest[wifi_out_queue.head]);
  
  dll_wifi_write(dll_states[wifi_out_queue.link[wifi_out_queue.head]].data.wifi,
                 wifi_out_queue.dest[wifi_out_queue.head],
                 (char *)&(wifi_out_queue.packet_queue[wifi_out_queue.head]),
                 wifi_out_queue.length[wifi_out_queue.head]);
                 
  wifi_out_queue.active[wifi_out_queue.head] = false;
  wifi_out_queue.head = (wifi_out_queue.head + 1) % WIFI_BUFFER_LENGTH;
  
  check_wifi_dll_ready();
}

/// Called when we receive data from one of our data link layers.
///
static void up_from_dll(int link, const char *data, size_t length)
{
  //printf("up_from_dll\n");

  if (length > sizeof(struct nl_packet)) {
    printf("AP: %zu is larger than a nl_packet! ignoring.\n", length);
    return;
  }
  
  // Treat this frame as a network layer packet.
  struct nl_packet *packet = (struct nl_packet *)data;
  
  printf("AP: got packet on link %i for node %i from node %i\n", link, packet->dest, packet->src);
         
  if(packet->kind == NL_ROUTING_INFO)
  {
    printf("Got routing info packet...\n");
    print_routing_info_packet(packet);

    struct routing_info_entry info_array_ptr[ROUTING_TABLE_ROWS];
    memcpy(info_array_ptr, packet->data, ROUTING_TABLE_ROWS * sizeof(struct routing_info_entry));
  
    update_routing_info(link, info_array_ptr);
    return;
  }

  CnetNICaddr broadcast;
  CHECK(CNET_parse_nicaddr(broadcast, "ff:ff:ff:ff:ff:ff")); 

  CnetAddr dest_addr = packet->dest;
  
  
  int i;
  bool dest_associated = false;
  for (int outlink = 1; outlink <= nodeinfo.nlinks; ++outlink) {
    if(dll_states[outlink].type == DLL_WIFI) {

      for(i = 0; i < WIFI_MAX_ASSOCIATED_CLIENTS; i++)
      {
        if(dll_states[outlink].data.wifi->assoc_records[i].valid && dll_states[outlink].data.wifi->assoc_records[i].client_node_number == dest_addr)
        {
          dest_associated = true;
          break;
        }
      }
      if(dest_associated)
      {
        break;
      }
    }
  }
  
  printf("AP: dest_associated: %i\n", (int)dest_associated);
  
  for (int outlink = 1; outlink <= nodeinfo.nlinks; ++outlink) {
    switch (dll_states[outlink].type) {
      case DLL_UNSUPPORTED:
        break;
      
      case DLL_ETHERNET:
        if (outlink == link || dest_associated)
          break;
          
        CnetNICaddr next_addr;
        memcpy(next_addr, broadcast, sizeof(CnetNICaddr));
        
        if(ENABLE_ROUTING)
        {
          for(i = 0; i < ROUTING_TABLE_ROWS; i++)
          {
            if(dll_states[outlink].data.ethernet->routing_table[i].active && dll_states[outlink].data.ethernet->routing_table[i].mobile_num_addr == dest_addr)
            {
              memcpy(next_addr, dll_states[outlink].data.ethernet->routing_table[i].ap_nic_addr, sizeof(CnetNICaddr));
              break;
            }
          }
        }   
          
        printf("AP: Sending packet for node %i from node %i on Ethernet link %d \n", packet->dest, packet->src, outlink);
        dll_eth_write(dll_states[outlink].data.ethernet,
                      next_addr,
                      data,
                      length,
                      false);
        break;
      
      case DLL_WIFI:
        if(outlink == link && !dest_associated)
          break;

        printf("Got packet for node: %i\n", dest_addr);

        // more debug
        printf("outlink: %d\n", outlink);
        printf("iterating to %d\n", WIFI_MAX_ASSOCIATED_CLIENTS);
        
        bool found = false;
        int record_num;
        for(i = 0; i < WIFI_MAX_ASSOCIATED_CLIENTS; i++)
        {
          printf("iteration %d\n", i);
          printf("dll_states[outlink].data.wifi: %p\n", dll_states[outlink].data.wifi);
          printf("dll_states[outlink].data.wifi->assoc_records[i]: %p\n", dll_states[outlink].data.wifi->assoc_records[i]);
          printf("dll_states[outlink].data.wifi->assoc_records[i].valid: %d\n", dll_states[outlink].data.wifi->assoc_records[i].valid);
          printf("dll_states[outlink].data.wifi->assoc_records[i].client_node_number: %d\n", dll_states[outlink].data.wifi->assoc_records[i].client_node_number);
          if(dll_states[outlink].data.wifi->assoc_records[i].valid && dll_states[outlink].data.wifi->assoc_records[i].client_node_number == dest_addr)
          {
            printf("found!\n");
            record_num = i;
            found = true;
            break;
          } else {
            //if(dll_states[outlink].data.wifi->assoc_records[i].valid)
            //  printf("assoc: %i, dest: %i\n", 
            // dll_states[outlink].data.wifi->assoc_records[i].client_node_number, dest_addr);
          }
        }

        if(found)
        {
          printf("preparing to queue\n");
          queue_wifi_pkt(outlink, dll_states[outlink].data.wifi->assoc_records[record_num].associated_client, (char *)packet, length);
          check_wifi_dll_ready();
          break;
        }
    }
  }

  //printf("up_from_dll RETURN\n");
}

// called when one of this node's wifi DLLs comes out of backoff mode
EVENT_HANDLER(ap_wifi_backon) 
{
  int link = data;
  dll_wifi_backon(dll_states[link].data.wifi); 
}

// called when one of this node's ethernet DLLs comes out of backoff mode
EVENT_HANDLER(ap_ether_backon)
{
  int link = data;
  dll_eth_backon(dll_states[link].data.ethernet);
}

// called when it is time for one of this node's ethernet DLLs to check the channel again
EVENT_HANDLER(ap_ether_sense)
{
  int link = data;
  dll_eth_carrier_sense(dll_states[link].data.ethernet);
}

// called when there is a collision on one of this node's ethernet DLLs
EVENT_HANDLER(ap_handle_collision)
{
  int link = data;
 
  if(dll_states[link].type == DLL_ETHERNET)
  {
    dll_eth_handle_collision(dll_states[link].data.ethernet);
  }
}

/// Called when this access point is booted up.
///
void reboot_accesspoint()
{
  // We require each node to have a different stream of random numbers.
  CNET_srand(nodeinfo.time_of_day.sec + nodeinfo.nodenumber);
    
  // Prepare to talk via our wireless connection.
  CHECK(CNET_set_wlan_model(my_WLAN_model));
  
  for(int i = 0; i < WIFI_BUFFER_LENGTH; i++)
  {
    wifi_out_queue.active[i] = false;
  }
 
  // Setup our data link layer instances.
  dll_states = calloc(nodeinfo.nlinks + 1, sizeof(struct dll_state));
  
  //printf("Link summary:\n");
  
  int num_lans = 0;
  int num_wlans = 0;
  
  for (int link = 0; link <= nodeinfo.nlinks; ++link) {
    switch (linkinfo[link].linktype) {
      case LT_LOOPBACK:
        dll_states[link].type = DLL_UNSUPPORTED;
        break;
      
      case LT_WAN:
        dll_states[link].type = DLL_UNSUPPORTED;
        break;
      
      case LT_LAN:
        num_lans++;
        dll_states[link].type = DLL_ETHERNET;
        dll_states[link].data.ethernet = dll_eth_new_state(link, up_from_dll);
        if(ENABLE_ROUTING){ init_routing_table(link); }
        break;
      
      case LT_WLAN:
        num_wlans++;
        dll_states[link].type = DLL_WIFI;
        dll_states[link].data.wifi = dll_wifi_new_state(link,
                                                        up_from_dll,
                                                        true, /* is_ds */
							                                          wifi_dll_ready,
							                                          handle_new_association);
        break;
    }
  }
  
  if (num_lans > 1 || num_wlans > 1) {
    //printf("This solution is not designed to cope with multiple LANs or WLANs attached to an access point.");
    exit(1);
  }
  
  // Provide the required event handlers. (0 means the data attribute doesn't matter)
  CHECK(CNET_set_handler(EV_PHYSICALREADY, physical_ready, 0));
  CHECK(CNET_set_handler(WIFI_BACKOFF_TIMER, ap_wifi_backon, 0));
  CHECK(CNET_set_handler(ETHER_BACKOFF_TIMER, ap_ether_backon, 0));
  CHECK(CNET_set_handler(ETHER_CARRIER_SENSE_TIMER, ap_ether_sense, 0));
  CHECK(CNET_set_handler(EV_FRAMECOLLISION, ap_handle_collision, 0));
  CHECK(CNET_set_handler(EV_DEBUG0, info, 0));
  CHECK(CNET_set_debug_string(EV_DEBUG0, "Info"));
  CHECK(CNET_set_handler(EV_DEBUG1, print_routing_tables, 0));
  CHECK(CNET_set_debug_string(EV_DEBUG1, "Routes"));
  CHECK(CNET_set_handler(EV_DEBUG2, print_associated_nodes, 0));
  CHECK(CNET_set_debug_string(EV_DEBUG2, "Assoc"));
  
 
  // //printf("reboot_accesspoint() complete.\n");
}
