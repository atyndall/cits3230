/// Provides helper functions

#include <cnet.h>
#include <stdlib.h>
#include <string.h>

/// Prints info about link
EVENT_HANDLER(info)
{
  printf("\nINFORMATION\n");
  printf("  Node address: %d\n", nodeinfo.address);
  printf("  Node number: %d\n\n", nodeinfo.nodenumber);
  
  char *slinktype;
  char mac[17];
  
  for (int link = 0; link <= nodeinfo.nlinks; ++link) {
    switch (linkinfo[link].linktype) {
      case LT_LOOPBACK:
        slinktype = "LOOPBACK";
        break;
      
      case LT_WAN:
        slinktype = "WAN";
        break;
      
      case LT_LAN:
        slinktype = "LAN";
        break;
      
      case LT_WLAN:
        slinktype = "WLAN";
        break;
    }
    
    
    CNET_format_nicaddr(mac, linkinfo[link].nicaddr);
    printf("  Link %d (%s)\n", link, slinktype);
    printf("    Name: %s\n", linkinfo[link].linkname);
    printf("    MAC: %s\n", mac);
  }
}

void tprint_nic(char* desc, CnetNICaddr addr) {
  char str[17];
  CNET_format_nicaddr(str, addr);
  //printf("%s: %s\n", desc, str);
}

void print_nic(CnetNICaddr addr) {
  tprint_nic("NIC", addr);
}