/// This files implements the reboot_node event handler for our project. You
/// may edit this as you see fit, but readmap() must be called appropriately
/// for the default scenario to function.

#include <cnet.h>
#include <stdlib.h>
#include <string.h>

#include "ap.h"
#include "mapping.h"
#include "mobile.h"

/// Called when any of our nodes are booted up.
///
EVENT_HANDLER(reboot_node)
{
  // Ensure that we're running the correct version of cnet.
  CNET_check_version(CNET_VERSION);
  
  char **argv = (char **)data;
  
  // Ensure that we have a map filename.
  if (!argv[0])
    return;
  
  // Read and draw the map (only node 0 will draw the map).
  readmap(argv[0]);
  
  // Select which reboot function to call based on the node's type.
  switch (nodeinfo.nodetype) {
    case NT_HOST: // No hosts in this project.
      break;
    
    case NT_ROUTER: // No routers in this project.
      break;
    
    case NT_MOBILE:
      reboot_mobile();
      break;
    
    case NT_ACCESSPOINT:
      reboot_accesspoint();
      break;
  }
}
