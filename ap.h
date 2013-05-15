/// This file declares the external interface for our access points. All that
/// we need to do is reboot the access point, and it will setup everything else
/// internally (in ap.c).

#ifndef AP_H
#define AP_H

/// Called when this access point is booted up.
///
void reboot_accesspoint();

#endif // AP_H
