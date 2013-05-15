/// This file declares the external interface for our mobile nodes. All that
/// we need to do is reboot the mobile node, and it will setup everything else
/// internally (in mobile.c).

#ifndef MOBILE_H
#define MOBILE_H

/// Called when this mobile node is booted up.
///
void reboot_mobile();

#endif // MOBILE_H
