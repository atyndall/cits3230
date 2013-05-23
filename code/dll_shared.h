/// Contains data types and definitions shared by the data link layers.

#ifndef DLL_SHARED_H
#define DLL_SHARED_H

#include <stddef.h>

#define DLL_MTU 8192 // The maximum size of any data link layer frame.

// change to true to enable routing functionality
#define ENABLE_ROUTING false

/// Defines the type of callback functions used by the data link layers to send
/// frame data up to the next layer.
///
typedef void (*up_from_dll_fn_ty)(int link, char const *data, size_t length);

// type of function called when the DLL wishes to notify the NL that it is ready to accept a packet
typedef void (*dll_notify_ready_fn_ty)(int link);



#endif // DLL_SHARED_H
