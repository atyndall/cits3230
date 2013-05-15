/// There is no need to understand or modify this file.

#ifndef MAPPING_H
#define MAPPING_H

#include <cnet.h>

//  READ THE OBJECTS ON OUR MAP FROM THE INDICATED FILE
extern	void	readmap(const char *filenm);

//  CHOOSE A LOCATION THAT IS NOT INSIDE ANY OBJECT
extern	void	choose_position(CnetPosition *new);

//  DOES THE PATH FROM S -> D PASS THROUGH AN OBJECT?
extern	bool	through_an_object(CnetPosition S, CnetPosition D);

//  THROUGH HOW MANY OBJECTS DOES THE PATH FROM S -> D PASS?
extern	int	through_N_objects(CnetPosition S, CnetPosition D);

//  CALCULATE WIRELESS TRANSMISSION THROUGH MAP OBJECTS
extern  WLANRESULT  my_WLAN_model(WLANSIGNAL *sig);

#endif // MAPPING_H
