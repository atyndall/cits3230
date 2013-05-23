/// This file declares the functions that we use to make mobile nodes walk
/// to random locations in the simulation map. There is no need to edit this.

#ifndef WALKING_H
#define WALKING_H

#define	EV_WALKING		EV_TIMER9

extern	void	init_walking(void);
extern	void	start_walking(void);
extern	void	stop_walking(void);
extern	bool	am_walking(void);

#endif // WALKING_H
