/// There is no need to understand or modify this file.

#include <cnet.h>
#include <ctype.h>
#include <stdlib.h>
#include <string.h>

#define	COMMENT		'#'
#define	COLOUR_OBJECTS	"grey75"

typedef struct {
    char	*text;
    int		x0;
    int		y0;
    int		x1;
    int		y1;
} OBJECT;

static	OBJECT	*objects	= NULL;
static	int	nobjects	= 0;

static	int	minx		= (1<<30);
static	int	miny		= (1<<30);
static	int	maxx		= -1;
static	int	maxy		= -1;

static void add_object(char *text, int x0, int y0, int x1, int y1)
{
    objects	= realloc(objects, (nobjects+1)*sizeof(OBJECT));

    if(objects) {
	extern char *strdup(const char *str);

	OBJECT	*new	= &objects[nobjects];

	memset(new, 0, sizeof(OBJECT));
	if(text)
	    new->text	= strdup(text);

	if(x0 == x1)
	    ++x1;
	if(y0 == y1)
	    ++y1;
	new->x0			= x0;
	new->y0			= y0;
	new->x1			= x1;
	new->y1			= y1;

	if(minx > new->x0)	minx = new->x0;
	if(miny > new->y0)	miny = new->y0;
	if(maxx < new->x1)	maxx = new->x1;
	if(maxy < new->y1)	maxy = new->y1;

	++nobjects;
    }
    else
	nobjects = 0;
}

static void draw_objects(void)
{
#define	SCALE(x)	((int)((x) / scale))

    double	scale	= CNET_get_mapscale();

    for(int n=0 ; n<nobjects ; ++n) {
	OBJECT	*op	= &objects[n];

	if(op->text)
	    TCLTK("$map lower [$map create text %d %d -text \"%s\"]",
		    SCALE(op->x0), SCALE(op->y0),
		    op->text);
	else
TCLTK("$map lower [$map create rect %d %d %d %d -width 1 -outline %s -fill %s]",
		    SCALE(op->x0), SCALE(op->y0), SCALE(op->x1), SCALE(op->y1),
		    COLOUR_OBJECTS, COLOUR_OBJECTS);
    }
}

static char *trim(char *line)
{
    char	*s = line;

    while(*s) {
	if(*s == COMMENT || *s == '\n' || *s == '\r') {
	    *s	= '\0';
	    break;
	}
	++s;
    }
    s	= line;
    while(isspace(*s))
	++s;
    return s;
}

void readmap(const char *mapfile)
{
    FILE *fp	= fopen(mapfile, "r");

//  EACH NODE READS IN THE MAP DETAILS
    if(fp) {
	char	line[1024], text[1024], *s;

	while(fgets(line, sizeof(line), fp)) {
	    s	= trim(line);

	    if(*s) {
		int	x0, y0, x1, y1;

		if(sscanf(s, "object %d %d %d %d", &x0, &y0, &x1, &y1) == 4)
		    add_object(NULL, x0, y0, x1, y1);
		else if(sscanf(s, "text %d %d %s", &x0, &y0, text) == 3)
		    add_object(text, x0, y0, 0, 0);
	    }
	}
	fclose(fp);
//  ONLY ONE NODE NEEDS TO DRAW THE MAP
	if(nodeinfo.nodenumber == 0)
	    draw_objects();
    }
    else {
	fprintf(stderr, "%s: cannot open '%s'\n", nodeinfo.nodename, mapfile);
	exit(EXIT_FAILURE);
    }
}


/*  Two segments ab and cd intersect if and only if 
	+ the endpoints a and b are on opposite sides of the line cd, and
	+ the endpoints c and d are on opposite sides of the line ab. 

    To test whether two points are on opposite sides of a line through
    two other points, we use the counterclockwise test.

    Specically, a and b are on opposite sides of line cd if and only if
    exactly one of the two triples a, c, d and b, c, d is in
    counterclockwise order.

    http://compgeom.cs.uiuc.edu/~jeffe/teaching/373/notes/x06-sweepline.pdf
 */

static bool ccw(int x0, int y0, int x1, int y1, int x2, int y2)
{
    int	a = x0 - x1,
	b = y0 - y1,
	c = x2 - x1,
	d = y2 - y1;
    return a*d - b*c <= 0;	// true iff P0, P1, P2 counterclockwise
}

//  DOES THE PATH FROM S -> D PASS THROUGH AN OBJECT?
bool through_an_object(CnetPosition S, CnetPosition D)
{
    for(int n=0 ; n<nobjects ; ++n) {
	OBJECT	*op	= &objects[n];

	if(op->text == NULL)		// only interested in objects
	    if((ccw(S.x, S.y, op->x0, op->y0, op->x1, op->y1)	!=
		ccw(D.x, D.y, op->x0, op->y0, op->x1, op->y1))	&&
	       (ccw(S.x, S.y, D.x, D.y, op->x0, op->y0)		!=
		ccw(S.x, S.y, D.x, D.y, op->x1, op->y1))	)
		return true;
    }
    return false;
}

//  THROUGH HOW MANY OBJECTS DOES THE PATH FROM S -> D PASS?
int through_N_objects(CnetPosition S, CnetPosition D)
{
    int	count	= 0;

    for(int n=0 ; n<nobjects ; ++n) {
	OBJECT	*op	= &objects[n];

	if(op->text == NULL)		// only interested in objects
	    if((ccw(S.x, S.y, op->x0, op->y0, op->x1, op->y1)	!=
		ccw(D.x, D.y, op->x0, op->y0, op->x1, op->y1))	&&
	       (ccw(S.x, S.y, D.x, D.y, op->x0, op->y0)		!=
		ccw(S.x, S.y, D.x, D.y, op->x1, op->y1))	)
		++count;
    }
    return count;
}

//  CHOOSE A RANDOM POSITION WITHIN THE MAP, BUT NOT WITHIN ANY OBJECT
void choose_position(CnetPosition *new)
{
    for(;;) {
	int	tryx	= CNET_rand() % (maxx - minx) + minx;
	int	tryy	= CNET_rand() % (maxy - miny) + miny;
        int	n;

	for(n=0 ; n<nobjects ; ++n) {
	    OBJECT	*op	= &objects[n];

	    if(op->text == NULL &&
		tryx >= op->x0 && tryx <= op->x1 &&
		tryy >= op->y0 && tryy <= op->y1)
		    break;		// oops, inside an object
	}
	if(n == nobjects) {
	    new->x	= tryx;
	    new->y	= tryy;
	    new->z	= 0;
	    break;
	}
    }
}

#define	SIGNAL_LOSS_PER_OBJECT		8.0		// dBm

//  CALCULATE WIRELESS TRANSMISSION THROUGH MAP OBJECTS
WLANRESULT  my_WLAN_model(WLANSIGNAL *sig)
{
    int		dx, dy;
    double	metres;
    double	TXtotal, FSL, budget;

//  CALCULATE THE TOTAL OUTPUT POWER LEAVING TRANSMITTER
    TXtotal	= sig->tx_info->tx_power_dBm - sig->tx_info->tx_cable_loss_dBm +
		    sig->tx_info->tx_antenna_gain_dBi;

//  CALCULATE THE DISTANCE TO THE DESTINATION NODE
    dx		= (sig->tx_pos.x - sig->rx_pos.x);
    dy		= (sig->tx_pos.y - sig->rx_pos.y);
    metres	= sqrt((double)(dx*dx + dy*dy)) + 0.1;	// just 2D

//  CALCULATE THE FREE-SPACE-LOSS OVER THIS DISTANCE
    FSL		= (92.467 + 20.0*log10(sig->tx_info->frequency_GHz)) +
		    20.0*log10(metres/1000.0);

//  CALCULATE THE SIGNAL STRENGTH ARRIVING AT RECEIVER
    sig->rx_strength_dBm = TXtotal - FSL +
	    sig->rx_info->rx_antenna_gain_dBi - sig->rx_info->rx_cable_loss_dBm;

//  DEGRAGDE THE WIRELESS SIGNAL BASED ON THE NUMBER OF OBJECTS IT HITS
    int	nobjects = through_N_objects(sig->tx_pos, sig->rx_pos);

    sig->rx_strength_dBm -= (nobjects * SIGNAL_LOSS_PER_OBJECT);

//  CAN THE RECEIVER DETECT THIS SIGNAL AT ALL?
    budget	= sig->rx_strength_dBm - sig->rx_info->rx_sensitivity_dBm;
    if(budget < 0.0)
	return(WLAN_TOOWEAK);

//  CAN THE RECEIVER DECODE THIS SIGNAL?
    return (budget < sig->rx_info->rx_signal_to_noise_dBm) ?
		WLAN_TOONOISY : WLAN_RECEIVED;
}
