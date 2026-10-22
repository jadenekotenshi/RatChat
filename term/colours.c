#include "colours.h"

double hk_luminance(double r, double g, double b)
{
    return 0.299 * r + 0.587 * g + 0.114 * b;
}

#define LIGHT_MAX 0.42      /* on a light background nothing is brighter than this */
#define DARK_MIN  0.40      /* on a dark one nothing is dimmer than this */

void hk_adjust_for_background(double *r, double *g, double *b, double bg_luminance)
{
    double lum = hk_luminance(*r, *g, *b);

    if (bg_luminance > 0.5) {
        if (lum > LIGHT_MAX) {                          /* scale towards black: the hue stays */
            double k = LIGHT_MAX / lum;
            *r *= k; *g *= k; *b *= k;
        }
    } else if (lum < DARK_MIN) {
        if (lum <= 0.0001) {                            /* black has no hue to keep */
            *r = *g = *b = DARK_MIN;
        } else {                                        /* mix in white until bright enough */
            double t = (DARK_MIN - lum) / (1.0 - lum);
            *r += (1.0 - *r) * t;
            *g += (1.0 - *g) * t;
            *b += (1.0 - *b) * t;
        }
    }
}
