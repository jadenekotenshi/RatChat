/*
 * colours.h -- keeping a terminal's palette readable on the background it is shown on.
 *
 * The usual palette is made for a dark screen: yellow, cyan and white are pale and nearly vanish on white, and blue is dim
 * on black.  hk_adjust_for_background() moves a colour along its own hue (darker on a light background, lighter on a dark
 * one) just far enough to be legible, and leaves colours that already are.
 *
 * Pure C89, no I/O.  Components are 0.0 to 1.0.
 */
#ifndef HK_COLOURS_H
#define HK_COLOURS_H

double hk_luminance(double r, double g, double b);                     /* 0.299 r + 0.587 g + 0.114 b */
void   hk_adjust_for_background(double *r, double *g, double *b, double bg_luminance);

#endif
