/* nsenc.h -- NeXTSTEP character encoding <-> Unicode (BMP). */
#ifndef NSENC_H
#define NSENC_H

/* Unicode code point for a NeXTSTEP byte (0xFFFD for the two unassigned codes). */
unsigned short nsenc_decode(unsigned char b);
/* NeXTSTEP byte for a code point, or -1 if the encoding has no such character. */
int nsenc_encode(unsigned short cp);

#endif
