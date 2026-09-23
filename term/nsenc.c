#include "nsenc.h"
#include "nsenc_tab.h"

unsigned short nsenc_decode(unsigned char b)
{
    return b < 0x80 ? (unsigned short)b : NS_TO_UNI[b - 0x80];
}

int nsenc_encode(unsigned short cp)
{
    int lo = 0, hi = (int)(sizeof(UNI_TO_NS) / sizeof(UNI_TO_NS[0])) - 1, mid;
    if (cp < 0x80) return cp;
    while (lo <= hi) {
        mid = (lo + hi) / 2;
        if (UNI_TO_NS[mid].uni == cp) return UNI_TO_NS[mid].ns;
        if (UNI_TO_NS[mid].uni < cp) lo = mid + 1; else hi = mid - 1;
    }
    return -1;
}
