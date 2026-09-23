#import "Compat.h"

enum { DCC_SEND, DCC_RECEIVE };
enum { DCC_WAITING, DCC_TRANSFERRING, DCC_DONE, DCC_FAILED };

/* One DCC file transfer -- a single direct peer-to-peer TCP connection, entirely separate from
 * the server connection it was negotiated over. Mirrors IRCConnection's own non-blocking
 * connect/select/recv/send pattern and 20ms poll loop (see its own header for why that pattern is
 * trusted), but simpler: no line protocol, just a raw byte stream copied to or from a local file.
 *
 * DCC_SEND: we open a listening socket and wait for the peer to connect to us (the classic DCC
 * model -- the offering side is the TCP server). DCC_RECEIVE: we connect out to the IP/port the
 * peer's own offer gave us. Deliberately skips the old app-level 4-byte-ack-per-chunk convention
 * some DCC implementations use for flow control -- TCP already provides that at the transport
 * layer, so it is redundant here (this only matters for interop with a very old/strict client
 * that insists on it, which has not come up). */
@interface DCCTransfer : NSObject
{
    id       delegate;
    int      direction;          /* DCC_SEND or DCC_RECEIVE */
    int      state;
    int      fd;                 /* the data connection, once accepted/connected */
    int      listenFd;           /* DCC_SEND only, until accepted */
    NSTimer *timer;
    int      inTick;
    long     ticks, waitDeadline; /* both the SEND accept-wait and the RECEIVE connect-wait time out */

    NSString *peerNick;
    NSString *filename;
    long      totalSize;
    long      transferred;
    int       lastPercentReported;   /* -1 initially; -dccTransferDidProgress: fires every 25% */
    FILE     *file;

    unsigned char *pendingOut;   /* DCC_SEND only: bytes read from the file, not yet sent */
    size_t         pendingLen, pendingCap;
}
- (id)initWithDelegate:(id)aDelegate;

/* Opens a listening socket and returns its port (0 on failure) -- the caller sends the DCC offer
 * (with this port and its own address) over the main IRC connection, then. Reading starts once
 * the peer actually connects. */
- (int)beginSendFile:(NSString *)path toNick:(NSString *)nick;

/* Connects out to (ip, port) and, once connected, reads `size` bytes into a new file at
 * `savePath`, overwriting any existing file there. */
- (BOOL)beginReceiveFromIP:(NSString *)ip port:(int)port size:(long)size
                    toPath:(NSString *)savePath fromNick:(NSString *)nick;

- (int)direction;        /* DCC_SEND or DCC_RECEIVE */
- (NSString *)peerNick;
- (NSString *)filename;
- (long)totalSize;
- (long)transferred;
- (int)percentDone;      /* 0-100, or 100 if totalSize is 0 */
- (void)cancel;
@end

@interface NSObject (DCCTransferDelegate)
- (void)dccTransferDidProgress:(DCCTransfer *)t;
- (void)dccTransferDidFinish:(DCCTransfer *)t success:(BOOL)success message:(NSString *)msg;
@end
