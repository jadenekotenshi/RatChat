/*
 * dcc_smoke.m -- drives two real DCCTransfer instances (one DCC_SEND, one DCC_RECEIVE) against
 * each other over a real 127.0.0.1 TCP connection, on the host. Bypasses the IRC negotiation layer
 * entirely (core/dcc.c's own parsing/formatting is already covered by tests/test_dcc.c, and the
 * CTCP routing by tests/irc_smoke.m) to focus on what neither of those exercises: DCCTransfer's
 * actual socket + file I/O, end to end -- a real listen/accept, a real non-blocking connect, and a
 * multi-chunk file (larger than one CHUNK_SIZE read/write) copied byte-for-byte from a real source
 * file to a real destination file.
 * usage: dcc_smoke
 */
#import "Compat.h"
#import "DCCTransfer.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

@interface DCCWatcher : NSObject
{
@public
    int progressCalls;
    int finished;
    BOOL success;
    NSString *failMessage;
}
@end
@implementation DCCWatcher
- (void)dccTransferDidProgress:(DCCTransfer *)t { progressCalls++; }
- (void)dccTransferDidFinish:(DCCTransfer *)t success:(BOOL)ok message:(NSString *)msg
{
    finished = 1;
    success = ok;
    failMessage = [msg retain];
}
@end

static void spin(double seconds)
{
    [[NSRunLoop currentRunLoop] runUntilDate:[NSDate dateWithTimeIntervalSinceNow:seconds]];
}

static int wait_until(int *flag, double timeout)
{
    double waited = 0;
    while (waited < timeout) {
        if (*flag) return 1;
        spin(0.02);
        waited += 0.02;
    }
    return 0;
}

/* Writes a deterministic, non-trivial-size (bigger than DCCTransfer's own 8KB chunk size, so a
 * real transfer needs several send()/recv() rounds) test file and returns its path. */
static NSString *makeTestFile(int seed, size_t size)
{
    NSString *path = [NSTemporaryDirectory() stringByAppendingPathComponent:
                      [NSString stringWithFormat:@"dcc_smoke_src_%d.bin", seed]];
    FILE *f = fopen([path cString], "wb");
    size_t i;
    for (i = 0; i < size; i++) fputc((int)((i * 37 + seed) & 0xff), f);
    fclose(f);
    return path;
}

static int filesAreIdentical(NSString *a, NSString *b)
{
    FILE *fa = fopen([a cString], "rb");
    FILE *fb = fopen([b cString], "rb");
    int match = 1;
    if (!fa || !fb) { if (fa) fclose(fa); if (fb) fclose(fb); return 0; }
    for (;;) {
        int ca = fgetc(fa), cb = fgetc(fb);
        if (ca != cb) { match = 0; break; }
        if (ca == EOF) break;
    }
    fclose(fa); fclose(fb);
    return match;
}

static int pass, fail;
#define EXPECT(cond, what) do { if (cond) { pass++; printf("  ok   %s\n", what); } else { fail++; printf("  FAIL %s\n", what); } } while (0)

int main(void)
{
    NSAutoreleasePool *pool = [[NSAutoreleasePool alloc] init];
    NSString *srcPath, *dstPath;
    DCCTransfer *sender, *receiver;
    DCCWatcher *sendWatcher, *recvWatcher;
    int port;

    srcPath = makeTestFile(1, 200000);          /* > 24 chunks at CHUNK_SIZE (8192) */
    dstPath = [NSTemporaryDirectory() stringByAppendingPathComponent:@"dcc_smoke_dst_1.bin"];
    [[NSFileManager defaultManager] removeFileAtPath:dstPath handler:nil];

    sendWatcher = [[DCCWatcher alloc] init];
    recvWatcher = [[DCCWatcher alloc] init];

    sender = [[DCCTransfer alloc] initWithDelegate:sendWatcher];
    port = [sender beginSendFile:srcPath toNick:@"bob"];
    EXPECT(port > 0, "DCC_SEND opens a real listening socket and returns its port");
    EXPECT([sender totalSize] == 200000, "the sender correctly reads the real file's size");

    receiver = [[DCCTransfer alloc] initWithDelegate:recvWatcher];
    EXPECT([receiver beginReceiveFromIP:@"127.0.0.1" port:port size:200000 toPath:dstPath fromNick:@"alice"],
           "DCC_RECEIVE opens a real non-blocking connect to the sender's port");

    EXPECT(wait_until(&recvWatcher->finished, 10.0), "the transfer completes (both sides notice)");
    EXPECT(recvWatcher->success, "the receiver reports success");
    EXPECT(wait_until(&sendWatcher->finished, 2.0), "the sender also finishes (its own EOF-on-file completion)");
    EXPECT(sendWatcher->success, "the sender reports success");

    EXPECT([[NSFileManager defaultManager] fileExistsAtPath:dstPath], "the destination file was actually created");
    EXPECT(filesAreIdentical(srcPath, dstPath), "the received file is byte-for-byte identical to the source");

    EXPECT(sendWatcher->progressCalls > 0, "the sender's delegate got at least one progress notification");
    EXPECT(recvWatcher->progressCalls > 0, "the receiver's delegate got at least one progress notification");
    EXPECT([receiver transferred] == 200000, "the receiver's own transferred-byte count matches the file size");

    /* A receiver that can never reach anything must fail cleanly, not hang or crash. */
    {
        DCCWatcher *failWatcher = [[DCCWatcher alloc] init];
        DCCTransfer *deadEnd = [[DCCTransfer alloc] initWithDelegate:failWatcher];
        NSString *deadPath = [NSTemporaryDirectory() stringByAppendingPathComponent:@"dcc_smoke_dead.bin"];
        BOOL started = [deadEnd beginReceiveFromIP:@"127.0.0.1" port:1 size:100 toPath:deadPath fromNick:@"nobody"];
        EXPECT(started, "connecting to a real-but-refusing port at least starts (non-blocking connect)");
        EXPECT(wait_until(&failWatcher->finished, 10.0), "a connection nothing answers eventually fails rather than hanging forever");
        EXPECT(!failWatcher->success, "and it is reported as a failure, not a false success");
        [deadEnd release];
        [failWatcher release];
    }

    [[NSFileManager defaultManager] removeFileAtPath:srcPath handler:nil];
    [[NSFileManager defaultManager] removeFileAtPath:dstPath handler:nil];

    printf("dcc smoke: %d passed, %d failed\n", pass, fail);
    [pool release];
    return fail ? 1 : 0;
}
