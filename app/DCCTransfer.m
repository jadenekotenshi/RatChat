#import "DCCTransfer.h"
#import "UIHelpers.h"
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include "oscompat.h"

#ifdef OPENSTEP
typedef int sock_len_t;                    /* 4.4BSD-era getsockopt takes int * */
#else
typedef socklen_t sock_len_t;
#endif

#define TICK_SECONDS  0.02
#define CHUNK_SIZE    8192
#define TICKS_PER_SEC 50
#define WAIT_TIMEOUT  120   /* seconds to wait for an accept (SEND) or a connect (RECEIVE) */

/* gcc 2.7.2 does not look ahead within an @implementation. */
@interface DCCTransfer (Private)
- (void)fail:(NSString *)msg;
- (void)finishOK;
- (void)pumpSend;
- (void)pumpReceive;
- (void)refillFromFile;
- (void)reportProgress;
@end

@implementation DCCTransfer

- (id)initWithDelegate:(id)aDelegate
{
    self = [super init];
    if (!self) return nil;
    delegate = aDelegate;
    fd = -1;
    listenFd = -1;
    lastPercentReported = -1;
    return self;
}

- (void)dealloc
{
    [self cancel];
    if (pendingOut) free(pendingOut);
    [peerNick release]; [filename release];
    [super dealloc];
}

- (int)direction { return direction; }
- (NSString *)peerNick { return peerNick; }
- (NSString *)filename { return filename; }
- (long)totalSize { return totalSize; }
- (long)transferred { return transferred; }
- (int)percentDone { return totalSize > 0 ? (int)((transferred * 100) / totalSize) : 100; }

/* ---------------------------------------------------------------- */
/* setup                                                             */

- (int)beginSendFile:(NSString *)path toNick:(NSString *)nick
{
    struct sockaddr_in sa;
    socklen_t salen = sizeof(sa);
    int flags;

    file = fopen([path cString], "rb");
    if (!file) return 0;
    fseek(file, 0, SEEK_END);
    totalSize = ftell(file);
    fseek(file, 0, SEEK_SET);

    direction = DCC_SEND;
    peerNick = [nick retain];
    filename = [[path lastPathComponent] retain];

    listenFd = socket(AF_INET, SOCK_STREAM, 0);
    if (listenFd < 0) { fclose(file); file = NULL; return 0; }
    memset(&sa, 0, sizeof(sa));
    sa.sin_family = AF_INET;
    sa.sin_addr.s_addr = htonl(INADDR_ANY);
    sa.sin_port = 0;                              /* let the OS choose a free port */
    if (bind(listenFd, (struct sockaddr *)&sa, sizeof(sa)) != 0 ||
        listen(listenFd, 1) != 0 ||
        getsockname(listenFd, (struct sockaddr *)&sa, &salen) != 0) {
        close(listenFd); listenFd = -1; fclose(file); file = NULL;
        return 0;
    }
    flags = fcntl(listenFd, F_GETFL, 0);
    fcntl(listenFd, F_SETFL, flags | O_NONBLOCK);

    state = DCC_WAITING;
    waitDeadline = ticks + WAIT_TIMEOUT * TICKS_PER_SEC;
    timer = [[NSTimer scheduledTimerWithTimeInterval:TICK_SECONDS target:self
                                            selector:@selector(tick:) userInfo:nil repeats:YES] retain];
    return ntohs(sa.sin_port);
}

- (BOOL)beginReceiveFromIP:(NSString *)ip port:(int)port size:(long)size
                    toPath:(NSString *)savePath fromNick:(NSString *)nick
{
    struct sockaddr_in sa;
    int flags, rc;

    file = fopen([savePath cString], "wb");
    if (!file) return NO;

    direction = DCC_RECEIVE;
    peerNick = [nick retain];
    filename = [[savePath lastPathComponent] retain];
    totalSize = size;

    fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) { fclose(file); file = NULL; return NO; }
    memset(&sa, 0, sizeof(sa));
    sa.sin_family = AF_INET;
    sa.sin_addr.s_addr = inet_addr([ip cString]);
    sa.sin_port = htons((unsigned short)port);
    flags = fcntl(fd, F_GETFL, 0);
    fcntl(fd, F_SETFL, flags | O_NONBLOCK);

    state = DCC_WAITING;
    waitDeadline = ticks + WAIT_TIMEOUT * TICKS_PER_SEC;
    rc = connect(fd, (struct sockaddr *)&sa, sizeof(sa));
    if (rc == 0) state = DCC_TRANSFERRING;
    else if (errno != EINPROGRESS) {
        close(fd); fd = -1; fclose(file); file = NULL;
        return NO;
    }

    timer = [[NSTimer scheduledTimerWithTimeInterval:TICK_SECONDS target:self
                                            selector:@selector(tick:) userInfo:nil repeats:YES] retain];
    return YES;
}

/* ---------------------------------------------------------------- */
/* the poll loop                                                     */

- (void)tick:(NSTimer *)t
{
    if (inTick || state == DCC_DONE || state == DCC_FAILED) return;
    inTick = 1;
    ticks++;

    if (state == DCC_WAITING && (int)(ticks - waitDeadline) > 0) {
        [self fail:(direction == DCC_SEND ? @"Timed out waiting for the other side to accept"
                                          : @"Timed out trying to connect to the other side")];
        inTick = 0;
        return;
    }

    if (state == DCC_WAITING && direction == DCC_SEND) {
        int c = accept(listenFd, NULL, NULL);
        if (c >= 0) {
            int flags = fcntl(c, F_GETFL, 0);
            fcntl(c, F_SETFL, flags | O_NONBLOCK);
            close(listenFd); listenFd = -1;
            fd = c;
            state = DCC_TRANSFERRING;
        }
    } else if (state == DCC_WAITING && direction == DCC_RECEIVE) {
        fd_set wf;
        struct timeval tv;
        int err = 0;
        sock_len_t len = sizeof(err);
        FD_ZERO(&wf);
        FD_SET(fd, &wf);
        tv.tv_sec = 0; tv.tv_usec = 0;
        if (select(fd + 1, NULL, &wf, NULL, &tv) > 0) {
            getsockopt(fd, SOL_SOCKET, SO_ERROR, (char *)&err, &len);
            if (err) [self fail:[NSString stringWithFormat:@"Connection failed: %s", strerror(err)]];
            else state = DCC_TRANSFERRING;
        }
    } else if (state == DCC_TRANSFERRING) {
        if (direction == DCC_SEND) [self pumpSend];
        else [self pumpReceive];
    }
    inTick = 0;
}

- (void)refillFromFile
{
    unsigned char buf[CHUNK_SIZE];
    size_t n;
    if (pendingLen > 0 || !file) return;
    n = fread(buf, 1, sizeof(buf), file);
    if (n == 0) return;
    if (n > pendingCap) {
        unsigned char *p = (unsigned char *)realloc(pendingOut, n);
        if (!p) return;
        pendingOut = p; pendingCap = n;
    }
    memcpy(pendingOut, buf, n);
    pendingLen = n;
}

- (void)pumpSend
{
    int w;
    [self refillFromFile];
    if (pendingLen == 0) {
        if (feof(file)) [self finishOK];
        return;
    }
    w = send(fd, (char *)pendingOut, pendingLen, 0);
    if (w > 0) {
        memmove(pendingOut, pendingOut + w, pendingLen - (size_t)w);
        pendingLen -= (size_t)w;
        transferred += w;
        [self reportProgress];
    } else if (w < 0 && errno != EWOULDBLOCK && errno != EINTR) {
        [self fail:[NSString stringWithFormat:@"Network error: %s", strerror(errno)]];
    }
}

- (void)pumpReceive
{
    unsigned char buf[CHUNK_SIZE];
    int n = recv(fd, (char *)buf, sizeof(buf), 0);
    if (n > 0) {
        fwrite(buf, 1, (size_t)n, file);
        transferred += n;
        [self reportProgress];
        if (transferred >= totalSize) [self finishOK];
    } else if (n == 0) {
        [self fail:@"Connection closed before the transfer finished"];
    } else if (errno != EWOULDBLOCK && errno != EINTR) {
        [self fail:[NSString stringWithFormat:@"Network error: %s", strerror(errno)]];
    }
}

/* Throttled to roughly every 25%, rather than firing on every 8KB chunk -- a large transfer at
 * one tick per 20ms would otherwise spam the delegate (and whatever UI it drives) constantly. */
- (void)reportProgress
{
    int pct = [self percentDone];
    if (pct < lastPercentReported + 25 && pct < 100) return;
    lastPercentReported = pct;
    if ([delegate respondsToSelector:@selector(dccTransferDidProgress:)])
        [delegate dccTransferDidProgress:self];
}

/* ---------------------------------------------------------------- */
/* teardown                                                          */

- (void)finishOK
{
    if (state == DCC_DONE || state == DCC_FAILED) return;
    state = DCC_DONE;
    [timer invalidate]; [timer release]; timer = nil;
    if (fd >= 0) { close(fd); fd = -1; }
    if (file) { fclose(file); file = NULL; }
    if ([delegate respondsToSelector:@selector(dccTransferDidFinish:success:message:)])
        [delegate dccTransferDidFinish:self success:YES message:nil];
}

- (void)fail:(NSString *)msg
{
    if (state == DCC_DONE || state == DCC_FAILED) return;
    state = DCC_FAILED;
    [timer invalidate]; [timer release]; timer = nil;
    if (fd >= 0) { close(fd); fd = -1; }
    if (listenFd >= 0) { close(listenFd); listenFd = -1; }
    if (file) { fclose(file); file = NULL; }
    if ([delegate respondsToSelector:@selector(dccTransferDidFinish:success:message:)])
        [delegate dccTransferDidFinish:self success:NO message:msg];
}

- (void)cancel
{
    [timer invalidate]; [timer release]; timer = nil;
    if (fd >= 0) { close(fd); fd = -1; }
    if (listenFd >= 0) { close(listenFd); listenFd = -1; }
    if (file) { fclose(file); file = NULL; }
    if (state != DCC_DONE) state = DCC_FAILED;
}

@end
