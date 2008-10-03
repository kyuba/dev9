/*
 *  dev9.c
 *  dev9
 *
 *  Created by Magnus Deininger on 03/10/2008.
 *  Copyright 2008 Magnus Deininger. All rights reserved.
 *
 */

/*
 * Copyright (c) 2008, Magnus Deininger All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are
 * met:
 *
 * * Redistributions of source code must retain the above copyright
 * notice, this list of conditions and the following disclaimer. *
 * Redistributions in binary form must reproduce the above copyright
 * notice, this list of conditions and the following disclaimer in the
 * documentation and/or other materials provided with the distribution. *
 * Neither the name of the project nor the names of its contributors may
 * be used to endorse or promote products derived from this software
 * without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS
 * IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED
 * TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A
 * PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include <curie/multiplex.h>
#include <curie/memory.h>

#include <duat/9p-server.h>
#include <duat/filesystem.h>
#include <duat/sxfs.h>

#include <sys/types.h>
#include <dirent.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include <asm/types.h>
#include <sys/socket.h>
#include <linux/netlink.h>

#define NETLINK_BUFFER (1024*1024*16)

static void connect_to_netlink();

static void *rm_recover(unsigned long int s, void *c, unsigned long int l)
{
    exit(22);
    return (void *)0;
}

static void *gm_recover(unsigned long int s)
{
    exit(23);
    return (void *)0;
}

static int_16 joinpath(char *path1, char *path2, char **path)
{
    char *rv = NULL;
    int tlen = strlen(path1);

    if (path1[tlen] == '/') {
        tlen += strlen(path2) + 1;
        rv = aalloc(tlen);

        snprintf(rv, tlen, "%s%s", path1, path2);
    } else {
        tlen += strlen(path2) + 2;
        rv = aalloc(tlen);

        snprintf(rv, tlen, "%s/%s", path1, path2);
    }

    *path = rv;
    return (int_16)tlen;
}

static void ping_for_uevents (char *dir, char depth) {
    struct stat st;
    int_16 len;

    if (!dir || stat (dir, &st)) return;

    if (S_ISLNK (st.st_mode)) {
        return;
    }

    if (S_ISDIR (st.st_mode)) {
        DIR *d;
        struct dirent *e;

        d = opendir (dir);
        if (d != NULL) {
            while ((e = readdir (d))) {
                if ((strcmp (e->d_name, ".") == 0) ||
                    (strcmp (e->d_name, "..") == 0))
                {
                    continue;
                }

                char *f;
                len = joinpath ((char *)dir, e->d_name, &f);

                if (len > 0) {
                    if (!stat (f, &st) && !S_ISLNK (st.st_mode) &&
                        S_ISDIR (st.st_mode))
                    {
                        if (depth > 0) {
                            ping_for_uevents (f, depth - 1);
                        }
                    }

                    afree (len, f);
                }
            }

            closedir(d);
        }
    }

    char *x;
    len = joinpath (dir, "uevent", &x);

    if (len > 0)
    {
        int f = open (x, O_WRONLY);

        if (f > 0) {
            write (f, "add\n", 4);
            close (f);
        }

        afree (len, x);
    }
}

static void on_netlink_read(struct io *io, void *ignored)
{
    char *b = io->buffer,
         *fragment_header = b,
         *is = b,
         *ms = b,
         *i = b,
         *max = (b + io->length);
    struct sexpr *attributes = sx_end_of_list;

    while (i < max)
    {
        switch (*i)
        {
            case '0':
                fprintf (stderr, "i=%u, is=%u, ms=%u\n", i, is, ms);

                if (is == ms) /* fragment header */
                {
                    fragment_header = is;
                    fprintf (stderr, "new fragment: %s\n", fragment_header);
                    sx_destroy(attributes);
                    attributes = sx_end_of_list;
                }
                else /* key/value pair */
                {
                    *ms = 0;
                    ms++;
                    attributes = cons (cons(make_symbol(is),
                                            make_string(ms)),
                                       attributes);
                }

                i++;
                is = ms = i;
                fprintf (stderr, "i=%u, is=%u, ms=%u\n", i, is, ms);
                break;
            case '=':
                if (ms == is) ms = i;
        }

        i++;
    }

    fprintf (stderr, "call-end\n");

    io->position += (int_pointer)(max - fragment_header);
}

static void on_netlink_close(struct io *io, void *ignored)
{
    exit(24);
/*    connect_to_netlink();*/
}

static void mx_on_subprocess_death(struct exec_context *cx, void *d)
{
    if (cx->exitstatus != 0)
        exit (26);
}

static void connect_to_netlink()
{
    struct sockaddr_nl nls;
    int fd;
    struct io *io;
    int newlength = NETLINK_BUFFER;
    struct exec_context *context;

    memset(&nls, 0, sizeof(struct sockaddr_nl));
    nls.nl_family = AF_NETLINK;
    nls.nl_pid = getpid();
    nls.nl_groups = -1;

    fd = socket(PF_NETLINK, SOCK_DGRAM, NETLINK_KOBJECT_UEVENT);

    if (fd == -1)
    {
        exit (17);
    }

    if (bind(fd, (void *)&nls, sizeof(struct sockaddr_nl))) {
        exit (18);
    }

    if (setsockopt (fd, SOL_SOCKET, SO_RCVBUF, &newlength, sizeof (int))) {
        exit(19);
    }

    if (fcntl (fd, F_SETFD, FD_CLOEXEC)) {
        exit(20);
    }

    if (fcntl(fd, F_SETFL, O_NONBLOCK)) {
        exit(21);
    }

    io = io_open (fd);
    io->type = iot_read;

    multiplex_add_io (io, on_netlink_read, on_netlink_close, (void *)0);

    context = execute(EXEC_CALL_NO_IO, (char **)0, (char **)0);
    switch (context->pid)
    {
        case -1:
            exit (25);
        case 0:
            ping_for_uevents("/sys/bus", 1);
            ping_for_uevents("/sys/class", 1);
            ping_for_uevents("/sys/block", 1);
            exit (0);
        default:
            multiplex_add_process(context, mx_on_subprocess_death, (void *)0);
    }
}

int main(void) {
    struct dfs *fs;

    set_resize_mem_recovery_function(rm_recover);
    set_get_mem_recovery_function(gm_recover);

    multiplex_process();
    multiplex_io();

    multiplex_d9s();

    fs = dfs_create ();

    multiplex_add_d9s_socket ("/tmp/dev9-duat-socket", fs);

    connect_to_netlink();
    while (multiplex() != mx_nothing_to_do);

    return 0;
}
