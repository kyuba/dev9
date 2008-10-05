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

#define _BSD_SOURCE

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

#include <sys/mount.h>

#include <dev9/rules.h>

#include <pwd.h>
#include <grp.h>

#ifndef ETCDIR
#define ETCDIR "/etc/dev9/"
#endif

#define DEFAULT_RULES ETCDIR "rules.sx"

/* This is probably a bit excessive, but better safe than sorry right now. */
#define NETLINK_BUFFER (1024*1024*32)

static void connect_to_netlink(struct dfs *);

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

static void on_netlink_read(struct io *io, void *fsv)
{
    struct dfs *fs = (struct dfs *)fsv;
    char *b = io->buffer,
         *fragment_header = b,
         *is = b,
         *ms = b,
         *i = b,
         *max = (b + io->length),
         frag_boundary = 0;
    struct sexpr *attributes = sx_end_of_list;

    while (i < max)
    {
        frag_boundary = 0;

        switch (*i)
        {
            case 0:
                if (i == (max - 1)) /* definitely a fragment end */
                {
                    frag_boundary = 1;
                }

                if (is == ms) /* fragment header */
                {
                    if (is != b) /* first fragment header: nothing to examine */
                    {
                        dev9_rules_apply
                            (cons(make_symbol (fragment_header), attributes),
                             fs);
                    }
                    fragment_header = is;
                    attributes = sx_end_of_list;
                }
                else /* key/value pair */
                {
                    *ms = 0;
                    attributes = cons (cons(make_symbol(is),
                                            make_string(ms+1)),
                                       attributes);
                    *ms = '=';
                }

                i++;
                is = ms = i;
                break;
            case '=':
                if (ms == is) ms = i;
        }

        i++;
    }

    if (frag_boundary)
    {
        dev9_rules_apply
            (cons(make_symbol (fragment_header), attributes), fs);
        io->position += io->length;
    }
    else
    {
        io->position += (int_pointer)(max - fragment_header);
    }
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

static void connect_to_netlink(struct dfs *fs)
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

    multiplex_add_io (io, on_netlink_read, on_netlink_close, (void *)fs);

    context = execute(EXEC_CALL_NO_IO, (char **)0, (char **)0);
    switch (context->pid)
    {
        case -1:
            exit (25);
        case 0:
            ping_for_uevents("/sys/bus", 2);
            ping_for_uevents("/sys/class", 2);
            ping_for_uevents("/sys/block", 2);
            exit (0);
        default:
            multiplex_add_process(context, mx_on_subprocess_death, (void *)0);
    }
}

static void on_rules_read(struct sexpr *sx, struct sexpr_io *io, void *unused)
{
    dev9_rules_add (sx, io);
}

static void print_help()
{
    fprintf (stdout,
             "dev9-1\n"
             "Usage: dev9 [-opmih] [rules-file ...] [-s socket-name]\n"
             "\n"
             " -o          Talk 9p on stdio\n"
             " -s          Talk 9p on the supplied socket-name\n"
             " -p          Mount /proc and /sys\n"
             " -m          Automount dev9 over /dev\n"
             " -i          Initialise common nodes under /dev.\n"
             " -h          Print this and exit.\n"
             "\n"
             " rules-file  The rules file to use, defaults to " DEFAULT_RULES "\n"
             " socket-name The socket to use, defaults to\n"
             "\n"
             "One of -S, -s or -m must be specified.\n"
             "\n"
             "The programme will automatically fork to the background, unless -o is used.\n"
             "\n");
    exit(0);
}

int main(int argc, char **argv, char **envv) {
    int i;
    struct dfs *fs;
    struct group *g;
    struct passwd *u;
    char use_stdio = 0;
    char mount_self = 0;
    char *use_socket = (char *)0;
    char next_socket = 0;
    char had_rules_file = 0;
    char initialise_common = 0;

    set_resize_mem_recovery_function(rm_recover);
    set_get_mem_recovery_function(gm_recover);

    multiplex_sexpr();

    for (i = 1; i < argc; i++) {
        if (argv[i][0] == '-')
        {
            int j;
            for (j = 1; argv[i][j] != (char)0; j++) {
                switch (argv[i][j])
                {
                    case 'o': use_stdio = 1; break;
                    case 'p':
                        mount ("proc", "/proc", "proc", 0, (char *)0);
                        mount ("sys", "/sys", "sysfs", 0, (char *)0);
                        break;
                    case 'i': initialise_common = 1; break;
                    case 'm': mount_self = 1; break;
                    case 's': next_socket = 1; break;
                    default:
                        print_help();
                }
            }
            continue;
        }

        if (next_socket)
        {
            use_socket = argv[i];
            next_socket = 0;
            continue;
        }

        multiplex_add_sexpr(sx_open_io (io_open_read (argv[i]), io_open (-1)),
                            on_rules_read, (void *)0);
        while (multiplex() != mx_nothing_to_do);
        had_rules_file = 1;
    }

    if ((use_socket == (char *)0) && (use_stdio == 0) && (mount_self == 0))
    {
        print_help();
    }

    if (!had_rules_file)
    {
        multiplex_add_sexpr(sx_open_io (io_open_read (DEFAULT_RULES), io_open (-1)),
                            on_rules_read, (void *)0);
        while (multiplex() != mx_nothing_to_do);
    }

    while ((u = getpwent())) dfs_update_user (u->pw_name, u->pw_uid);
    endpwent();
    while ((g = getgrent())) dfs_update_group (g->gr_name, g->gr_gid);
    endgrent();

    fs = dfs_create ();
    fs->root->c.mode |= 0111;

    if (initialise_common)
    {
        struct dfs_directory *d;
        d = dfs_mk_directory (fs->root, "pts");
        d->c.mode |= 0111;
        d = dfs_mk_directory (fs->root, "shm");
        d->c.mode |= 0111;

        dfs_mk_symlink (fs->root, "fd",     "/proc/self/fd");
        dfs_mk_symlink (fs->root, "stdin",  "fd/0");
        dfs_mk_symlink (fs->root, "stdout", "fd/1");
        dfs_mk_symlink (fs->root, "stderr", "fd/2");
    }

    connect_to_netlink(fs);

    multiplex_process();
    multiplex_io();

    multiplex_d9s();

    if (use_stdio)
    {
        multiplex_add_d9s_stdio (fs);
    }
    else
    {
        if (daemon(0, 0) == -1)
            perror ("dev9: could not fork to the background");
    }

    if (use_socket != (char *)0) {
        multiplex_add_d9s_socket (use_socket, fs);
   }

    if (mount_self)
    {
        char options[256];
        struct io *in, *out;
        int fdi[2], fdo[2];

        if ((pipe (fdi) != -1) && (pipe (fdo) != -1))
        {
            struct exec_context *context;
            in  = io_open(fdi[0]);
            out = io_open(fdo[1]);

            multiplex_add_d9s_io(in, out, fs);

            snprintf (options, 256, "access=any,trans=fd,rfdno=%i,wfdno=%i", fdo[0], fdi[1]);

            context = execute(EXEC_CALL_NO_IO, (char **)0, (char **)0);
            switch (context->pid)
            {
                case -1:
                    exit (30);
                case 0:
                    close (fdi[0]);
                    close (fdo[1]);
                    mount ("dev9",   "/dev",     "9p",     0, options);
                    mount ("devpts", "/dev/pts", "devpts", 0, (void *)0);
                    mount ("shm",    "/dev/shm", "tmpfs",  0, (void *)0);
                    exit (0);
                default:
                    close (fdo[0]);
                    close (fdi[1]);
                    multiplex_add_process(context, mx_on_subprocess_death, (void *)0);
            }
        }
    }

    while (multiplex() != mx_nothing_to_do);

    return 0;
}
