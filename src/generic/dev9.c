/*
 *  dev9.c
 *  dev9
 *
 *  Created by Magnus Deininger on 03/10/2008.
 *  Copyright 2008, 2009 Magnus Deininger. All rights reserved.
 *
 */

/*
 * Copyright (c) 2008, 2009, Magnus Deininger All rights reserved.
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

#include <curie/main.h>
#include <curie/multiplex.h>
#include <curie/memory.h>
#include <curie/directory.h>

#include <duat/9p-server.h>
#include <duat/filesystem.h>
#include <duat/sxfs.h>

#include <syscall/syscall.h>

#include <dev9/rules.h>

#include <asm/fcntl.h>
#include <linux/netlink.h>

#define HELPTEXT\
        "dev9-1\n"\
        "Usage: dev9 [-opmih] [rules-file ...] [-s socket-name]\n"\
        "\n"\
        " -o          Talk 9p on stdio\n"\
        " -s          Talk 9p on the supplied socket-name\n"\
        " -p          Mount /proc and /sys\n"\
        " -m          Automount dev9 over /dev\n"\
        " -i          Initialise common nodes under /dev.\n"\
        " -h          Print this and exit.\n"\
        " -f          Don't detach and creep into the background.\n"\
        "\n"\
        " rules-file  The rules file to use, defaults to " DEFAULT_RULES "\n"\
        " socket-name The socket to use, defaults to\n"\
        "\n"\
        "One of -S, -s or -m must be specified.\n"\
        "\n"\
        "The programme will automatically fork to the background, unless -o is used.\n"\
        "\n"\

#ifndef ETCDIR
#define ETCDIR "/etc/dev9/"
#endif

#define DEFAULT_RULES ETCDIR "rules.sx"

/* This is probably a bit excessive, but better safe than sorry right now. */
#define NETLINK_BUFFER (1024*1024*32)

static void connect_to_netlink(struct dfs *);
static struct sexpr_io *queue;
static struct io *queue_io;

define_symbol (sym_disable, "disable");

static void *rm_recover(unsigned long int s, void *c, unsigned long int l)
{
    cexit(22);
    return (void *)0;
}

static void *gm_recover(unsigned long int s)
{
    cexit(23);
    return (void *)0;
}

static void ping_for_uevents (const char *dir) {
    sexpr ueventfiles = read_directory (dir);

    for (sexpr x = ueventfiles; consp(x); x = cdr (x))
    {
        sexpr xcar = car(x);
        int f = sys_open (sx_string(xcar), O_WRONLY, 0);

        if (f >= 0) {
            sys_write (f, "add\n", 4);
            sys_close (f);
        }
    }

    sx_destroy (ueventfiles);
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
    sexpr attributes = sx_end_of_list;

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
                        attributes = cons(make_symbol (fragment_header), attributes);
                        dev9_rules_apply (attributes, fs);
                    }
                    fragment_header = is;
                    sx_destroy (attributes);
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
        attributes = cons(make_symbol (fragment_header), attributes);
        dev9_rules_apply (attributes, fs);
        io->position += io->length;
    }
    else
    {
        io->position += (int_pointer)(max - fragment_header);
    }

    sx_destroy (attributes);

    optimise_static_memory_pools();
    io_flush (io);
}

static void on_netlink_close(struct io *io, void *ignored)
{
    cexit(24);
/*    connect_to_netlink();*/
}

static void mx_on_subprocess_death(struct exec_context *cx, void *d)
{
    if (cx->exitstatus != 0)
        cexit (26);
}

static void connect_to_netlink(struct dfs *fs)
{
    struct sockaddr_nl nls = { 0, 0, 0, 0 };
    int fd;
    struct io *io;
    int newlength = NETLINK_BUFFER;
    struct exec_context *context;

    nls.nl_family = AF_NETLINK;
    nls.nl_pid = sys_getpid();
    nls.nl_groups = -1;

    fd = sys_socket(PF_NETLINK, SOCK_DGRAM, NETLINK_KOBJECT_UEVENT);

    if (fd < 0) { cexit (17); }

    if (sys_bind(fd, (void *)&nls, sizeof(struct sockaddr_nl)) < 0) {
        cexit (18);
    }

    if (sys_setsockopt (fd, SOL_SOCKET, SO_RCVBUF, (char *)&newlength,
                        sizeof (int)) < 0) {
        cexit(19);
    }

    if (sys_fcntl (fd, F_SETFD, FD_CLOEXEC) < 0) {
        cexit(20);
    }

    if (sys_fcntl(fd, F_SETFL, O_NONBLOCK) < 0) {
        cexit(21);
    }

    io = io_open (fd);
    io->type = iot_read;

    multiplex_add_io (io, on_netlink_read, on_netlink_close, (void *)fs);

    context = execute(EXEC_CALL_NO_IO, (char **)0, (char **)0);
    switch (context->pid)
    {
        case -1:
            cexit (25);
        case 0:
            ping_for_uevents ("/sys/(bus|class|block)/.+/.+/uevent");
            cexit (0);
        default:
            multiplex_add_process(context, mx_on_subprocess_death, (void *)0);
    }
}

static void on_rules_read(sexpr sx, struct sexpr_io *io, void *unused)
{
    dev9_rules_add (sx, io);
}

static void mx_sx_ctl_queue_read (sexpr sx, struct sexpr_io *io, void *aux)
{
    if (consp(sx))
    {
        sexpr sxcar = car (sx);
        if (truep(equalp(sxcar, sym_disable)))
        {
            cexit (0);
        }
    }
    sx_destroy (sx);
}

static int_32 on_control_write
        (struct dfs_file *f, int_64 offset, int_32 length, int_8 *data)
{
    io_write (queue_io, (char *)data, length);

    return length;
}

static void print_help()
{
    sys_write (1, HELPTEXT, sizeof (HELPTEXT));
    cexit(0);
}

int cmain() {
    int i;
    struct dfs *fs;
    char use_stdio = 0;
    char mount_self = 0;
    char *use_socket = (char *)0;
    char next_socket = 0;
    char had_rules_file = 0;
    char initialise_common = 0;
    char o_foreground = 0;

    set_resize_mem_recovery_function(rm_recover);
    set_get_mem_recovery_function(gm_recover);

    multiplex_io();
    dfs_update_ids();

    multiplex_sexpr();

    for (i = 1; curie_argv[i]; i++) {
        if (curie_argv[i][0] == '-')
        {
            int j;
            for (j = 1; curie_argv[i][j] != (char)0; j++) {
                switch (curie_argv[i][j])
                {
                    case 'o': use_stdio = 1; break;
                    case 'p':
                        sys_mount ("proc", "/proc", "proc", 0, (char *)0);
                        sys_mount ("sys", "/sys", "sysfs", 0, (char *)0);
                        break;
                    case 'i': initialise_common = 1; break;
                    case 'm': mount_self = 1; break;
                    case 's': next_socket = 1; break;
                    case 'f': o_foreground = 1; break;
                    default:
                        print_help();
                }
            }
            continue;
        }

        if (next_socket)
        {
            use_socket = curie_argv[i];
            next_socket = 0;
            continue;
        }

        multiplex_add_sexpr(sx_open_io (io_open_read (curie_argv[i]),
                                        io_open (-1)),
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

    fs = dfs_create ();
    fs->root->c.mode |= 0111;

    struct dfs_directory *d_dev9 = dfs_mk_directory (fs->root, "dev9");
    struct dfs_file *d_dev9_ctl  = dfs_mk_file (d_dev9, "control", (char *)0,
            (int_8 *)"(nop)\n", 6, (void *)0, (void *)0, on_control_write);

    queue_io = io_open_special();
    d_dev9->c.mode     = 0550;
    d_dev9->c.uid      = "dev9";
    d_dev9->c.gid      = "dev9";
    d_dev9_ctl->c.mode = 0660;
    d_dev9_ctl->c.uid  = "dev9";
    d_dev9_ctl->c.gid  = "dev9";

    queue = sx_open_io (queue_io, queue_io);

    multiplex_add_sexpr (queue, mx_sx_ctl_queue_read, (void *)0);

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

    multiplex_all_processes();

    multiplex_d9s();

    if (use_stdio)
    {
        multiplex_add_d9s_stdio (fs);
    }
    else if (o_foreground == 0)
    {
        struct exec_context *context
                = execute(EXEC_CALL_NO_IO, (char **)0, (char **)0);

        switch (context->pid)
        {
            case -1:
                cexit (11);
            case 0:
                break;
            default:
                cexit (0);
        }
    }

    if (use_socket != (char *)0) {
        multiplex_add_d9s_socket (use_socket, fs);
    }

    if (mount_self)
    {
        static char options[] =
                "access=any,trans=fd,rfdno=000000,wfdno=000000";
        struct io *in, *out;
        int fdi[2], fdo[2];

        if ((sys_pipe (fdi) != -1) && (sys_pipe (fdo) != -1))
        {
            struct exec_context *context;
            in  = io_open(fdi[0]);
            out = io_open(fdo[1]);

            multiplex_add_d9s_io(in, out, fs);

            if (!((fdo[0] > 999999) || (fdi[1] > 999999) ||
                  (fdo[0] < 1)      || (fdi[1] < 1)))
            {
                int tj, ti, mn, s2 = 44;

                for (tj = 31, ti = fdo[0], mn = 6; ti > 0; tj--, ti /= 10, mn--)
                {
                    options[tj] = '0' + (ti % 10);
                }

                for (tj = 26, ti = tj + mn; options[ti]; tj++, ti++)
                {
                    options[tj] = options[ti];
                }
                options[tj] = options[ti];

                s2 -= mn;

                for (tj = s2, ti = fdi[1], mn = 6; ti > 0; tj--, ti /= 10, mn--)
                {
                    options[tj] = '0' + (ti % 10);
                }

                for (tj = s2-5, ti = tj + mn; options[ti]; tj++, ti++)
                {
                    options[tj] = options[ti];
                }
                options[tj] = options[ti];

                context = execute(EXEC_CALL_NO_IO, (char **)0, (char **)0);
                switch (context->pid)
                {
                    case -1:
                        cexit (30);
                    case 0:
                        sys_close (fdi[0]);
                        sys_close (fdo[1]);
                        sys_mount ("dev9",   "/dev",     "9p",     0, options);
                        if (initialise_common)
                        {
                            sys_mount ("devpts", "/dev/pts", "devpts", 0, (void *)0);
                            sys_mount ("shm",    "/dev/shm", "tmpfs",  0, (void *)0);
                        }
                        cexit (0);
                    default:
                        sys_close (fdo[0]);
                        sys_close (fdi[1]);
                        multiplex_add_process(context, mx_on_subprocess_death, (void *)0);
                }
            }
        }
    }

    while (multiplex() != mx_nothing_to_do);

    return 0;
}
