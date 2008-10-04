/*
 *  rules.c
 *  dev9
 *
 *  Created by Magnus Deininger on 04/10/2008.
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

#include <dev9/rules.h>
#include <curie/memory.h>
#include <curie/tree.h>
#include <duat/filesystem.h>
#include <string.h>
#include <curie/immutable.h>

#include <regex.h>

static struct tree regex_tree = TREE_INITIALISER;

static struct rule {
    enum dev9_opcodes opcode;

    union {
        struct {
            struct rule *expression;
            struct rule *rules;
        } when;
        struct sexpr *list;
        const char *string;
        signed long int integer;
    } parameters;

    struct rule *next;
} *rules_list = (struct rule *)0;

struct state
{
    char block_device;
    char *user;
    char *group;
    int_32 mode;
    struct sexpr_io *io;
    int_16 majour;
    int_16 minor;
};

static struct sexpr *lookup_symbol (struct sexpr *environ, struct sexpr *key)
{
    struct sexpr *cur = environ;

    while (consp(cur))
    {
        struct sexpr *sx_car = car(cur);

        if (consp(sx_car))
        {
            if (truep(equalp(car(sx_car), key)))
            {
                return cdr(sx_car);
            }
        }

        cur = cdr (cur);
    }

    return sx_nonexistent;
}

static void dev9_rules_add_deep
        (struct sexpr *sx, struct sexpr_io *io, struct rule **currule)
{
    struct rule *rule;
    static struct memory_pool pool = MEMORY_POOL_INITIALISER (sizeof (struct rule));
    static struct memory_pool rxpool = MEMORY_POOL_INITIALISER (sizeof (regex_t));
    static struct sexpr *sym_match = (struct sexpr *)0;
    static struct sexpr *sym_when = (struct sexpr *)0;
    static struct sexpr *sym_mknod = (struct sexpr *)0;
    static struct sexpr *sym_set_group = (struct sexpr *)0;
    static struct sexpr *sym_set_user = (struct sexpr *)0;
    static struct sexpr *sym_set_attribute = (struct sexpr *)0;
    static struct sexpr *sym_set_mode = (struct sexpr *)0;
    static struct sexpr *sym_block_device = (struct sexpr *)0;
    struct sexpr *sxcar, *sxcdr;

    if (sym_match == (struct sexpr *)0)
    {
        sym_match         = make_symbol ("match");
        sym_when          = make_symbol ("when");
        sym_mknod         = make_symbol ("mknod");
        sym_set_group     = make_symbol ("set-group");
        sym_set_user      = make_symbol ("set-user");
        sym_set_attribute = make_symbol ("set-attribute");
        sym_set_mode      = make_symbol ("set-mode");
        sym_block_device  = make_symbol ("block-device");
    }

    if (!consp(sx)) {
        return;
    }

    sxcar = car (sx);
    sxcdr = cdr (sx);

    rule = (struct rule *)get_pool_mem (&pool);
    rule->next = (struct rule *)0;

    if (truep(equalp(sxcar, sym_match))) {
        struct sexpr *tsx = sxcdr;
        rule->opcode = dev9op_match;
        rule->parameters.list = sxcdr;

        while (consp(tsx))
        {
            struct sexpr *tsx_car = car (tsx);

            if (consp(tsx_car))
            {
                struct sexpr *tsxc_car = car (tsx_car);
                struct sexpr *tsxc_cdr = cdr (tsx_car);

                if (symbolp(tsxc_car) && stringp (tsxc_cdr))
                {
                    regex_t *rx = (regex_t *)get_pool_mem (&rxpool);
                    if (regcomp (rx, sx_string(tsxc_cdr),
                                 REG_EXTENDED | REG_NOSUB) == 0)
                    {
                        tree_add_node_string_value
                                (&regex_tree, (char *)sx_string(tsxc_cdr),
                                  (void *)rx);
                    }
                }
            }

            tsx = cdr (tsx);
        }
    } else if (truep(equalp(sxcar, sym_when))) {
        rule->parameters.when.expression = (struct rule *)0;
        rule->parameters.when.rules = (struct rule *)0;

        dev9_rules_add_deep (car (sxcdr), io, &(rule->parameters.when.expression));

        if (rule->parameters.when.expression == (struct rule *)0) {
            free_pool_mem ((void *)rule);
            return;
        }

        dev9_rules_add_deep (car (cdr (sxcdr)), io, &(rule->parameters.when.rules));

        if (rule->parameters.when.rules == (struct rule *)0) {
            free_pool_mem ((void *)rule->parameters.when.expression);
            free_pool_mem ((void *)rule);
            return;
        }

        rule->opcode = dev9op_when;
    } else if (truep(equalp(sxcar, sym_mknod))) {
        rule->opcode = dev9op_mknod;
        rule->parameters.list = sxcdr;
    } else if (truep(equalp(sxcar, sym_set_group))) {
        rule->opcode = dev9op_set_group;
        rule->parameters.string
                = str_immutable_unaligned (sx_string(car(sxcdr)));
    } else if (truep(equalp(sxcar, sym_set_user))) {
        rule->opcode = dev9op_set_user;
        rule->parameters.string
                = str_immutable_unaligned (sx_string(car(sxcdr)));
    } else if (truep(equalp(sxcar, sym_set_attribute))) {
        struct sexpr *tsx = sxcdr;

        while (consp(tsx))
        {
            struct sexpr *tsx_car = car (tsx);

            if (truep(equalp(tsx_car, sym_block_device)))
            {
                rule->opcode = dev9op_set_attribute_block_device;
            }

            tsx = cdr (tsx);
        }
    } else if (truep(equalp(sxcar, sym_set_mode))) {
        rule->opcode = dev9op_set_mode;
        rule->parameters.integer = sx_integer(car(sxcdr));
    } else {
        free_pool_mem ((void *)rule);
        return;
    }

    while ((*currule) != (struct rule *)0) {
        currule = &((*currule)->next);
    }

    (*currule) = rule;
}

static struct sexpr * dev9_rules_apply_deep
        (struct sexpr *sx, struct dfs *fs, struct rule *rule,
         struct state *state)
{
    switch (rule->opcode)
    {
        case dev9op_match:
            {
                struct sexpr *tsx = rule->parameters.list;

                while (consp(tsx))
                {
                    struct sexpr *tsx_car = car (tsx);

                    if (consp(tsx_car))
                    {
                        struct sexpr *tsxc_car = car (tsx_car);
                        struct sexpr *tsxc_cdr = cdr (tsx_car);

                        if (symbolp(tsxc_car) && stringp (tsxc_cdr))
                        {
                            struct tree_node *n
                                    = tree_get_node_string (&regex_tree, (char *)sx_string(tsxc_cdr));
                            regex_t *rx;
                            struct sexpr *against;

                            if (n == (void *)0) return sx_false;

                            against = lookup_symbol (sx, tsxc_car);

                            if (!stringp(against)) return sx_false;

                            rx = (regex_t *)node_get_value (n);

                            if (regexec(rx, sx_string(against), 0, (void *)0, 0)
                                != 0) return sx_false;
                        }
                    }

                    tsx = cdr (tsx);
                }

            }
            return sx_true;
        case dev9op_when:
            if (truep(dev9_rules_apply_deep
                (sx, fs, rule->parameters.when.expression, state)))
            {
                return dev9_rules_apply_deep
                        (sx, fs, rule->parameters.when.rules, state);
            }

            return sx_false;
        case dev9op_mknod:
            {
                struct dfs_directory *dir = fs->root;
                struct sexpr *cur = rule->parameters.list;

                while (consp(cur) && !eolp(cur))
                {
                    struct sexpr *sxcar = car (cur);
                    struct sexpr *sxcdr = cdr (cur);
                    char *dname = (char *)0;

                    if (symbolp(sxcar))
                    {
                        struct sexpr *sxx = lookup_symbol (sx, sxcar);

                        if (stringp(sxx)) {
                            dname = (char *)sx_string(sxx);
                        } else {
                            dname = (char *)sx_symbol(sxcar);
                        }
                    } else if (stringp(sxcar)) {
                        dname = (char *)sx_string(sxcar);
                    }

                    if (dname != (char *)0)
                    {
                        if (eolp(sxcdr))
                        {
                            struct dfs_device *d =
                                dfs_mk_device (dir, dname,
                                               state->block_device ?
                                                       dfs_block_device :
                                                       dfs_character_device,
                                               state->majour,
                                               state->minor);

                            d->c.uid  = state->user;
                            d->c.muid = state->user;
                            d->c.gid  = state->group;
                            d->c.mode = (d->c.mode & ~07777)| state->mode;
                        }
                        else
                        {
                            struct tree_node *n
                                    = tree_get_node_string (dir->nodes, dname);
                            if (n == (struct tree_node *)0) {
                                dir = dfs_mk_directory(dir, dname);
                                dir->c.mode |= 0111;
                            } else {
                                dir =(struct dfs_directory *)node_get_value (n);
                            }

                            if (dir->c.type != dft_directory) return sx_false;
                        }
                    }

                    cur = sxcdr;
                }
            }
            return sx_true;
        case dev9op_set_group:
            state->group = (char *)rule->parameters.string;
            return sx_true;
        case dev9op_set_user:
            state->user = (char *)rule->parameters.string;
            return sx_true;
        case dev9op_set_attribute_block_device:
            state->block_device = (char)1;
            return sx_true;
        case dev9op_set_mode:
            state->mode = rule->parameters.integer;
            return sx_true;
    }

    return sx_false;
}

void dev9_rules_add (struct sexpr *sx, struct sexpr_io *io)
{
    dev9_rules_add_deep (sx, io, &rules_list);
}

void dev9_rules_apply (struct sexpr *sx, struct dfs *fs)
{
    static struct sexpr *sym_devpath   = (struct sexpr *)0;
    static struct sexpr *sym_majour    = (struct sexpr *)0;
    static struct sexpr *sym_minor     = (struct sexpr *)0;
    static struct sexpr *sym_subsystem = (struct sexpr *)0;
    struct sexpr *tsx;
    struct rule *rule = rules_list;
    struct state state =
    {
        .block_device = 0,
        .user         = "root",
        .group        = "group",
        .mode         = 0660,
        .majour       = 0,
        .minor        = 0
    };

    if (sym_devpath == (struct sexpr *)0)
    {
        sym_devpath   = make_symbol ("DEVPATH");
        sym_majour    = make_symbol ("MAJOR");
        sym_minor     = make_symbol ("MINOR");
        sym_subsystem = make_symbol ("SUBSYSTEM");
    }

    tsx = lookup_symbol (sx, sym_devpath);
    if (stringp(tsx))
    {
        char *x = (char *)sx_string (tsx);
        char *y = strrchr (x, '/');

        if (y == (char *)0) {
            y = x;
        } else {
            y++;
        }

        sx = cons(cons (make_symbol("DEV-BASE-PATH"), make_string(y)), sx);
    }

    tsx = lookup_symbol (sx, sym_majour);
    if (stringp(tsx))
    {
        char *x = (char *)sx_string (tsx);
        int i = 0;
        while (x[i])
        {
            state.majour *= 10;
            state.majour += (char)(x[i] - '0');
            i++;
        }
    }

    tsx = lookup_symbol (sx, sym_minor);
    if (stringp(tsx))
    {
        char *x = (char *)sx_string (tsx);
        int i = 0;
        while (x[i])
        {
            state.minor *= 10;
            state.minor += (char)(x[i] - '0');
            i++;
        }
    }

    tsx = lookup_symbol (sx, sym_subsystem);
    if (stringp(tsx))
    {
        state.user  = (char *)str_immutable_unaligned(sx_string (tsx));
        state.group = state.user;
    }

    if ((state.majour == 0) && (state.minor == 0))
    {
        return;
    }

    while (rule != (struct rule *)0)
    {
        (void)dev9_rules_apply_deep (sx, fs, rule, &state);

        rule = rule->next;
    }

    sx_destroy(sx);
}
