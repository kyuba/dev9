/*
 * This file is part of the kyuba.org Dev9 project.
 * See the appropriate repository at http://git.kyuba.org/ for exact file
 * modification records.
*/

/*
 * Copyright (c) 2008, 2009, Kyuba Project Members
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
*/

#include <dev9/rules.h>
#include <curie/memory.h>
#include <curie/tree.h>
#include <duat/filesystem.h>
#include <curie/immutable.h>
#include <curie/regex.h>

static struct tree regex_tree = TREE_INITIALISER;

define_symbol (sym_devpath,       "DEVPATH");
define_symbol (sym_devbasepath,   "DEV-BASE-PATH");
define_symbol (sym_majour,        "MAJOR");
define_symbol (sym_minor,         "MINOR");
define_symbol (sym_subsystem,     "SUBSYSTEM");
define_symbol (sym_match,         "match");
define_symbol (sym_when,          "when");
define_symbol (sym_mknod,         "mknod");
define_symbol (sym_set_group,     "set-group");
define_symbol (sym_set_user,      "set-user");
define_symbol (sym_set_attribute, "set-attribute");
define_symbol (sym_set_mode,      "set-mode");
define_symbol (sym_block_device,  "block-device");

static struct rule {
    enum dev9_opcodes opcode;

    union {
        struct {
            struct rule *expression;
            struct rule *rules;
        } when;
        sexpr list;
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

static sexpr lookup_symbol (sexpr environ, sexpr key)
{
    sexpr cur = environ;

    while (consp(cur))
    {
        sexpr sx_car = car(cur);

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
        (sexpr sx, struct sexpr_io *io, struct rule **currule)
{
    struct rule *rule;
    static struct memory_pool pool = MEMORY_POOL_INITIALISER (sizeof (struct rule));
    sexpr sxcar, sxcdr;

    if (!consp(sx)) {
        return;
    }

    sxcar = car (sx);
    sxcdr = cdr (sx);

    rule = (struct rule *)get_pool_mem (&pool);
    rule->next = (struct rule *)0;

    if (truep(equalp(sxcar, sym_match))) {
        sexpr tsx = sxcdr;
        rule->opcode = dev9op_match;
        rule->parameters.list = sxcdr;

        while (consp(tsx))
        {
            sexpr tsx_car = car (tsx);

            if (consp(tsx_car))
            {
                sexpr tsxc_car = car (tsx_car);
                sexpr tsxc_cdr = cdr (tsx_car);

                if (symbolp(tsxc_car) && stringp (tsxc_cdr))
                {
                    sexpr g = rx_compile_sx (tsxc_cdr);

                    tree_add_node_string_value
                            (&regex_tree, (char *)sx_string(tsxc_cdr), (void *)g);
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
        sexpr tsx = sxcdr;

        while (consp(tsx))
        {
            sexpr tsx_car = car (tsx);

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

static sexpr  dev9_rules_apply_deep
        (sexpr sx, struct dfs *fs, struct rule *rule,
         struct state *state)
{
    switch (rule->opcode)
    {
        case dev9op_match:
            {
                sexpr tsx = rule->parameters.list;

                while (consp(tsx))
                {
                    sexpr tsx_car = car (tsx);

                    if (consp(tsx_car))
                    {
                        sexpr tsxc_car = car (tsx_car);
                        sexpr tsxc_cdr = cdr (tsx_car);

                        if (symbolp(tsxc_car) && stringp (tsxc_cdr))
                        {
                            struct tree_node *n
                                    = tree_get_node_string (&regex_tree, (char *)sx_string(tsxc_cdr));
                            sexpr rx;
                            sexpr against;

                            if (n == (void *)0) return sx_false;

                            against = lookup_symbol (sx, tsxc_car);

                            if (!stringp(against)) return sx_false;

                            rx = (sexpr)node_get_value (n);

                            if (falsep(rx_match_sx (rx, against)))
                                return sx_false;
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
                sexpr cur = rule->parameters.list;

                while (consp(cur) && !eolp(cur))
                {
                    sexpr sxcar = car (cur);
                    sexpr sxcdr = cdr (cur);
                    char *dname = (char *)0;

                    if (symbolp(sxcar))
                    {
                        sexpr sxx = lookup_symbol (sx, sxcar);

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
                        struct tree_node *n
                                = tree_get_node_string (dir->nodes, dname);

                        if (eolp(sxcdr))
                        {
                            struct dfs_device *d;
                            if (n == (struct tree_node *)0) {
                                d = dfs_mk_device (dir, dname,
                                                   state->block_device ?
                                                           dfs_block_device :
                                                           dfs_character_device,
                                                   state->majour,
                                                   state->minor);
                            } else {
                                d = (struct dfs_device *)node_get_value (n);

                                if (d->c.type != dft_device) {
                                    return sx_false;
                                }

                                d->majour = state->majour;
                                d->minor = state->minor;
                                d->type = state->block_device ?
                                              dfs_block_device :
                                              dfs_character_device;
                            }

                            d->c.uid  = state->user;
                            d->c.muid = state->user;
                            d->c.gid  = state->group;
                            d->c.mode = (d->c.mode & ~07777)| state->mode;
                        }
                        else
                        {
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

void dev9_rules_add (sexpr sx, struct sexpr_io *io)
{
    dev9_rules_add_deep (sx, io, &rules_list);
}

void dev9_rules_apply (sexpr sx, struct dfs *fs)
{
    sexpr tsx;
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

    tsx = lookup_symbol (sx, sym_devpath);
    if (stringp(tsx))
    {
        char *x = (char *)sx_string (tsx);
        char *y = x;

        for (char *c = x; (*c) != 0; c++)
        {
            if ((*c) == '/') y = c + 1;
        }

        sx = cons(cons (sym_devbasepath, make_string(y)), sx);
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
}
