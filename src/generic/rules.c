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

static struct rule {
    enum dev9_opcodes opcode;

    struct sexpr *raw_parameters;

    union {
        struct {
            struct rule *expression;
            struct rule *rules;
        } when;
    } parameters;

    struct rule *next;
} *rules_list = (struct rule *)0;

static void dev9_rules_add_deep
        (struct sexpr *sx, struct sexpr_io *io, struct rule **currule)
{
    struct rule *rule;
    static struct memory_pool pool = MEMORY_POOL_INITIALISER (sizeof (struct rule));
    static struct sexpr *sym_match = (struct sexpr *)0;
    static struct sexpr *sym_when = (struct sexpr *)0;
    static struct sexpr *sym_mknod = (struct sexpr *)0;
    static struct sexpr *sym_set_group = (struct sexpr *)0;
    static struct sexpr *sym_set_user = (struct sexpr *)0;
    static struct sexpr *sym_set_attribute = (struct sexpr *)0;
    static struct sexpr *sym_set_mode = (struct sexpr *)0;
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
    }

    if (!consp(sx)) {
        return;
    }

    sxcar = car (sx);
    sxcdr = cdr (sx);

    rule = (struct rule *)get_pool_mem (&pool);
    rule->raw_parameters = sxcdr;

    if (truep(equalp(sxcar, sym_match))) {
        rule->opcode = dev9op_match;
    } else if (truep(equalp(sxcar, sym_when))) {
        rule->parameters.when.expression = (struct rule *)0;
        rule->parameters.when.rules = (struct rule *)0;

        dev9_rules_add_deep (car (sxcdr), io, &(rule->parameters.when.expression));
        dev9_rules_add_deep (car (cdr (sxcdr)), io, &(rule->parameters.when.rules));

        rule->opcode = dev9op_when;
    } else if (truep(equalp(sxcar, sym_mknod))) {
        rule->opcode = dev9op_mknod;
    } else if (truep(equalp(sxcar, sym_set_group))) {
        rule->opcode = dev9op_set_group;
    } else if (truep(equalp(sxcar, sym_set_user))) {
        rule->opcode = dev9op_set_user;
    } else if (truep(equalp(sxcar, sym_set_attribute))) {
        rule->opcode = dev9op_set_attribute;
    } else if (truep(equalp(sxcar, sym_set_mode))) {
        rule->opcode = dev9op_set_mode;
    } else {
        return;
    }

    while ((*currule) != (struct rule *)0) {
        currule = &((*currule)->next);
    }

    rule->next = (struct rule *)0;

    (*currule) = rule;
}

void dev9_rules_add (struct sexpr *sx, struct sexpr_io *io)
{
    dev9_rules_add_deep (sx, io, &rules_list);
}

void dev9_rules_apply (struct sexpr *sx, struct dfs *fs)
{
    static struct sexpr_io *io = (struct sexpr_io *)0;
    struct rule *rule = rules_list;

    if (io == (struct sexpr_io *)0)
    {
        io = sx_open_stdio();
    }

    sx_write (io, sx);

    while (rule != (struct rule *)0)
    {
        switch (rule->opcode)
        {
            case dev9op_match:
                sx_write (io, make_symbol ("match"));
                break;
            case dev9op_when:
                sx_write (io, make_symbol ("when"));
                break;
            case dev9op_mknod:
                sx_write (io, make_symbol ("mknod"));
                break;
            case dev9op_set_group:
                sx_write (io, make_symbol ("set-group"));
                break;
            case dev9op_set_user:
                sx_write (io, make_symbol ("set-user"));
                break;
            case dev9op_set_attribute:
                sx_write (io, make_symbol ("set-attributes"));
                break;
            case dev9op_set_mode:
                sx_write (io, make_symbol ("set-mode"));
                break;
        }

        sx_write (io, rule->raw_parameters);

        rule = rule->next;
    }

    sx_destroy(sx);
}
