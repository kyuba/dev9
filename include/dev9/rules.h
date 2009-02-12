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

#ifdef __cplusplus
extern "C" {
#endif

#ifndef DEV9_RULES_H
#define DEV9_RULES_H

#include <curie/sexpr.h>
#include <duat/filesystem.h>

enum dev9_opcodes {
    dev9op_match,
    dev9op_when,
    dev9op_mknod,
    dev9op_set_group,
    dev9op_set_user,
    dev9op_set_attribute_block_device,
    dev9op_set_mode
};

void dev9_rules_add (sexpr, struct sexpr_io *);
void dev9_rules_apply (sexpr, struct dfs *);

#endif

#ifdef __cplusplus
}
#endif
