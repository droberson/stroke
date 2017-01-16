/* stroke.h -- Minor formatting changes from the original
 */

/*
 *  $Id: stroke.h,v 1.1.1.1 2001/11/29 00:16:48 route Exp $
 *
 *  Building Open Source Network Security Tools
 *  stroke.h - pcap example code
 *
 *  Copyright (c) 2002 Mike D. Schiffman <mike@infonexus.com>
 *  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 */

#include <unistd.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <pcap.h>
#include <signal.h>

#include "oui.h"

#define SNAPLEN         34
#define PROMISC         1
#define TIMEOUT         500
#define FILTER          "ip"
#define HASH_TABLE_SIZE 2048

struct table_entry {
  u_char mac[6];
  struct table_entry *next;
};

const char *b_search(u_char *);
char *eprintf(u_char *);
char *iprintf(u_char *);
int interesting(u_char *, struct table_entry **);
int ht_dup_check(u_char *, struct table_entry **, int);
int ht_add_entry(u_char *, struct table_entry **, int);
u_long ht_hash(u_char *);
void ht_init_table(struct table_entry **);
void cleanup(int);
int catch_sig(int, void(*)());
