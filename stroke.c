/* stroke.c -- Formatting and other minor tweaks from original.
 */

/*
 *  $Id: stroke.c,v 1.1.1.1 2001/11/29 00:16:48 route Exp $
 *
 *  Building Open Source Network Security Tools
 *  stroke.c - pcap example code
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

#include "stroke.h"

int loop = 1;
u_long mac = 0;

int main(int argc, char *argv[]) {
  int c;
  pcap_t *p;
  char *device;
  u_char *packet;
  int print_ip;
  struct pcap_pkthdr h;
  struct pcap_stat ps;
  char errbuf[PCAP_ERRBUF_SIZE];
  struct bpf_program filter_code;
  bpf_u_int32 local_net, netmask;
  struct table_entry *hash_table[HASH_TABLE_SIZE];

  device = NULL;
  print_ip = 0;

  while ((c = getopt(argc, argv, "Ii:")) != EOF) {
    switch (c) {
    case 'I':
      print_ip = 1;
      break;
    case 'i':
      device = optarg;
      break;
    default:
      exit(EXIT_FAILURE);
    }
  }

  printf("Stroke 1.1 [passive MAC -> OUI mapping tool]\n");

  if (device == NULL) {
    device = pcap_lookupdev(errbuf);
    if (device == NULL) {
      fprintf(stderr, "pcap_lookupdev() failed: %s\n", errbuf);
      exit(EXIT_FAILURE);
    }
  }

  p = pcap_open_live(device, SNAPLEN, PROMISC, TIMEOUT, errbuf);
  if (p == NULL) {
    fprintf(stderr,"pcap_open_live() failed: %s\n", errbuf);
    exit(EXIT_FAILURE);
  }

  if (pcap_lookupnet(device, &local_net, &netmask, errbuf) == -1) {
    fprintf(stderr, "pcap_lookupnet() failed: %s\n", errbuf);
    pcap_close(p);
    exit(EXIT_FAILURE);
  }

  if (pcap_compile(p, &filter_code, FILTER, 1, netmask) == -1) {
    fprintf(stderr, "pcap_compile() failed: %s\n", pcap_geterr(p));
    pcap_close(p);
    exit(EXIT_FAILURE);
  }

  if (pcap_setfilter(p, &filter_code) == -1) {
    fprintf(stderr, "pcap_setfilter() failed: %s\n", pcap_geterr(p));
    pcap_close(p);
    exit(EXIT_FAILURE);
  }

  if (pcap_datalink(p) != DLT_EN10MB) {
    fprintf(stderr, "Stroke only works with ethernet.\n");
    pcap_close(p);
    exit(EXIT_FAILURE);
  }

  if (catch_sig(SIGINT, cleanup) == -1) {
    fprintf(stderr, "can't catch SIGINT.\n");
    pcap_close(p);
    exit(EXIT_FAILURE);
  }

  for (ht_init_table(hash_table); loop;) {
    packet = (u_char *)pcap_next(p, &h);
    if (packet == NULL)
      continue;

    if (interesting(packet, hash_table)) {
      if (print_ip) {
	printf("%s @ %s -> %s\n",
	       eprintf(packet),
	       iprintf(packet + 26),
	       b_search(packet + 6));
      } else {
	printf("%s -> %s\n",
	       eprintf(packet),
	       b_search(packet + 6));
      }
    }
  }

  if (pcap_stats(p, &ps) == -1) {
    fprintf(stderr, "pcap_stats() failed: %s\n", pcap_geterr(p));
  } else {
    printf("Packets received by libpcap:\t%6d\n", ps.ps_recv);
    printf("Packets dropped by libpcap:\t%6d\n", ps.ps_drop);
    printf("Unique MAC addresses stored:\t%ld\n", mac);
  }

  pcap_close(p);
  return EXIT_SUCCESS;
}


const char *b_search(u_char *prefix) {
  struct oui *ent;
  int start, end, diff, mid;

  start = 0;
  end = sizeof(oui_table) / sizeof(oui_table[0]);

  while (end > start) {
    mid = (start + end) / 2;
    ent = &oui_table[mid];

    diff = prefix[0] - ent->prefix[0];
    if (diff == 0) {
      /* first byte matches */
      diff = prefix[1] - ent->prefix[1];
    }

    if (diff == 0) {
      /* second byte matches */
      diff = prefix[2] - ent->prefix[2];
    }

    if (diff == 0) {
      /* third byte matches */
      return ent->vendor;
    }

    if (diff < 0) {
      end = mid;
    } else {
      start = mid + 1;
    }
  }

  return "Unknown Vendor";
}


char *eprintf(u_char *packet) {
  int n;
  static char address[16];

  n =  sprintf(address, "%.2x:", packet[6]);
  n += sprintf(address + n, "%.2x:", packet[7]);
  n += sprintf(address + n, "%.2x:", packet[8]);
  n += sprintf(address + n, "%.2x:", packet[9]);
  n += sprintf(address + n, "%.2x:", packet[10]);
  n += sprintf(address + n, "%.2x", packet[11]);
  address[n] = '\0';

  return address;
}


char *iprintf(u_char *address) {
  static char ip[17];

  sprintf(ip, "%3d.%3d.%3d.%3d",
	  (address[0] & 255),
	  (address[1] & 255),
	  (address[2] & 255),
	  (address[3] & 255));

  return ip;
}


int interesting(u_char *packet, struct table_entry **hash_table) {
  u_long n;

  n = ht_hash(packet);

  if (hash_table[n]) {
    /* check to see if this is a duplicate entry or collision */
    if (!ht_dup_check(packet, hash_table, n)) {
      /* this is a collision, lets add a bucket */
      if (ht_add_entry(packet, hash_table, n)) {
	mac++;
        return 1;
      }
    }
    else {
      return 0;
    }
  }

  else {
    /* this table slot is free */
    if (ht_add_entry(packet, hash_table, n)) {
      mac++;
      return 1;
    }
  }
  return 0;
}


int ht_dup_check(u_char *packet, struct table_entry **hash_table, int loc) {
  struct table_entry *p;

  for (p = hash_table[loc]; p; p = p->next) {
    if (p->mac[0] == packet[6]  &&
	p->mac[1] == packet[7]  &&
	p->mac[2] == packet[8]  &&
	p->mac[3] == packet[9]  &&
	p->mac[4] == packet[10] &&
	p->mac[5] == packet[11]) {
      /* this MAC is already in our table */
      return 1;
    }
  }

  /* this MAC has collided with another entry */
  return 0;
}


int ht_add_entry(u_char *packet, struct table_entry **hash_table, int loc) {
  struct table_entry *p;

  if (hash_table[loc] == NULL) {
    hash_table[loc] = malloc(sizeof(struct table_entry));
    if (hash_table[loc] == NULL) {
      return 0;
    }

    hash_table[loc]->mac[0] = packet[6];
    hash_table[loc]->mac[1] = packet[7];
    hash_table[loc]->mac[2] = packet[8];
    hash_table[loc]->mac[3] = packet[9];
    hash_table[loc]->mac[4] = packet[10];
    hash_table[loc]->mac[5] = packet[11];
    
    hash_table[loc]->next = NULL;

    return 1;
  }

  else {
    /* this is a chain, find the end of it */
    for (p = hash_table[loc]; p->next; p = p->next);
    p->next = malloc(sizeof(struct table_entry));
    if (p->next == NULL) {
      return 0;
    }

    p = p->next;
    p->mac[0] = packet[6];
    p->mac[1] = packet[7];
    p->mac[2] = packet[8];
    p->mac[3] = packet[9];
    p->mac[4] = packet[10];
    p->mac[5] = packet[11];

    p->next = NULL;
  }

  return 1;
}


u_long ht_hash(u_char *packet) {
  int i;
  u_long j;

  for (i = 6, j = 0; i != 12; i++) {
    j = (j * 13) + packet[i];
  }

  return j %= HASH_TABLE_SIZE;
}


void ht_init_table(struct table_entry **hash_table) {
  int c;

  for (c = 0; c <HASH_TABLE_SIZE; c++) {
    hash_table[c] = NULL;
  }
}


void cleanup(int sig) {
  loop = 0;
  printf("Interrupt signal caught...\n");
}

int catch_sig(int sig, void (*handler)()) {
  struct sigaction action;

  action.sa_handler = handler;
  sigemptyset(&action.sa_mask);
  action.sa_flags = 0;
  if (sigaction(sig, &action, NULL) == -1) {
    return -1;
  }
  else {
    return 1;
  }
}

