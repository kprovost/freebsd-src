/*	$OpenBSD: pf_syncookies.c,v 1.7 2018/09/10 15:54:28 henning Exp $ */

/* Copyright (c) 2016,2017 Henning Brauer <henning@openbsd.org>
 * Copyright (c) 2016 Alexandr Nedvedicky <sashan@openbsd.org>
 *
 * syncookie parts based on FreeBSD sys/netinet/tcp_syncache.c
 *
 * Copyright (c) 2001 McAfee, Inc.
 * Copyright (c) 2006,2013 Andre Oppermann, Internet Business Solutions AG
 * All rights reserved.
 *
 * This software was developed for the FreeBSD Project by Jonathan Lemon
 * and McAfee Research, the Security Research Division of McAfee, Inc. under
 * DARPA/SPAWAR contract N66001-01-C-8035 ("CBOSS"), as part of the
 * DARPA CHATS research program. [2001 McAfee, Inc.]
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
 */

/*
 * when we're under synflood, we use syncookies to prevent state table
 * exhaustion. Trigger for the synflood mode is the number of half-open
 * connections in the state table.
 * We leave synflood mode when the number of half-open states - including
 * in-flight syncookies - drops far enough again
 */
 
/*
 * syncookie enabled Initial Sequence Number:
 *  24 bit MAC
 *   3 bit WSCALE index
 *   3 bit MSS index
 *   1 bit SACK permitted
 *   1 bit odd/even secret
 *
 * References:
 *  RFC4987 TCP SYN Flooding Attacks and Common Mitigations
 *  http://cr.yp.to/syncookies.html    (overview)
 *  http://cr.yp.to/syncookies/archive (details)
 */

//#include "pflog.h"

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/mbuf.h>
#include <sys/filio.h>
#include <sys/socket.h>
#include <sys/socketvar.h>
#include <sys/kernel.h>
#include <sys/time.h>
#include <sys/proc.h>
#include <sys/rwlock.h>
#include <sys/syslog.h>

#include <crypto/siphash/siphash.h>

#include <net/if.h>
#include <net/if_var.h>
#include <net/if_types.h>
#include <net/route.h>

#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/tcp_var.h>

#include <net/pfvar.h>

#define	DPFPRINTF(n, x)	if (V_pf_status.debug >= (n)) printf x

union pf_syncookie {
	uint8_t		cookie;
	struct {
		uint8_t	oddeven:1,
			sack_ok:1,
			wscale_idx:3,
			mss_idx:3;
	} flags;
};

#define	PF_SYNCOOKIE_SECRET_SIZE	SIPHASH_KEY_LENGTH
#define	PF_SYNCOOKIE_SECRET_LIFETIME	15 /* seconds */

static struct {
	struct callout	keytimeout;
	uint8_t		oddeven;	/* XXX TODO, locking? Access pattern? */
	uint8_t		key[2][SIPHASH_KEY_LENGTH];
#if 0
	uint32_t	hiwat;	/* absolute; # of states */
	uint32_t	lowat;
#endif
} pf_syncookie_status;

void		pf_syncookie_rotate(void *);
void		pf_syncookie_newkey(void);
uint32_t	pf_syncookie_mac(struct pf_pdesc *, union pf_syncookie,
		    uint32_t);
uint32_t	pf_syncookie_generate(struct mbuf *m, int off, struct pf_pdesc *,
		    uint16_t);

void
pf_syncookies_init(void)
{
	callout_init(&pf_syncookie_status.keytimeout, 1);
#if 0
	pf_syncookie_status.hiwat = PFSTATE_HIWAT * PF_SYNCOOKIES_HIWATPCT/100;
	pf_syncookie_status.lowat = PFSTATE_HIWAT * PF_SYNCOOKIES_LOWATPCT/100;
#endif
	pf_syncookies_setmode(PF_SYNCOOKIES_NEVER);
}

int
pf_syncookies_setmode(u_int8_t mode)
{
	if (mode > PF_SYNCOOKIES_MODE_MAX)
		return (EINVAL);

	if (V_pf_status.syncookies_mode == mode)
		return (0);

	V_pf_status.syncookies_mode = mode;
	if (V_pf_status.syncookies_mode == PF_SYNCOOKIES_ALWAYS) {
		pf_syncookie_newkey();
		V_pf_status.syncookies_active = true;
	}
	return (0);
}

#if 0 
int
pf_syncookies_setwats(u_int32_t hiwat, u_int32_t lowat)
{
	if (lowat > hiwat)
		return (EINVAL);

	pf_syncookie_status.hiwat = hiwat;
	pf_syncookie_status.lowat = lowat;
	return (0);
}

int
pf_syncookies_getwats(struct pfioc_synflwats *wats)
{
	wats->hiwat = pf_syncookie_status.hiwat;
	wats->lowat = pf_syncookie_status.lowat;
	return (0);
}
#endif

int
pf_synflood_check(struct pf_pdesc *pd)
{
	MPASS(pd->proto == IPPROTO_TCP);

	if (pd->pf_mtag && (pd->pf_mtag->tag & PF_TAG_SYNCOOKIE_RECREATED))
		return (0);

	//MPASS(V_pf_status.syncookies_mode != PF_SYNCOOKIES_ADAPTIVE);

	//if (V_pf_status.syncookies_mode != PF_SYNCOOKIES_ADAPTIVE)
		return (V_pf_status.syncookies_mode);
/*
	if (!V_pf_status.syncookies_active &&
	    V_pf_status.states_halfopen > pf_syncookie_status.hiwat) {
		pf_syncookie_newkey();
		V_pf_status.syncookies_active = true;
		DPFPRINTF(PF_DEBUG_URGENT,
		    ("synflood detected, enabling syncookies"));
		V_pf_status.lcounters[LCNT_SYNFLOODS]++;
	}

	return (V_pf_status.syncookies_active);*/
}

void
pf_syncookie_send(struct mbuf *m, int off, struct pf_pdesc *pd)
{
	uint16_t	mss;
	uint32_t	iss;

	mss = max(V_tcp_mssdflt, pf_get_mss(m, off, pd->hdr.tcp->th_off, pd->af));
	iss = pf_syncookie_generate(m, off, pd, mss);
	pf_send_tcp(NULL, pd->af, pd->dst, pd->src, *pd->dport, *pd->sport,
	    iss, ntohl(pd->hdr.tcp->th_seq) + 1, TH_SYN|TH_ACK, 0, mss,
	    0, 1, 0);
	//V_pf_status.syncookies_inflight[pf_syncookie_status.oddeven]++;
	//V_pf_status.lcounters[LCNT_SYNCOOKIES_SENT]++;
}

uint8_t
pf_syncookie_validate(struct pf_pdesc *pd)
{
	uint32_t		 hash, ack, seq;
	union pf_syncookie	 cookie;

	MPASS(pd->proto == IPPROTO_TCP);

	seq = ntohl(pd->hdr.tcp->th_seq) - 1;
	ack = ntohl(pd->hdr.tcp->th_ack) - 1;
	cookie.cookie = (ack & 0xff) ^ (ack >> 24);

	/* we don't know oddeven before setting the cookie (union) */
	if (V_pf_status.syncookies_inflight[cookie.flags.oddeven] == 0)
		return (0);

	hash = pf_syncookie_mac(pd, cookie, seq);
	if ((ack & ~0xff) != (hash & ~0xff))
		return (0);

	V_pf_status.syncookies_inflight[cookie.flags.oddeven]--;
	V_pf_status.lcounters[LCNT_SYNCOOKIES_VALID]++;
	return (1);
}

/*
 * all following functions private
 */
void
pf_syncookie_rotate(void *arg)
{
	MPASS(arg == NULL);

	/* do we want to disable syncookies? */
	if (V_pf_status.syncookies_active /*&&
	    ((V_pf_status.syncookies_mode == PF_SYNCOOKIES_ADAPTIVE &&
	    V_pf_status.states_halfopen + V_pf_status.syncookies_inflight[0] +
	    V_pf_status.syncookies_inflight[1] < pf_syncookie_status.lowat) ||
	    V_pf_status.syncookies_mode == PF_SYNCOOKIES_NEVER)*/) {
		V_pf_status.syncookies_active = false;
		DPFPRINTF(PF_DEBUG_MISC, ("syncookies disabled"));
	}

	/* nothing in flight any more? delete keys and return */
	if (!V_pf_status.syncookies_active &&
	    V_pf_status.syncookies_inflight[0] == 0 &&
	    V_pf_status.syncookies_inflight[1] == 0) {
		memset(pf_syncookie_status.key[0], 0,
		    PF_SYNCOOKIE_SECRET_SIZE);
		memset(pf_syncookie_status.key[1], 0,
		    PF_SYNCOOKIE_SECRET_SIZE);
		return;
	}

	/* new key, including timeout */
	pf_syncookie_newkey();
}

void
pf_syncookie_newkey(void)
{
	pf_syncookie_status.oddeven = (pf_syncookie_status.oddeven + 1) & 0x1;
	V_pf_status.syncookies_inflight[pf_syncookie_status.oddeven] = 0;
	arc4random_buf(pf_syncookie_status.key[pf_syncookie_status.oddeven],
	    PF_SYNCOOKIE_SECRET_SIZE);
	callout_reset(&pf_syncookie_status.keytimeout,
	    PF_SYNCOOKIE_SECRET_LIFETIME, pf_syncookie_rotate, NULL);
}

/*
 * Distribution and probability of certain MSS values.  Those in between are
 * rounded down to the next lower one.
 * [An Analysis of TCP Maximum Segment Sizes, S. Alcock and R. Nelson, 2011]
 *   .2%  .3%   5%    7%    7%    20%   15%   45%
 */
static int pf_syncookie_msstab[] = 
    { 216, 536, 1200, 1360, 1400, 1440, 1452, 1460 };

/*
 * Distribution and probability of certain WSCALE values.
 * The absence of the WSCALE option is encoded with index zero.
 * [WSCALE values histograms, Allman, 2012]
 *                                  X 10 10 35  5  6 14 10%   by host
 *                                  X 11  4  5  5 18 49  3%   by connections
 */
static int pf_syncookie_wstab[] = { 0, 0, 1, 2, 4, 6, 7, 8 };

uint32_t
pf_syncookie_mac(struct pf_pdesc *pd, union pf_syncookie cookie, uint32_t seq)
{
	SIPHASH_CTX	ctx;
	uint32_t	siphash[2];

	MPASS(pd->proto == IPPROTO_TCP);

	SipHash24_Init(&ctx);
	SipHash_SetKey(&ctx, pf_syncookie_status.key[cookie.flags.oddeven]);

	switch (pd->af) {
	case AF_INET:
		SipHash_Update(&ctx, pd->src, sizeof(pd->src->v4));
		SipHash_Update(&ctx, pd->dst, sizeof(pd->dst->v4));
		break;
	case AF_INET6:
		SipHash_Update(&ctx, pd->src, sizeof(pd->src->v6));
		SipHash_Update(&ctx, pd->dst, sizeof(pd->dst->v6));
		break;
	default:
		panic("unknown address family");
	}

	SipHash_Update(&ctx, pd->sport, sizeof(*pd->sport));
	SipHash_Update(&ctx, pd->dport, sizeof(*pd->dport));
	SipHash_Update(&ctx, &seq, sizeof(seq));
	SipHash_Update(&ctx, &cookie, sizeof(cookie));
	SipHash_Final((uint8_t *)&siphash, &ctx);

	return (siphash[0] ^ siphash[1]);
}

uint32_t
pf_syncookie_generate(struct mbuf *m, int off, struct pf_pdesc *pd,
    uint16_t mss)
{
	uint8_t			 i, wscale;
	uint32_t		 iss, hash;
	union pf_syncookie	 cookie;

	cookie.cookie = 0;

	/* map MSS */
	for (i = nitems(pf_syncookie_msstab) - 1;
	    pf_syncookie_msstab[i] > mss && i > 0; i--)
		/* nada */;
	cookie.flags.mss_idx = i;

	/* map WSCALE */
	wscale = pf_get_wscale(m, off, pd->hdr.tcp->th_off, pd->af);
	for (i = nitems(pf_syncookie_wstab) - 1;
	    pf_syncookie_wstab[i] > wscale && i > 0; i--)
		/* nada */;
	cookie.flags.wscale_idx = i;
	cookie.flags.sack_ok = 0;	/* XXX */

	cookie.flags.oddeven = pf_syncookie_status.oddeven;
	hash = pf_syncookie_mac(pd, cookie, ntohl(pd->hdr.tcp->th_seq));

	/*
	 * Put the flags into the hash and XOR them to get better ISS number
	 * variance.  This doesn't enhance the cryptographic strength and is
	 * done to prevent the 8 cookie bits from showing up directly on the
	 * wire.
	 */
	iss = hash & ~0xff;
	iss |= cookie.cookie ^ (hash >> 24);

	return (iss);
}

struct mbuf *
pf_syncookie_recreate_syn(uint8_t ttl, int off, struct pf_pdesc *pd)
{
	uint8_t			 wscale;
	uint16_t		 mss;
	uint32_t		 ack, seq;
	union pf_syncookie	 cookie;

	seq = ntohl(pd->hdr.tcp->th_seq) - 1;
	ack = ntohl(pd->hdr.tcp->th_ack) - 1;
	cookie.cookie = (ack & 0xff) ^ (ack >> 24);

	if (cookie.flags.mss_idx >= nitems(pf_syncookie_msstab) ||
	    cookie.flags.wscale_idx >= nitems(pf_syncookie_wstab))
		return (NULL);

	mss = pf_syncookie_msstab[cookie.flags.mss_idx];
	wscale = pf_syncookie_wstab[cookie.flags.wscale_idx];

	return (pf_build_tcp(NULL, pd->af, pd->src, pd->dst, *pd->sport,
	    *pd->dport, seq, 0, TH_SYN, wscale, mss, ttl, 0,
	    PF_TAG_SYNCOOKIE_RECREATED));
}
