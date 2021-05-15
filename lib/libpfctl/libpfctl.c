/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2021 Rubicon Communications, LLC (Netgate)
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 *    - Redistributions of source code must retain the above copyright
 *      notice, this list of conditions and the following disclaimer.
 *    - Redistributions in binary form must reproduce the above
 *      copyright notice, this list of conditions and the following
 *      disclaimer in the documentation and/or other materials provided
 *      with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 * FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
 * COPYRIGHT HOLDERS OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
 * BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
 * CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN
 * ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 *
 * $FreeBSD$
 */

#include <sys/cdefs.h>

#include <sys/ioctl.h>
#include <sys/nv.h>
#include <sys/queue.h>
#include <sys/types.h>

#include <net/if.h>
#include <net/pfvar.h>
#include <netinet/in.h>

#include <assert.h>
#include <err.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>

#include "libpfctl.h"

static int	_pfctl_clear_states(int , const struct pfctl_kill *,
		    unsigned int *, uint64_t);

static void
pf_nvuint_8_array(const nvlist_t *nvl, const char *name, size_t maxelems,
    u_int8_t *numbers, size_t *nelems)
{
	const uint64_t *tmp;
	size_t elems;

	tmp = nvlist_get_number_array(nvl, name, &elems);
	assert(elems <= maxelems);

	for (size_t i = 0; i < elems; i++)
		numbers[i] = tmp[i];

	if (nelems)
		*nelems = elems;
}

static void
pf_nvuint_16_array(const nvlist_t *nvl, const char *name, size_t maxelems,
    u_int16_t *numbers, size_t *nelems)
{
	const uint64_t *tmp;
	size_t elems;

	tmp = nvlist_get_number_array(nvl, name, &elems);
	assert(elems <= maxelems);

	for (size_t i = 0; i < elems; i++)
		numbers[i] = tmp[i];

	if (nelems)
		*nelems = elems;
}

static void
pf_nvuint_32_array(const nvlist_t *nvl, const char *name, size_t maxelems,
    u_int32_t *numbers, size_t *nelems)
{
	const uint64_t *tmp;
	size_t elems;

	tmp = nvlist_get_number_array(nvl, name, &elems);
	assert(elems <= maxelems);

	for (size_t i = 0; i < elems; i++)
		numbers[i] = tmp[i];

	if (nelems)
		*nelems = elems;
}

static void
pf_nvuint_64_array(const nvlist_t *nvl, const char *name, size_t maxelems,
    u_int64_t *numbers, size_t *nelems)
{
	const uint64_t *tmp;
	size_t elems;

	tmp = nvlist_get_number_array(nvl, name, &elems);
	assert(elems <= maxelems);

	for (size_t i = 0; i < elems; i++)
		numbers[i] = tmp[i];

	if (nelems)
		*nelems = elems;
}

static void
pfctl_nv_add_addr(nvlist_t *nvparent, const char *name,
    const struct pf_addr *addr)
{
	nvlist_t *nvl = nvlist_create(0);

	nvlist_add_binary(nvl, "addr", addr, sizeof(*addr));

	nvlist_add_nvlist(nvparent, name, nvl);
	nvlist_destroy(nvl);
}

static void
pf_nvaddr_to_addr(const nvlist_t *nvl, struct pf_addr *addr)
{
	size_t len;
	const void *data;

	data = nvlist_get_binary(nvl, "addr", &len);
	assert(len == sizeof(struct pf_addr));
	memcpy(addr, data, len);
}

static void
pfctl_nv_add_addr_wrap(nvlist_t *nvparent, const char *name,
    const struct pf_addr_wrap *addr)
{
	nvlist_t *nvl = nvlist_create(0);

	nvlist_add_number(nvl, "type", addr->type);
	nvlist_add_number(nvl, "iflags", addr->iflags);
	if (addr->type == PF_ADDR_DYNIFTL)
		nvlist_add_string(nvl, "ifname", addr->v.ifname);
	if (addr->type == PF_ADDR_TABLE)
		nvlist_add_string(nvl, "tblname", addr->v.tblname);
	pfctl_nv_add_addr(nvl, "addr", &addr->v.a.addr);
	pfctl_nv_add_addr(nvl, "mask", &addr->v.a.mask);

	nvlist_add_nvlist(nvparent, name, nvl);
	nvlist_destroy(nvl);
}

static void
pf_nvaddr_wrap_to_addr_wrap(const nvlist_t *nvl, struct pf_addr_wrap *addr)
{
	addr->type = nvlist_get_number(nvl, "type");
	addr->iflags = nvlist_get_number(nvl, "iflags");
	if (addr->type == PF_ADDR_DYNIFTL)
		strlcpy(addr->v.ifname, nvlist_get_string(nvl, "ifname"),
		    IFNAMSIZ);
	if (addr->type == PF_ADDR_TABLE)
		strlcpy(addr->v.tblname, nvlist_get_string(nvl, "tblname"),
		    PF_TABLE_NAME_SIZE);

	pf_nvaddr_to_addr(nvlist_get_nvlist(nvl, "addr"), &addr->v.a.addr);
	pf_nvaddr_to_addr(nvlist_get_nvlist(nvl, "mask"), &addr->v.a.mask);
}

static void
pfctl_nv_add_rule_addr(nvlist_t *nvparent, const char *name,
    const struct pf_rule_addr *addr)
{
	u_int64_t ports[2];
	nvlist_t *nvl = nvlist_create(0);

	pfctl_nv_add_addr_wrap(nvl, "addr", &addr->addr);
	ports[0] = addr->port[0];
	ports[1] = addr->port[1];
	nvlist_add_number_array(nvl, "port", ports, 2);
	nvlist_add_number(nvl, "neg", addr->neg);
	nvlist_add_number(nvl, "port_op", addr->port_op);

	nvlist_add_nvlist(nvparent, name, nvl);
	nvlist_destroy(nvl);
}

static void
pf_nvrule_addr_to_rule_addr(const nvlist_t *nvl, struct pf_rule_addr *addr)
{
	pf_nvaddr_wrap_to_addr_wrap(nvlist_get_nvlist(nvl, "addr"), &addr->addr);

	pf_nvuint_16_array(nvl, "port", 2, addr->port, NULL);
	addr->neg = nvlist_get_number(nvl, "neg");
	addr->port_op = nvlist_get_number(nvl, "port_op");
}

static void
pfctl_nv_add_mape(nvlist_t *nvparent, const char *name,
    const struct pf_mape_portset *mape)
{
	nvlist_t *nvl = nvlist_create(0);

	nvlist_add_number(nvl, "offset", mape->offset);
	nvlist_add_number(nvl, "psidlen", mape->psidlen);
	nvlist_add_number(nvl, "psid", mape->psid);
	nvlist_add_nvlist(nvparent, name, nvl);
	nvlist_destroy(nvl);
}

static void
pfctl_nv_add_pool(nvlist_t *nvparent, const char *name,
    const struct pfctl_pool *pool)
{
	u_int64_t ports[2];
	nvlist_t *nvl = nvlist_create(0);

	nvlist_add_binary(nvl, "key", &pool->key, sizeof(pool->key));
	pfctl_nv_add_addr(nvl, "counter", &pool->counter);
	nvlist_add_number(nvl, "tblidx", pool->tblidx);

	ports[0] = pool->proxy_port[0];
	ports[1] = pool->proxy_port[1];
	nvlist_add_number_array(nvl, "proxy_port", ports, 2);
	nvlist_add_number(nvl, "opts", pool->opts);
	pfctl_nv_add_mape(nvl, "mape", &pool->mape);

	nvlist_add_nvlist(nvparent, name, nvl);
	nvlist_destroy(nvl);
}

static void
pf_nvmape_to_mape(const nvlist_t *nvl, struct pf_mape_portset *mape)
{
	mape->offset = nvlist_get_number(nvl, "offset");
	mape->psidlen = nvlist_get_number(nvl, "psidlen");
	mape->psid = nvlist_get_number(nvl, "psid");
}

static void
pf_nvpool_to_pool(const nvlist_t *nvl, struct pfctl_pool *pool)
{
	size_t len;
	const void *data;

	data = nvlist_get_binary(nvl, "key", &len);
	assert(len == sizeof(pool->key));
	memcpy(&pool->key, data, len);

	pf_nvaddr_to_addr(nvlist_get_nvlist(nvl, "counter"), &pool->counter);

	pool->tblidx = nvlist_get_number(nvl, "tblidx");
	pf_nvuint_16_array(nvl, "proxy_port", 2, pool->proxy_port, NULL);
	pool->opts = nvlist_get_number(nvl, "opts");

	if (nvlist_exists_nvlist(nvl, "mape"))
		pf_nvmape_to_mape(nvlist_get_nvlist(nvl, "mape"), &pool->mape);
}

static void
pfctl_nv_add_uid(nvlist_t *nvparent, const char *name,
    const struct pf_rule_uid *uid)
{
	u_int64_t uids[2];
	nvlist_t *nvl = nvlist_create(0);

	uids[0] = uid->uid[0];
	uids[1] = uid->uid[1];
	nvlist_add_number_array(nvl, "uid", uids, 2);
	nvlist_add_number(nvl, "op", uid->op);

	nvlist_add_nvlist(nvparent, name, nvl);
	nvlist_destroy(nvl);
}

static void
pf_nvrule_uid_to_rule_uid(const nvlist_t *nvl, struct pf_rule_uid *uid)
{
	pf_nvuint_32_array(nvl, "uid", 2, uid->uid, NULL);
	uid->op = nvlist_get_number(nvl, "op");
}

static void
pfctl_nv_add_divert(nvlist_t *nvparent, const char *name,
    const struct pfctl_rule *r)
{
	nvlist_t *nvl = nvlist_create(0);

	pfctl_nv_add_addr(nvl, "addr", &r->divert.addr);
	nvlist_add_number(nvl, "port", r->divert.port);

	nvlist_add_nvlist(nvparent, name, nvl);
	nvlist_destroy(nvl);
}

static void
pf_nvdivert_to_divert(const nvlist_t *nvl, struct pfctl_rule *rule)
{
	pf_nvaddr_to_addr(nvlist_get_nvlist(nvl, "addr"), &rule->divert.addr);
	rule->divert.port = nvlist_get_number(nvl, "port");
}

static void
pf_nvrule_to_rule(const nvlist_t *nvl, struct pfctl_rule *rule)
{
	const uint64_t *skip;
	const char *const *labels;
	size_t skipcount, labelcount;

	rule->nr = nvlist_get_number(nvl, "nr");

	pf_nvrule_addr_to_rule_addr(nvlist_get_nvlist(nvl, "src"), &rule->src);
	pf_nvrule_addr_to_rule_addr(nvlist_get_nvlist(nvl, "dst"), &rule->dst);

	skip = nvlist_get_number_array(nvl, "skip", &skipcount);
	assert(skip);
	assert(skipcount == PF_SKIP_COUNT);
	for (int i = 0; i < PF_SKIP_COUNT; i++)
		rule->skip[i].nr = skip[i];

	labels = nvlist_get_string_array(nvl, "labels", &labelcount);
	assert(labelcount <= PF_RULE_MAX_LABEL_COUNT);
	for (size_t i = 0; i < labelcount; i++)
		strlcpy(rule->label[i], labels[i], PF_RULE_LABEL_SIZE);
	strlcpy(rule->ifname, nvlist_get_string(nvl, "ifname"), IFNAMSIZ);
	strlcpy(rule->qname, nvlist_get_string(nvl, "qname"), PF_QNAME_SIZE);
	strlcpy(rule->pqname, nvlist_get_string(nvl, "pqname"), PF_QNAME_SIZE);
	strlcpy(rule->tagname, nvlist_get_string(nvl, "tagname"),
	    PF_TAG_NAME_SIZE);
	strlcpy(rule->match_tagname, nvlist_get_string(nvl, "match_tagname"),
	    PF_TAG_NAME_SIZE);

	strlcpy(rule->overload_tblname, nvlist_get_string(nvl, "overload_tblname"),
	    PF_TABLE_NAME_SIZE);

	pf_nvpool_to_pool(nvlist_get_nvlist(nvl, "rpool"), &rule->rpool);

	rule->evaluations = nvlist_get_number(nvl, "evaluations");
	pf_nvuint_64_array(nvl, "packets", 2, rule->packets, NULL);
	pf_nvuint_64_array(nvl, "bytes", 2, rule->bytes, NULL);

	rule->os_fingerprint = nvlist_get_number(nvl, "os_fingerprint");

	rule->rtableid = nvlist_get_number(nvl, "rtableid");
	pf_nvuint_32_array(nvl, "timeout", PFTM_MAX, rule->timeout, NULL);
	rule->max_states = nvlist_get_number(nvl, "max_states");
	rule->max_src_nodes = nvlist_get_number(nvl, "max_src_nodes");
	rule->max_src_states = nvlist_get_number(nvl, "max_src_states");
	rule->max_src_conn = nvlist_get_number(nvl, "max_src_conn");
	rule->max_src_conn_rate.limit =
	    nvlist_get_number(nvl, "max_src_conn_rate.limit");
	rule->max_src_conn_rate.seconds =
	    nvlist_get_number(nvl, "max_src_conn_rate.seconds");
	rule->qid = nvlist_get_number(nvl, "qid");
	rule->pqid = nvlist_get_number(nvl, "pqid");
	rule->dnpipe = nvlist_get_number(nvl, "dnpipe");
	rule->pdnpipe = nvlist_get_number(nvl, "pdnpipe");
	rule->free_flags = nvlist_get_number(nvl, "dnflags");
	rule->prob = nvlist_get_number(nvl, "prob");
	rule->cuid = nvlist_get_number(nvl, "cuid");
	rule->cpid = nvlist_get_number(nvl, "cpid");

	rule->return_icmp = nvlist_get_number(nvl, "return_icmp");
	rule->return_icmp6 = nvlist_get_number(nvl, "return_icmp6");
	rule->max_mss = nvlist_get_number(nvl, "max_mss");
	rule->scrub_flags = nvlist_get_number(nvl, "scrub_flags");

	pf_nvrule_uid_to_rule_uid(nvlist_get_nvlist(nvl, "uid"), &rule->uid);
	pf_nvrule_uid_to_rule_uid(nvlist_get_nvlist(nvl, "gid"),
	    (struct pf_rule_uid *)&rule->gid);

	rule->rule_flag = nvlist_get_number(nvl, "rule_flag");
	rule->action = nvlist_get_number(nvl, "action");
	rule->direction = nvlist_get_number(nvl, "direction");
	rule->log = nvlist_get_number(nvl, "log");
	rule->logif = nvlist_get_number(nvl, "logif");
	rule->quick = nvlist_get_number(nvl, "quick");
	rule->ifnot = nvlist_get_number(nvl, "ifnot");
	rule->match_tag_not = nvlist_get_number(nvl, "match_tag_not");
	rule->natpass = nvlist_get_number(nvl, "natpass");

	rule->keep_state = nvlist_get_number(nvl, "keep_state");
	rule->af = nvlist_get_number(nvl, "af");
	rule->proto = nvlist_get_number(nvl, "proto");
	rule->type = nvlist_get_number(nvl, "type");
	rule->code = nvlist_get_number(nvl, "code");
	rule->flags = nvlist_get_number(nvl, "flags");
	rule->flagset = nvlist_get_number(nvl, "flagset");
	rule->min_ttl = nvlist_get_number(nvl, "min_ttl");
	rule->allow_opts = nvlist_get_number(nvl, "allow_opts");
	rule->rt = nvlist_get_number(nvl, "rt");
	rule->return_ttl  = nvlist_get_number(nvl, "return_ttl");
	rule->tos = nvlist_get_number(nvl, "tos");
	rule->set_tos = nvlist_get_number(nvl, "set_tos");
	rule->anchor_relative = nvlist_get_number(nvl, "anchor_relative");
	rule->anchor_wildcard = nvlist_get_number(nvl, "anchor_wildcard");

	rule->flush = nvlist_get_number(nvl, "flush");
	rule->prio = nvlist_get_number(nvl, "prio");
	pf_nvuint_8_array(nvl, "set_prio", 2, rule->set_prio, NULL);

	pf_nvdivert_to_divert(nvlist_get_nvlist(nvl, "divert"), rule);

	rule->states_cur = nvlist_get_number(nvl, "states_cur");
	rule->states_tot = nvlist_get_number(nvl, "states_tot");
	rule->src_nodes = nvlist_get_number(nvl, "src_nodes");
}

int
pfctl_add_rule(int dev, const struct pfctl_rule *r, const char *anchor,
    const char *anchor_call, u_int32_t ticket, u_int32_t pool_ticket)
{
	struct pfioc_nv nv;
	u_int64_t timeouts[PFTM_MAX];
	u_int64_t set_prio[2];
	nvlist_t *nvl, *nvlr;
	size_t labelcount;
	int ret;

	nvl = nvlist_create(0);
	nvlr = nvlist_create(0);

	nvlist_add_number(nvl, "ticket", ticket);
	nvlist_add_number(nvl, "pool_ticket", pool_ticket);
	nvlist_add_string(nvl, "anchor", anchor);
	nvlist_add_string(nvl, "anchor_call", anchor_call);

	nvlist_add_number(nvlr, "nr", r->nr);
	pfctl_nv_add_rule_addr(nvlr, "src", &r->src);
	pfctl_nv_add_rule_addr(nvlr, "dst", &r->dst);

	labelcount = 0;
	while (r->label[labelcount][0] != 0 &&
	    labelcount < PF_RULE_MAX_LABEL_COUNT) {
		nvlist_append_string_array(nvlr, "labels",
		    r->label[labelcount]);
		labelcount++;
	}

	nvlist_add_string(nvlr, "ifname", r->ifname);
	nvlist_add_string(nvlr, "qname", r->qname);
	nvlist_add_string(nvlr, "pqname", r->pqname);
	nvlist_add_string(nvlr, "tagname", r->tagname);
	nvlist_add_string(nvlr, "match_tagname", r->match_tagname);
	nvlist_add_string(nvlr, "overload_tblname", r->overload_tblname);

	pfctl_nv_add_pool(nvlr, "rpool", &r->rpool);

	nvlist_add_number(nvlr, "os_fingerprint", r->os_fingerprint);

	nvlist_add_number(nvlr, "rtableid", r->rtableid);
	for (int i = 0; i < PFTM_MAX; i++)
		timeouts[i] = r->timeout[i];
	nvlist_add_number_array(nvlr, "timeout", timeouts, PFTM_MAX);
	nvlist_add_number(nvlr, "max_states", r->max_states);
	nvlist_add_number(nvlr, "max_src_nodes", r->max_src_nodes);
	nvlist_add_number(nvlr, "max_src_states", r->max_src_states);
	nvlist_add_number(nvlr, "max_src_conn", r->max_src_conn);
	nvlist_add_number(nvlr, "max_src_conn_rate.limit",
	    r->max_src_conn_rate.limit);
	nvlist_add_number(nvlr, "max_src_conn_rate.seconds",
	    r->max_src_conn_rate.seconds);
	nvlist_add_number(nvlr, "dnpipe", r->dnpipe);
	nvlist_add_number(nvlr, "pdnpipe", r->pdnpipe);
	nvlist_add_number(nvlr, "dnflags", r->free_flags);
	nvlist_add_number(nvlr, "prob", r->prob);
	nvlist_add_number(nvlr, "cuid", r->cuid);
	nvlist_add_number(nvlr, "cpid", r->cpid);

	nvlist_add_number(nvlr, "return_icmp", r->return_icmp);
	nvlist_add_number(nvlr, "return_icmp6", r->return_icmp6);

	nvlist_add_number(nvlr, "max_mss", r->max_mss);
	nvlist_add_number(nvlr, "scrub_flags", r->scrub_flags);

	pfctl_nv_add_uid(nvlr, "uid", &r->uid);
	pfctl_nv_add_uid(nvlr, "gid", (const struct pf_rule_uid *)&r->gid);

	nvlist_add_number(nvlr, "rule_flag", r->rule_flag);
	nvlist_add_number(nvlr, "action", r->action);
	nvlist_add_number(nvlr, "direction", r->direction);
	nvlist_add_number(nvlr, "log", r->log);
	nvlist_add_number(nvlr, "logif", r->logif);
	nvlist_add_number(nvlr, "quick", r->quick);
	nvlist_add_number(nvlr, "ifnot", r->ifnot);
	nvlist_add_number(nvlr, "match_tag_not", r->match_tag_not);
	nvlist_add_number(nvlr, "natpass", r->natpass);

	nvlist_add_number(nvlr, "keep_state", r->keep_state);
	nvlist_add_number(nvlr, "af", r->af);
	nvlist_add_number(nvlr, "proto", r->proto);
	nvlist_add_number(nvlr, "type", r->type);
	nvlist_add_number(nvlr, "code", r->code);
	nvlist_add_number(nvlr, "flags", r->flags);
	nvlist_add_number(nvlr, "flagset", r->flagset);
	nvlist_add_number(nvlr, "min_ttl", r->min_ttl);
	nvlist_add_number(nvlr, "allow_opts", r->allow_opts);
	nvlist_add_number(nvlr, "rt", r->rt);
	nvlist_add_number(nvlr, "return_ttl", r->return_ttl);
	nvlist_add_number(nvlr, "tos", r->tos);
	nvlist_add_number(nvlr, "set_tos", r->set_tos);
	nvlist_add_number(nvlr, "anchor_relative", r->anchor_relative);
	nvlist_add_number(nvlr, "anchor_wildcard", r->anchor_wildcard);

	nvlist_add_number(nvlr, "flush", r->flush);

	nvlist_add_number(nvlr, "prio", r->prio);
	set_prio[0] = r->set_prio[0];
	set_prio[1] = r->set_prio[1];
	nvlist_add_number_array(nvlr, "set_prio", set_prio, 2);

	pfctl_nv_add_divert(nvlr, "divert", r);

	nvlist_add_nvlist(nvl, "rule", nvlr);
	nvlist_destroy(nvlr);

	/* Now do the call. */
	nv.data = nvlist_pack(nvl, &nv.len);
	nv.size = nv.len;

	ret = ioctl(dev, DIOCADDRULENV, &nv);

	free(nv.data);
	nvlist_destroy(nvl);

	return (ret);
}

int
pfctl_get_rule(int dev, u_int32_t nr, u_int32_t ticket, const char *anchor,
    u_int32_t ruleset, struct pfctl_rule *rule, char *anchor_call)
{
	return (pfctl_get_clear_rule(dev, nr, ticket, anchor, ruleset, rule,
	    anchor_call, false));
}

int	pfctl_get_clear_rule(int dev, u_int32_t nr, u_int32_t ticket,
	    const char *anchor, u_int32_t ruleset, struct pfctl_rule *rule,
	    char *anchor_call, bool clear)
{
	struct pfioc_nv nv;
	nvlist_t *nvl;
	void *nvlpacked;
	int ret;

	nvl = nvlist_create(0);
	if (nvl == 0)
		return (ENOMEM);

	nvlist_add_number(nvl, "nr", nr);
	nvlist_add_number(nvl, "ticket", ticket);
	nvlist_add_string(nvl, "anchor", anchor);
	nvlist_add_number(nvl, "ruleset", ruleset);

	if (clear)
		nvlist_add_bool(nvl, "clear_counter", true);

	nvlpacked = nvlist_pack(nvl, &nv.len);
	if (nvlpacked == NULL) {
		nvlist_destroy(nvl);
		return (ENOMEM);
	}
	nv.data = malloc(8182);
	nv.size = 8192;
	assert(nv.len <= nv.size);
	memcpy(nv.data, nvlpacked, nv.len);
	nvlist_destroy(nvl);
	nvl = NULL;
	free(nvlpacked);

	ret = ioctl(dev, DIOCGETRULENV, &nv);
	if (ret != 0) {
		free(nv.data);
		return (ret);
	}

	nvl = nvlist_unpack(nv.data, nv.len, 0);
	if (nvl == NULL) {
		free(nv.data);
		return (EIO);
	}

	pf_nvrule_to_rule(nvlist_get_nvlist(nvl, "rule"), rule);

	if (anchor_call)
		strlcpy(anchor_call, nvlist_get_string(nvl, "anchor_call"),
		    MAXPATHLEN);

	free(nv.data);
	nvlist_destroy(nvl);

	return (0);
}

int
pfctl_set_keepcounters(int dev, bool keep)
{
	struct pfioc_nv	 nv;
	nvlist_t	*nvl;
	int		 ret;

	nvl = nvlist_create(0);

	nvlist_add_bool(nvl, "keep_counters", keep);

	nv.data = nvlist_pack(nvl, &nv.len);
	nv.size = nv.len;

	nvlist_destroy(nvl);

	ret = ioctl(dev, DIOCKEEPCOUNTERS, &nv);

	free(nv.data);
	return (ret);
}

static void
pfctl_nv_add_state_cmp(nvlist_t *nvl, const char *name,
    const struct pfctl_state_cmp *cmp)
{
	nvlist_t	*nv;

	nv = nvlist_create(0);

	nvlist_add_number(nv, "id", cmp->id);
	nvlist_add_number(nv, "creatorid", cmp->creatorid);
	nvlist_add_number(nv, "direction", cmp->direction);

	nvlist_add_nvlist(nvl, name, nv);
	nvlist_destroy(nv);
}

static void
pf_nvstate_scrub_to_state_scrub(const nvlist_t *nvl,
    struct pfctl_state_scrub *scrub)
{
	bzero(scrub, sizeof(*scrub));

	scrub->timestamp = nvlist_get_bool(nvl, "timestamp");
	scrub->ttl = nvlist_get_number(nvl, "ttl");
	scrub->ts_mod = nvlist_get_number(nvl, "ts_mod");
}

static void
pf_nvstate_peer_to_state_peer(const nvlist_t *nvl,
    struct pfctl_state_peer *peer)
{
	bzero(peer, sizeof(*peer));

	if (nvlist_exists_nvlist(nvl, "scrub")) {
		peer->scrub = malloc(sizeof(*peer->scrub));
		pf_nvstate_scrub_to_state_scrub(
		    nvlist_get_nvlist(nvl, "scrub"),
		    peer->scrub);
	}

	peer->seqlo = nvlist_get_number(nvl, "seqlo");
	peer->seqhi = nvlist_get_number(nvl, "seqhi");
	peer->seqdiff = nvlist_get_number(nvl, "seqdiff");
	peer->max_win = nvlist_get_number(nvl, "max_win");
	peer->mss = nvlist_get_number(nvl, "mss");
	peer->state = nvlist_get_number(nvl, "state");
	peer->wscale = nvlist_get_number(nvl, "wscale");
}

static void
pf_nvstate_key_to_state_key(const nvlist_t *nvl, struct pfctl_state_key *key)
{
	const nvlist_t * const *tmp;
	size_t count;

	bzero(key, sizeof(*key));

	tmp = nvlist_get_nvlist_array(nvl, "addr", &count);
	assert(count == 2);

	for (int i = 0; i < 2; i++)
		pf_nvaddr_to_addr(tmp[i], &key->addr[i]);

	pf_nvuint_16_array(nvl, "port", 2, key->port, NULL);

	key->af = nvlist_get_number(nvl, "af");
	key->proto = nvlist_get_number(nvl, "proto");
}

static void
pf_nvstate_to_state(const nvlist_t *nvl, struct pfctl_state *s)
{
	bzero(s, sizeof(*s));

	s->id = nvlist_get_number(nvl, "id");
	s->creatorid = nvlist_get_number(nvl, "creatorid");
	s->direction = nvlist_get_number(nvl, "direction");

	pf_nvstate_peer_to_state_peer(nvlist_get_nvlist(nvl, "src"), &s->src);
	pf_nvstate_peer_to_state_peer(nvlist_get_nvlist(nvl, "dst"), &s->dst);

	pf_nvstate_key_to_state_key(nvlist_get_nvlist(nvl, "stack_key"),
	    &s->key[0]);
	pf_nvstate_key_to_state_key(nvlist_get_nvlist(nvl, "wire_key"),
	    &s->key[1]);

	strlcpy(s->ifname, nvlist_get_string(nvl, "ifname"),
	    sizeof(s->ifname));
	strlcpy(s->orig_ifname, nvlist_get_string(nvl, "orig_ifname"),
	    sizeof(s->orig_ifname));

	pf_nvaddr_to_addr(nvlist_get_nvlist(nvl, "rt_addr"), &s->rt_addr);
	s->rule = nvlist_get_number(nvl, "rule");
	s->anchor = nvlist_get_number(nvl, "anchor");
	s->nat_rule = nvlist_get_number(nvl, "nat_rule");
	s->creation = nvlist_get_number(nvl, "creation");
	s->expire = nvlist_get_number(nvl, "expire");

	pf_nvuint_64_array(nvl, "packets", 2, s->packets, NULL);
	pf_nvuint_64_array(nvl, "bytes", 2, s->bytes, NULL);

	s->log = nvlist_get_number(nvl, "log");
	s->state_flags = nvlist_get_number(nvl, "state_flags");
	s->timeout = nvlist_get_number(nvl, "timeout");
	s->sync_flags = nvlist_get_number(nvl, "sync_flags");
}

int
pfctl_get_states(int dev, struct pfctl_states *states)
{
	struct pfioc_nv		 nv;
	nvlist_t		*nvl = NULL;
	const nvlist_t * const	*slist;
	size_t			 found_count;
	int			 error = 0;

	bzero(states, sizeof(*states));
	TAILQ_INIT(&states->states);

	/* Just enough to get a number, and we'll grow from there. */
	nv.data = malloc(64);
	nv.len = nv.size = 64;

	for (;;) {
		if (ioctl(dev, DIOCGETSTATESNV, &nv)) {
			error = errno;
			goto out;
		}

		nvl = nvlist_unpack(nv.data, nv.len, 0);
		if (nvl == NULL) {
			error = EIO;
			goto out;
		}

		states->count = nvlist_get_number(nvl, "count");

		/* Are there any states? */
		if (states->count == 0)
			break;

		if (nvlist_exists_nvlist_array(nvl, "states"))
			slist = nvlist_get_nvlist_array(nvl, "states", &found_count);
		else
			found_count = 0;

		if (found_count < states->count) {
			size_t new_size = nv.size +
			    (nv.size * states->count / (found_count + 1) * 2);

			/* Our buffer is too small. Estimate what we need based
			 * on how many states fit in the previous allocation
			 * and how many states there are. Doubled for margin.
			 * */
			nv.data = realloc(nv.data, new_size);
			nv.size = new_size;

			if (nv.data == NULL) {
				error = ENOMEM;
				goto out;
			}
			continue;
		}

		for (size_t i = 0; i < found_count; i++) {
			struct pfctl_state *s = malloc(sizeof(*s));
			if (s == NULL) {
				pfctl_free_states(states);
				error = ENOMEM;
				goto out;
			}

			pf_nvstate_to_state(slist[i], s);
			TAILQ_INSERT_TAIL(&states->states, s, entry);
		}
		break;
	}

out:
	nvlist_destroy(nvl);
	free(nv.data);

	return (error);
}

void
pfctl_free_states(struct pfctl_states *states)
{
	struct pfctl_state *s, *tmp;

	TAILQ_FOREACH_SAFE(s, &states->states, entry, tmp) {
		free(s);
	}

	bzero(states, sizeof(*states));
}

static int
_pfctl_clear_states(int dev, const struct pfctl_kill *kill,
    unsigned int *killed, uint64_t ioctlval)
{
	struct pfioc_nv	 nv;
	nvlist_t	*nvl;
	int		 ret;

	nvl = nvlist_create(0);

	pfctl_nv_add_state_cmp(nvl, "cmp", &kill->cmp);
	nvlist_add_number(nvl, "af", kill->af);
	nvlist_add_number(nvl, "proto", kill->proto);
	pfctl_nv_add_rule_addr(nvl, "src", &kill->src);
	pfctl_nv_add_rule_addr(nvl, "dst", &kill->dst);
	pfctl_nv_add_rule_addr(nvl, "rt_addr", &kill->rt_addr);
	nvlist_add_string(nvl, "ifname", kill->ifname);
	nvlist_add_string(nvl, "label", kill->label);
	nvlist_add_bool(nvl, "kill_match", kill->kill_match);

	nv.data = nvlist_pack(nvl, &nv.len);
	nv.size = nv.len;
	nvlist_destroy(nvl);
	nvl = NULL;

	ret = ioctl(dev, ioctlval, &nv);
	if (ret != 0) {
		free(nv.data);
		return (ret);
	}

	nvl = nvlist_unpack(nv.data, nv.len, 0);
	if (nvl == NULL) {
		free(nv.data);
		return (EIO);
	}

	if (killed)
		*killed = nvlist_get_number(nvl, "killed");

	nvlist_destroy(nvl);
	free(nv.data);

	return (ret);
}

int
pfctl_clear_states(int dev, const struct pfctl_kill *kill,
    unsigned int *killed)
{
	return (_pfctl_clear_states(dev, kill, killed, DIOCCLRSTATESNV));
}

int
pfctl_kill_states(int dev, const struct pfctl_kill *kill, unsigned int *killed)
{
	return (_pfctl_clear_states(dev, kill, killed, DIOCKILLSTATESNV));
}
