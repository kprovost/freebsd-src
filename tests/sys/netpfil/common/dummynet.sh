# $FreeBSD$
#
# SPDX-License-Identifier: BSD-2-Clause-FreeBSD
#
# Copyright (c) 2021 Rubicon Communications, LLC (Netgate)
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions
# are met:
# 1. Redistributions of source code must retain the above copyright
#    notice, this list of conditions and the following disclaimer.
# 2. Redistributions in binary form must reproduce the above copyright
#    notice, this list of conditions and the following disclaimer in the
#    documentation and/or other materials provided with the distribution.
#
# THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
# ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
# ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
# FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
# DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
# OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
# HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
# LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
# OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
# SUCH DAMAGE.

. $(atf_get_srcdir)/utils.subr
. $(atf_get_srcdir)/runner.subr

pipe_head()
{
	atf_set descr 'Basic pipe test'
	atf_set require.user root
}

pipe_body()
{
	fw=$1
	firewall_init $fw
	dummynet_init $fw

	epair=$(vnet_mkepair)
	vnet_mkjail alcatraz ${epair}b

	ifconfig ${epair}a 192.0.2.1/24 up
	jexec alcatraz ifconfig ${epair}b 192.0.2.2/24 up

	# Sanity check
	atf_check -s exit:0 -o ignore ping -i .1 -c 3 -s 1200 192.0.2.2

	jexec alcatraz dnctl pipe 1 config bw 30Byte/s

	firewall_config alcatraz ${fw} \
		"ipfw"	\
			"ipfw add 1000 pipe 1 ip from any to any" \
		"pf"	\
			"pass in dnpipe 1"

	# single ping succeeds just fine
	atf_check -s exit:0 -o ignore ping -c 1 192.0.2.2

	# Saturate the link
	ping -i .1 -c 5 -s 1200 192.0.2.2

	# We should now be hitting the limits and get this packet dropped.
	atf_check -s exit:2 -o ignore ping -c 1 -s 1200 192.0.2.2
}

pipe_cleanup()
{
	firewall_cleanup $1
}

pipe_v6_head()
{
	atf_set descr 'Basic IPv6 pipe test'
	atf_set require.user root
}

pipe_v6_body()
{
	fw=$1
	firewall_init $fw
	dummynet_init $fw

	epair=$(vnet_mkepair)
	vnet_mkjail alcatraz ${epair}b

	ifconfig ${epair}a inet6 2001:db8:42::1/64 up no_dad
	jexec alcatraz ifconfig ${epair}b inet6 2001:db8:42::2/64 up no_dad

	# Sanity check
	atf_check -s exit:0 -o ignore ping6 -i .1 -c 3 -s 1200 2001:db8:42::2

	jexec alcatraz dnctl pipe 1 config bw 100Byte/s

	firewall_config alcatraz ${fw} \
		"ipfw"	\
			"ipfw add 1000 pipe 1 ip6 from any to any" \
		"pf"	\
			"pass in dnpipe 1"

	# Single ping succeeds
	atf_check -s exit:0 -o ignore ping6 -c 1 2001:db8:42::2

	# Saturate the link
	ping6 -i .1 -c 5 -s 1200 2001:db8:42::2

	# We should now be hitting the limit and get this packet dropped.
	atf_check -s exit:2 -o ignore ping6 -c 1 -s 1200 2001:db8:42::2
}

pipe_v6_cleanup()
{
	firewall_cleanup $1
}

queue_head()
{
	atf_set descr 'Basic queue test'
	atf_set require.user root
}

queue_body()
{
	fw=$1
	firewall_init $fw
	dummynet_init $fw

	epair=$(vnet_mkepair)
	vnet_mkjail alcatraz ${epair}b

	ifconfig ${epair}a 192.0.2.1/24 up
	jexec alcatraz ifconfig ${epair}b 192.0.2.2/24 up
	jexec alcatraz /usr/sbin/inetd -p inetd-alcatraz.pid \
	    $(atf_get_srcdir)/../pf/echo_inetd.conf

	# Sanity check
	atf_check -s exit:0 -o ignore ping -i .1 -c 3 -s 1200 192.0.2.2
	reply=$(echo "foo" | nc -N 192.0.2.2 7)
	if [ "$reply" != "foo" ];
	then
		atf_fail "Echo sanity check failed"
	fi

	jexec alcatraz dnctl pipe 1 config bw 100Byte/s
	jexec alcatraz dnctl sched 1 config pipe 1 type wf2q+
	jexec alcatraz dnctl queue 1 config sched 1 weight 99
	jexec alcatraz dnctl queue 2 config sched 1 weight 1

	firewall_config alcatraz ${fw} \
		"ipfw"	\
			"ipfw add 1000 queue 2 icmp from any to any" \
			"ipfw add 1001 queue 1 tcp from any to any" \
		"pf" \
			"pass proto tcp dnqueue 1"	\
			"pass proto icmp dnqueue 2"

	# Single ping succeeds
	atf_check -s exit:0 -o ignore ping -c 1 192.0.2.2

	# Saturate the link
	ping -i .01 -s 1200 192.0.2.2 &

	# We should now be hitting the limits and get this packet dropped.
	atf_check -s exit:2 -o ignore ping -c 1 -W 1 -s 1200 192.0.2.2

	# TCP should still just pass
	reply=$(echo "foo" | nc -N 192.0.2.2 7)
	if [ "$reply" != "foo" ];
	then
		atf_fail "Failed to prioritise TCP traffic"
	fi

	# This will fail if we don't differentiate the traffic
	firewall_config alcatraz ${fw} \
		"ipfw"	\
			"ipfw add 1000 queue 1 ip from any to any"	\
		"pf"	\
			"pass dnqueue 1"

	reply=$(echo "foo" | nc -N 192.0.2.2 7)
	if [ "$reply" == "foo" ];
	then
		atf_fail "TCP still made it through, even when not prioritised"
	fi

}

queue_cleanup()
{
	rm -f inetd-alcatraz.pid
	firewall_cleanup $1
}

setup_tests		\
	pipe		\
		ipfw	\
		pf	\
	pipe_v6		\
		ipfw	\
		pf	\
	queue		\
		ipfw	\
		pf

