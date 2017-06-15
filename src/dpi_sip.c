#include <net/netfilter/nf_conntrack_helper.h>

#include <linux/inet.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/tcp.h>
#include <linux/ctype.h>
#include <linux/skbuff.h>

#include "dpi_sip.h"

/* Время жизни callid по умолчанию в секундах */
#define DEFAULT_EXPIRES_VALUE 3600


#define SIP_RESPONSE_OK             200
#define SIP_RESPONSE_UNAUTHORIZED   401

struct extsip_handler {
	const char	*method;
	unsigned int	len;
	int		(*request)(struct sk_buff *skb, unsigned int protoff,
				   unsigned int dataoff,
				   const char **dptr, unsigned int *datalen,
                                   struct extsip_callinfo *callinfo,
				   unsigned int cseq);
	int		(*response)(struct sk_buff *skb, unsigned int protoff,
				    unsigned int dataoff,
				    const char **dptr, unsigned int *datalen,
                                    struct extsip_callinfo *callinfo,
				    unsigned int cseq, unsigned int code);
};

#define EXTSIP_HANDLER(__method, __request, __response)			\
{									\
	.method		= (__method),					\
	.len		= sizeof(__method) - 1,				\
	.request	= (__request),					\
	.response	= (__response),					\
}


struct sip_header {
	const char	*name;
	const char	*cname;
	const char	*search;
	unsigned int	len;
	unsigned int	clen;
	unsigned int	slen;
	int		(*match_len)(const struct nf_conn *ct,
				     const char *dptr, const char *limit,
				     int *shift);
};

#define __SIP_HDR(__name, __cname, __search, __match)			\
{									\
	.name		= (__name),					\
	.len		= sizeof(__name) - 1,				\
	.cname		= (__cname),					\
	.clen		= (__cname) ? sizeof(__cname) - 1 : 0,		\
	.search		= (__search),					\
	.slen		= (__search) ? sizeof(__search) - 1 : 0,	\
	.match_len	= (__match),					\
}

#define SIP_HDR(__name, __cname, __search, __match) \
	__SIP_HDR(__name, __cname, __search, __match)

#define SDP_HDR(__name, __search, __match) \
	__SIP_HDR(__name, NULL, __search, __match)

enum sip_header_types {
	SIP_HDR_CSEQ,
	SIP_HDR_FROM,
	SIP_HDR_TO,
	SIP_HDR_CONTACT,
	SIP_HDR_VIA_UDP,
	SIP_HDR_VIA_TCP,
	SIP_HDR_EXPIRES,
	SIP_HDR_CONTENT_LENGTH,
	SIP_HDR_CALL_ID,
};

enum sdp_header_types {
	SDP_HDR_UNSPEC,
	SDP_HDR_VERSION,
	SDP_HDR_OWNER,
	SDP_HDR_CONNECTION,
	SDP_HDR_MEDIA,
};




/* Forward local function declarations */
static int process_sip_msg(struct sk_buff *skb, struct nf_conn *ct,
			   unsigned int protoff, unsigned int dataoff,
			   const char **dptr, unsigned int *datalen);
static int process_sip_request(struct sk_buff *skb, unsigned int protoff,
			       unsigned int dataoff,
			       const char **dptr, unsigned int *datalen,
                               struct extsip_callinfo *callinfo);
static int process_sip_response(struct sk_buff *skb, unsigned int protoff,
				unsigned int dataoff,
				const char **dptr, unsigned int *datalen,
                                struct extsip_callinfo *callinfo);
static int process_invite_request(struct sk_buff *skb, unsigned int protoff,
				  unsigned int dataoff,
				  const char **dptr, unsigned int *datalen,
                                  struct extsip_callinfo *callinfo,
				  unsigned int cseq);
static int process_invite_response(struct sk_buff *skb, unsigned int protoff,
				   unsigned int dataoff,
				   const char **dptr, unsigned int *datalen,
                                   struct extsip_callinfo *callinfo,
				   unsigned int cseq, unsigned int code);
static int process_update_response(struct sk_buff *skb, unsigned int protoff,
				   unsigned int dataoff,
				   const char **dptr, unsigned int *datalen,
                                   struct extsip_callinfo *callinfo,
				   unsigned int cseq, unsigned int code);
static int process_sdp(struct sk_buff *skb, unsigned int protoff,
		       unsigned int dataoff,
		       const char **dptr, unsigned int *datalen,
                       struct extsip_callinfo *callinfo,
		       unsigned int cseq);
static int process_prack_response(struct sk_buff *skb, unsigned int protoff,
				  unsigned int dataoff,
				  const char **dptr, unsigned int *datalen,
                                  struct extsip_callinfo *callinfo,
				  unsigned int cseq, unsigned int code);
static int process_bye_request(struct sk_buff *skb, unsigned int protoff,
			       unsigned int dataoff,
			       const char **dptr, unsigned int *datalen,
                               struct extsip_callinfo *callinfo,
			       unsigned int cseq);
static int process_register_request(struct sk_buff *skb, unsigned int protoff,
				    unsigned int dataoff,
				    const char **dptr, unsigned int *datalen,
                                    struct extsip_callinfo *ci,
				    unsigned int cseq);
static int process_register_response(struct sk_buff *skb, unsigned int protoff,
				     unsigned int dataoff,
				     const char **dptr, unsigned int *datalen,
                                     struct extsip_callinfo *ci,
				     unsigned int cseq, unsigned int code);

static int ct_sip_parse_header_uri(const struct nf_conn *ct, const char *dptr,
			    unsigned int *dataoff, unsigned int datalen,
			    enum sip_header_types type, int *in_header,
			    unsigned int *matchoff, unsigned int *matchlen,
			    union nf_inet_addr *addr, __be16 *port);
static int ct_sip_walk_headers(const struct nf_conn *ct, const char *dptr,
			       unsigned int dataoff, unsigned int datalen,
			       enum sip_header_types type, int *in_header,
			       unsigned int *matchoff, unsigned int *matchlen);
static int ct_sip_next_header(const struct nf_conn *ct, const char *dptr,
			      unsigned int dataoff, unsigned int datalen,
			      enum sip_header_types type,
			      unsigned int *matchoff, unsigned int *matchlen);

static void update_callid_lifetime(struct extsip_callinfo *ci,
                                   const struct nf_conn *ct, 
                                   const char *dptr,
                                   unsigned int datalen,
                                   const char *reason);
static int ct_sip_get_expires(const struct nf_conn *ct, 
                              const char *dptr,
                              unsigned int datalen);

static int ct_sip_get_header(const struct nf_conn *ct, const char *dptr,
		      unsigned int dataoff, unsigned int datalen,
		      enum sip_header_types type,
		      unsigned int *matchoff, unsigned int *matchlen);
static const char *sip_skip_whitespace(const char *dptr, const char *limit);
static const char *ct_sip_header_search(const char *dptr, const char *limit,
					const char *needle, unsigned int len);
static const char *sip_follow_continuation(const char *dptr, const char *limit);


static int skp_epaddr_len(const struct nf_conn *ct, const char *dptr,
			  const char *limit, int *shift);
static int epaddr_len(const struct nf_conn *ct, const char *dptr,
		      const char *limit, int *shift);
static int sip_parse_addr(const struct nf_conn *ct, const char *cp,
			  const char **endp, union nf_inet_addr *addr,
			  const char *limit, bool delim);
static int callid_len(const struct nf_conn *ct, const char *dptr,
		      const char *limit, int *shift);

static int word_len(const char *dptr, const char *limit);
static int digits_len(const struct nf_conn *ct, const char *dptr,
		      const char *limit, int *shift);
static int iswordc(const char c);


static const struct extsip_handler sip_handlers[] = {
	EXTSIP_HANDLER("INVITE", process_invite_request, process_invite_response),
	EXTSIP_HANDLER("UPDATE", process_sdp, process_update_response),
	EXTSIP_HANDLER("ACK", process_sdp, NULL),
	EXTSIP_HANDLER("PRACK", process_sdp, process_prack_response),
	EXTSIP_HANDLER("BYE", process_bye_request, NULL),
	EXTSIP_HANDLER("REGISTER", process_register_request, process_register_response),
};

static const struct sip_header ct_sip_hdrs[] = {
	[SIP_HDR_CSEQ]			= SIP_HDR("CSeq", NULL, NULL, digits_len),
	[SIP_HDR_FROM]			= SIP_HDR("From", "f", "sip:", skp_epaddr_len),
	[SIP_HDR_TO]			= SIP_HDR("To", "t", "sip:", skp_epaddr_len),
	[SIP_HDR_CONTACT]		= SIP_HDR("Contact", "m", "sip:", skp_epaddr_len),
	[SIP_HDR_VIA_UDP]		= SIP_HDR("Via", "v", "UDP ", epaddr_len),
	[SIP_HDR_VIA_TCP]		= SIP_HDR("Via", "v", "TCP ", epaddr_len),
	[SIP_HDR_EXPIRES]		= SIP_HDR("Expires", NULL, NULL, digits_len),
	[SIP_HDR_CONTENT_LENGTH]	= SIP_HDR("Content-Length", "l", NULL, digits_len),
	[SIP_HDR_CALL_ID]		= SIP_HDR("Call-Id", "i", NULL, callid_len),
};



int extsip_help_udp(struct sk_buff *skb, unsigned int protoff,
                    struct nf_conn *ct, enum ip_conntrack_info ctinfo) {
	unsigned int dataoff, datalen;
	const char *dptr;

	/* No Data ? */
	dataoff = protoff + sizeof(struct udphdr);
	if (dataoff >= skb->len)
		return NF_ACCEPT;

	nf_ct_refresh(ct, skb, sip_timeout * HZ);

	if (unlikely(skb_linearize(skb)))
		return NF_DROP;

	dptr = skb->data + dataoff;
	datalen = skb->len - dataoff;
	if (datalen < strlen("SIP/2.0 200"))
		return NF_ACCEPT;

	return process_sip_msg(skb, ct, protoff, dataoff, &dptr, &datalen);
}


int extsip_help_tcp(struct sk_buff *skb, unsigned int protoff,
		    struct nf_conn *ct, enum ip_conntrack_info ctinfo) {
	struct tcphdr *th, _tcph;
	unsigned int dataoff, datalen;
	unsigned int matchoff, matchlen, clen;
	unsigned int msglen, origlen;
	const char *dptr, *end;
	s16 diff, tdiff = 0;
	int ret = NF_ACCEPT;
	bool term;

	if (ctinfo != IP_CT_ESTABLISHED &&
	    ctinfo != IP_CT_ESTABLISHED_REPLY)
		return NF_ACCEPT;

	/* No Data ? */
	th = skb_header_pointer(skb, protoff, sizeof(_tcph), &_tcph);
	if (th == NULL)
		return NF_ACCEPT;
	dataoff = protoff + th->doff * 4;
	if (dataoff >= skb->len)
		return NF_ACCEPT;

	nf_ct_refresh(ct, skb, sip_timeout * HZ);

	if (unlikely(skb_linearize(skb)))
		return NF_DROP;

	dptr = skb->data + dataoff;
	datalen = skb->len - dataoff;
	if (datalen < strlen("SIP/2.0 200"))
		return NF_ACCEPT;

	while (1) {
		if (ct_sip_get_header(ct, dptr, 0, datalen,
				      SIP_HDR_CONTENT_LENGTH,
				      &matchoff, &matchlen) <= 0)
			break;

		clen = simple_strtoul(dptr + matchoff, (char **)&end, 10);
		if (dptr + matchoff == end)
			break;

		term = false;
		for (; end + strlen("\r\n\r\n") <= dptr + datalen; end++) {
			if (end[0] == '\r' && end[1] == '\n' &&
			    end[2] == '\r' && end[3] == '\n') {
				term = true;
				break;
			}
		}
		if (!term)
			break;
		end += strlen("\r\n\r\n") + clen;

		msglen = origlen = end - dptr;
		if (msglen > datalen)
			return NF_ACCEPT;

		ret = process_sip_msg(skb, ct, protoff, dataoff,
				      &dptr, &msglen);
		/* process_sip_* functions report why this packet is dropped */
		if (ret != NF_ACCEPT)
			break;
		diff     = msglen - origlen;
		tdiff   += diff;

		dataoff += msglen;
		dptr    += msglen;
		datalen  = datalen + diff - msglen;
	}

	return ret;
}

static int process_sip_msg(struct sk_buff *skb, struct nf_conn *ct,
			   unsigned int protoff, unsigned int dataoff,
			   const char **dptr, unsigned int *datalen) {
    int ret;
    unsigned int callidoff, callidlen;
    struct extsip_callinfo *callinfo;

    if (ct_sip_get_header(ct, *dptr, 0, *datalen, SIP_HDR_CALL_ID,
                          &callidoff, &callidlen) <= 0) {
            nf_ct_helper_log(skb, ct, "Missing callid");
            return NF_DROP;
    }

    callinfo = extsip_callinfo_get(ct, *dptr + callidoff, callidlen);
    
    if (strncasecmp(*dptr, "SIP/2.0 ", strlen("SIP/2.0 ")) != 0) {
        ret = process_sip_request(skb, protoff, dataoff, dptr, datalen, callinfo);
    } else {
        ret = process_sip_response(skb, protoff, dataoff, dptr, datalen, callinfo);
    }

    /* Уменьшаем использование указателя */
    callinfo_put(callinfo);
    
    return ret;
}

static int process_sip_request(struct sk_buff *skb, unsigned int protoff,
			       unsigned int dataoff,
			       const char **dptr, unsigned int *datalen,
                               struct extsip_callinfo *callinfo) {
	enum ip_conntrack_info ctinfo;
	struct nf_conn *ct = nf_ct_get(skb, &ctinfo);
	struct nf_ct_extsip_master *ct_extsip_info = nfct_help_data(ct);
	enum ip_conntrack_dir dir = CTINFO2DIR(ctinfo);
	unsigned int matchoff, matchlen;
	unsigned int cseq, i;
	union nf_inet_addr addr;
	__be16 port;
        int len;

	/* Many Cisco IP phones use a high source port for SIP requests, but
	 * listen for the response on port 5060.  If we are the local
	 * router for one of these phones, save the port number from the
	 * Via: header so that nf_nat_sip can redirect the responses to
	 * the correct port.
	 */
	if (ct_sip_parse_header_uri(ct, *dptr, NULL, *datalen,
				    SIP_HDR_VIA_UDP, NULL, &matchoff,
				    &matchlen, &addr, &port) > 0 &&
	    port != ct->tuplehash[dir].tuple.src.u.udp.port &&
	    nf_inet_addr_cmp(&addr, &ct->tuplehash[dir].tuple.src.u3)) {
            ct_extsip_info->forced_dport = port;
        }

        /* Определяем длину кода запроса */
        len = word_len(*dptr, *dptr + *datalen);
        if(len > 0) {
            struct iphdr *ip_header = (struct iphdr *)skb_network_header(skb);
            unsigned int src_ip = (unsigned int)ip_header->saddr;
            unsigned int dest_ip = (unsigned int)ip_header->daddr;
    
            pr_info("EXTSIP: %.*s REQUEST %pI4 -> %pI4 Call-ID: %s\n", len, *dptr, &src_ip, &dest_ip, callinfo->callid);
        }
        
	for (i = 0; i < ARRAY_SIZE(sip_handlers); i++) {
		const struct extsip_handler *handler;

		handler = &sip_handlers[i];
		if (handler->request == NULL)
			continue;
		if (*datalen < handler->len ||
		    strncasecmp(*dptr, handler->method, handler->len))
			continue;

		if (ct_sip_get_header(ct, *dptr, 0, *datalen, SIP_HDR_CSEQ,
				      &matchoff, &matchlen) <= 0) {
			nf_ct_helper_log(skb, ct, "cannot parse cseq");
			return NF_DROP;
		}
		cseq = simple_strtoul(*dptr + matchoff, NULL, 10);
		if (!cseq) {
			nf_ct_helper_log(skb, ct, "cannot get cseq");
			return NF_DROP;
		}

		return handler->request(skb, protoff, dataoff, dptr, datalen,
                                        callinfo,
					cseq);
	}
	return NF_ACCEPT;
}

static int process_sip_response(struct sk_buff *skb, unsigned int protoff,
				unsigned int dataoff,
				const char **dptr, unsigned int *datalen,
                                struct extsip_callinfo *callinfo) {
	enum ip_conntrack_info ctinfo;
	struct nf_conn *ct = nf_ct_get(skb, &ctinfo);
	unsigned int matchoff, matchlen, matchend;
	unsigned int code, cseq, i;
        int len;

	if (*datalen < strlen("SIP/2.0 200"))
		return NF_ACCEPT;
	code = simple_strtoul(*dptr + strlen("SIP/2.0 "), NULL, 10);
	if (!code) {
		nf_ct_helper_log(skb, ct, "cannot get code");
		return NF_DROP;
	}

	if (ct_sip_get_header(ct, *dptr, 0, *datalen, SIP_HDR_CSEQ,
			      &matchoff, &matchlen) <= 0) {
		nf_ct_helper_log(skb, ct, "cannot parse cseq");
		return NF_DROP;
	}
	cseq = simple_strtoul(*dptr + matchoff, NULL, 10);
	if (!cseq) {
		nf_ct_helper_log(skb, ct, "cannot get cseq");
		return NF_DROP;
	}
	matchend = matchoff + matchlen + 1;

        /* Определяем, на что был этот ответ */
        len = word_len(*dptr + matchend, *dptr + *datalen);
        if(len > 0) {
            /* Мы определили, на какой тип запроса был получен ответ */
            struct iphdr *ip_header = (struct iphdr *)skb_network_header(skb);
            unsigned int src_ip = (unsigned int)ip_header->saddr;
            unsigned int dest_ip = (unsigned int)ip_header->daddr;
    
            pr_info("EXTSIP: %.*s RESPONSE=%u %pI4 -> %pI4 Call-ID: %s\n", len, *dptr + matchend, code, &src_ip, &dest_ip, callinfo->callid);
        }
        
	for (i = 0; i < ARRAY_SIZE(sip_handlers); i++) {
		const struct extsip_handler *handler;

		handler = &sip_handlers[i];
		if (handler->response == NULL)
			continue;
		if (*datalen < matchend + handler->len ||
		    strncasecmp(*dptr + matchend, handler->method, handler->len))
			continue;
		return handler->response(skb, protoff, dataoff, dptr, datalen,
                                         callinfo,
					 cseq, code);
	}
	return NF_ACCEPT;
}

static int process_invite_request(struct sk_buff *skb, unsigned int protoff,
				  unsigned int dataoff,
				  const char **dptr, unsigned int *datalen,
                                  struct extsip_callinfo *callinfo,
				  unsigned int cseq) {
#if 0
	enum ip_conntrack_info ctinfo;
	struct nf_conn *ct = nf_ct_get(skb, &ctinfo);
	struct nf_ct_sip_master *ct_sip_info = nfct_help_data(ct);
	unsigned int ret;

	flush_expectations(ct, true);
	ret = process_sdp(skb, protoff, dataoff, dptr, datalen, cseq);
	if (ret == NF_ACCEPT)
		ct_sip_info->invite_cseq = cseq;
	return ret;
#else
	enum ip_conntrack_info ctinfo;
	struct nf_conn *ct = nf_ct_get(skb, &ctinfo);
        
//        trace_pkt("INVITE REQUEST", skb, callinfo);
        
        update_callid_lifetime(callinfo, ct, *dptr, *datalen, "INVITE REQUEST");
        
        return NF_ACCEPT;
#endif
}

static int process_invite_response(struct sk_buff *skb, unsigned int protoff,
				   unsigned int dataoff,
				   const char **dptr, unsigned int *datalen,
                                   struct extsip_callinfo *callinfo,
				   unsigned int cseq, unsigned int code) {
#if 0
        enum ip_conntrack_info ctinfo;
	struct nf_conn *ct = nf_ct_get(skb, &ctinfo);
	struct nf_ct_sip_master *ct_sip_info = nfct_help_data(ct);

	if ((code >= 100 && code <= 199) ||
	    (code >= 200 && code <= 299))
		return process_sdp(skb, protoff, dataoff, dptr, datalen, cseq);
	else if (ct_sip_info->invite_cseq == cseq)
		flush_expectations(ct, true);
	return NF_ACCEPT;
#else
	enum ip_conntrack_info ctinfo;
	struct nf_conn *ct = nf_ct_get(skb, &ctinfo);
        
//        trace_pkt("INVITE RESPONSE", skb, callinfo);
        
        update_callid_lifetime(callinfo, ct, *dptr, *datalen, "INVITE RESPONSE");
        
        return NF_ACCEPT;
#endif
}

static int process_update_response(struct sk_buff *skb, unsigned int protoff,
				   unsigned int dataoff,
				   const char **dptr, unsigned int *datalen,
                                   struct extsip_callinfo *callinfo,
				   unsigned int cseq, unsigned int code) {
#if 0
        enum ip_conntrack_info ctinfo;
	struct nf_conn *ct = nf_ct_get(skb, &ctinfo);
	struct nf_ct_sip_master *ct_sip_info = nfct_help_data(ct);

	if ((code >= 100 && code <= 199) ||
	    (code >= 200 && code <= 299))
		return process_sdp(skb, protoff, dataoff, dptr, datalen, cseq);
	else if (ct_sip_info->invite_cseq == cseq)
		flush_expectations(ct, true);
	return NF_ACCEPT;
#else
	enum ip_conntrack_info ctinfo;
	struct nf_conn *ct = nf_ct_get(skb, &ctinfo);
        
//        trace_pkt("UPDATE RESPONSE", skb, callinfo);
        
        update_callid_lifetime(callinfo, ct, *dptr, *datalen, "UPDATE RESPONSE");
        
        return NF_ACCEPT;
#endif
}

static int process_sdp(struct sk_buff *skb, unsigned int protoff,
		       unsigned int dataoff,
		       const char **dptr, unsigned int *datalen,
                       struct extsip_callinfo *callinfo,
		       unsigned int cseq) {
#if 0
	enum ip_conntrack_info ctinfo;
	struct nf_conn *ct = nf_ct_get(skb, &ctinfo);
	unsigned int matchoff, matchlen;
	unsigned int mediaoff, medialen;
	unsigned int sdpoff;
	unsigned int caddr_len, maddr_len;
	unsigned int i;
	union nf_inet_addr caddr, maddr, rtp_addr;
	const struct nf_nat_sip_hooks *hooks;
	unsigned int port;
	const struct sdp_media_type *t;
	int ret = NF_ACCEPT;

	hooks = rcu_dereference(nf_nat_sip_hooks);

	/* Find beginning of session description */
	if (ct_sip_get_sdp_header(ct, *dptr, 0, *datalen,
				  SDP_HDR_VERSION, SDP_HDR_UNSPEC,
				  &matchoff, &matchlen) <= 0)
		return NF_ACCEPT;
	sdpoff = matchoff;

	/* The connection information is contained in the session description
	 * and/or once per media description. The first media description marks
	 * the end of the session description. */
	caddr_len = 0;
	if (ct_sip_parse_sdp_addr(ct, *dptr, sdpoff, *datalen,
				  SDP_HDR_CONNECTION, SDP_HDR_MEDIA,
				  &matchoff, &matchlen, &caddr) > 0)
		caddr_len = matchlen;

	mediaoff = sdpoff;
	for (i = 0; i < ARRAY_SIZE(sdp_media_types); ) {
		if (ct_sip_get_sdp_header(ct, *dptr, mediaoff, *datalen,
					  SDP_HDR_MEDIA, SDP_HDR_UNSPEC,
					  &mediaoff, &medialen) <= 0)
			break;

		/* Get media type and port number. A media port value of zero
		 * indicates an inactive stream. */
		t = sdp_media_type(*dptr, mediaoff, medialen);
		if (!t) {
			mediaoff += medialen;
			continue;
		}
		mediaoff += t->len;
		medialen -= t->len;

		port = simple_strtoul(*dptr + mediaoff, NULL, 10);
		if (port == 0)
			continue;
		if (port < 1024 || port > 65535) {
			nf_ct_helper_log(skb, ct, "wrong port %u", port);
			return NF_DROP;
		}

		/* The media description overrides the session description. */
		maddr_len = 0;
		if (ct_sip_parse_sdp_addr(ct, *dptr, mediaoff, *datalen,
					  SDP_HDR_CONNECTION, SDP_HDR_MEDIA,
					  &matchoff, &matchlen, &maddr) > 0) {
			maddr_len = matchlen;
			memcpy(&rtp_addr, &maddr, sizeof(rtp_addr));
		} else if (caddr_len)
			memcpy(&rtp_addr, &caddr, sizeof(rtp_addr));
		else {
			nf_ct_helper_log(skb, ct, "cannot parse SDP message");
			return NF_DROP;
		}

		ret = set_expected_rtp_rtcp(skb, protoff, dataoff,
					    dptr, datalen,
					    &rtp_addr, htons(port), t->class,
					    mediaoff, medialen);
		if (ret != NF_ACCEPT) {
			nf_ct_helper_log(skb, ct,
					 "cannot add expectation for voice");
			return ret;
		}

		/* Update media connection address if present */
		if (maddr_len && hooks && ct->status & IPS_NAT_MASK) {
			ret = hooks->sdp_addr(skb, protoff, dataoff,
					      dptr, datalen, mediaoff,
					      SDP_HDR_CONNECTION,
					      SDP_HDR_MEDIA,
					      &rtp_addr);
			if (ret != NF_ACCEPT) {
				nf_ct_helper_log(skb, ct, "cannot mangle SDP");
				return ret;
			}
		}
		i++;
	}

	/* Update session connection and owner addresses */
	hooks = rcu_dereference(nf_nat_sip_hooks);
	if (hooks && ct->status & IPS_NAT_MASK)
		ret = hooks->sdp_session(skb, protoff, dataoff,
					 dptr, datalen, sdpoff,
					 &rtp_addr);

	return ret;
#else
	enum ip_conntrack_info ctinfo;
	struct nf_conn *ct = nf_ct_get(skb, &ctinfo);
        
//        trace_pkt("SDP", skb, callinfo);
        
        update_callid_lifetime(callinfo, ct, *dptr, *datalen, "SDP");
        
        return NF_ACCEPT;
#endif
}

static int process_prack_response(struct sk_buff *skb, unsigned int protoff,
				  unsigned int dataoff,
				  const char **dptr, unsigned int *datalen,
                                  struct extsip_callinfo *callinfo,
				  unsigned int cseq, unsigned int code) {
#if 0
	enum ip_conntrack_info ctinfo;
	struct nf_conn *ct = nf_ct_get(skb, &ctinfo);
	struct nf_ct_sip_master *ct_sip_info = nfct_help_data(ct);

	if ((code >= 100 && code <= 199) ||
	    (code >= 200 && code <= 299))
		return process_sdp(skb, protoff, dataoff, dptr, datalen, cseq);
	else if (ct_sip_info->invite_cseq == cseq)
		flush_expectations(ct, true);
	return NF_ACCEPT;
#else
	enum ip_conntrack_info ctinfo;
	struct nf_conn *ct = nf_ct_get(skb, &ctinfo);
        
//        trace_pkt("PRACK RESPONSE", skb, callinfo);
        
        update_callid_lifetime(callinfo, ct, *dptr, *datalen, "PRACK RESPONSE");
        
        return NF_ACCEPT;
#endif
}

static int process_bye_request(struct sk_buff *skb, unsigned int protoff,
			       unsigned int dataoff,
			       const char **dptr, unsigned int *datalen,
                               struct extsip_callinfo *callinfo,
			       unsigned int cseq) {
#if 0
	enum ip_conntrack_info ctinfo;
	struct nf_conn *ct = nf_ct_get(skb, &ctinfo);

	flush_expectations(ct, true);
	return NF_ACCEPT;
#else
	enum ip_conntrack_info ctinfo;
	struct nf_conn *ct = nf_ct_get(skb, &ctinfo);
        
//        trace_pkt("BYE REQUEST", skb, callinfo);
        
        update_callid_lifetime(callinfo, ct, *dptr, *datalen, "BYE REQUEST");
        
        return NF_ACCEPT;
#endif
}

/* Parse a REGISTER request and create a permanent expectation for incoming
 * signalling connections. The expectation is marked inactive and is activated
 * when receiving a response indicating success from the registrar.
 */
static int process_register_request(struct sk_buff *skb, unsigned int protoff,
				    unsigned int dataoff,
				    const char **dptr, unsigned int *datalen,
                                    struct extsip_callinfo *ci,
				    unsigned int cseq) {
#if 0
	enum ip_conntrack_info ctinfo;
	struct nf_conn *ct = nf_ct_get(skb, &ctinfo);
	struct nf_ct_sip_master *ct_sip_info = nfct_help_data(ct);
	enum ip_conntrack_dir dir = CTINFO2DIR(ctinfo);
	unsigned int matchoff, matchlen;
	struct nf_conntrack_expect *exp;
	union nf_inet_addr *saddr, daddr;
	const struct nf_nat_sip_hooks *hooks;
	__be16 port;
	u8 proto;
	unsigned int expires = 0;
	int ret;

	/* Expected connections can not register again. */
	if (ct->status & IPS_EXPECTED)
		return NF_ACCEPT;

	/* We must check the expiration time: a value of zero signals the
	 * registrar to release the binding. We'll remove our expectation
	 * when receiving the new bindings in the response, but we don't
	 * want to create new ones.
	 *
	 * The expiration time may be contained in Expires: header, the
	 * Contact: header parameters or the URI parameters.
	 */
	if (ct_sip_get_header(ct, *dptr, 0, *datalen, SIP_HDR_EXPIRES,
			      &matchoff, &matchlen) > 0)
		expires = simple_strtoul(*dptr + matchoff, NULL, 10);

	ret = ct_sip_parse_header_uri(ct, *dptr, NULL, *datalen,
				      SIP_HDR_CONTACT, NULL,
				      &matchoff, &matchlen, &daddr, &port);
	if (ret < 0) {
		nf_ct_helper_log(skb, ct, "cannot parse contact");
		return NF_DROP;
	} else if (ret == 0)
		return NF_ACCEPT;

	/* We don't support third-party registrations */
	if (!nf_inet_addr_cmp(&ct->tuplehash[dir].tuple.src.u3, &daddr))
		return NF_ACCEPT;

	if (ct_sip_parse_transport(ct, *dptr, matchoff + matchlen, *datalen,
				   &proto) == 0)
		return NF_ACCEPT;

	if (ct_sip_parse_numerical_param(ct, *dptr,
					 matchoff + matchlen, *datalen,
					 "expires=", NULL, NULL, &expires) < 0) {
		nf_ct_helper_log(skb, ct, "cannot parse expires");
		return NF_DROP;
	}

	if (expires == 0) {
		ret = NF_ACCEPT;
		goto store_cseq;
	}

	exp = nf_ct_expect_alloc(ct);
	if (!exp) {
		nf_ct_helper_log(skb, ct, "cannot alloc expectation");
		return NF_DROP;
	}

	saddr = NULL;
	if (sip_direct_signalling)
		saddr = &ct->tuplehash[!dir].tuple.src.u3;

	nf_ct_expect_init(exp, SIP_EXPECT_SIGNALLING, nf_ct_l3num(ct),
			  saddr, &daddr, proto, NULL, &port);
	exp->timeout.expires = sip_timeout * HZ;
	exp->helper = nfct_help(ct)->helper;
	exp->flags = NF_CT_EXPECT_PERMANENT | NF_CT_EXPECT_INACTIVE;

	hooks = rcu_dereference(nf_nat_sip_hooks);
	if (hooks && ct->status & IPS_NAT_MASK)
		ret = hooks->expect(skb, protoff, dataoff, dptr, datalen,
				    exp, matchoff, matchlen);
	else {
		if (nf_ct_expect_related(exp) != 0) {
			nf_ct_helper_log(skb, ct, "cannot add expectation");
			ret = NF_DROP;
		} else
			ret = NF_ACCEPT;
	}
	nf_ct_expect_put(exp);

store_cseq:
	if (ret == NF_ACCEPT)
		ct_sip_info->register_cseq = cseq;
	return ret;
#else
    enum ip_conntrack_info ctinfo;
    struct nf_conn *ct = nf_ct_get(skb, &ctinfo);
        
    /* Запрошенное время жизни в секундах из пакета */
    int expires = ct_sip_get_expires(ct, *dptr, *datalen);

    if(expires < 0) {
        /* Отсутствует expires в заголовке, ставим значение по умолчанию */
        expires = sip_max_callid_lifetime;
    }
    
    if(expires) {
        /* expires > 0 - запрос регистрации */
        ci->register_state = SIP_REGISTER_SENT;
        
        /* Сколько секунд абонент хочет установить в качестве вермени жизни регистрации */
        ci->register_expire_seconds = expires;
    } else {
        /* expires == 0 - запрос отмены регистрации */
        ci->register_state = SIP_UNREGISTER_SENT;
    }

    /* Устанавливаем значение таймера */
//    set_callinfo_lifetime(ci, expires * 1000);
    
//        trace_pkt("REGISTER REQUEST", skb, callinfo);
        
//        update_callid_lifetime(callinfo, ct, *dptr, *datalen, "REGISTER REQUEST");
        
    return NF_ACCEPT;
#endif
}

static int process_register_response(struct sk_buff *skb, unsigned int protoff,
				     unsigned int dataoff,
				     const char **dptr, unsigned int *datalen,
                                     struct extsip_callinfo *ci,
				     unsigned int cseq, unsigned int code) {
#if 0
	enum ip_conntrack_info ctinfo;
	struct nf_conn *ct = nf_ct_get(skb, &ctinfo);
	struct nf_ct_sip_master *ct_sip_info = nfct_help_data(ct);
	enum ip_conntrack_dir dir = CTINFO2DIR(ctinfo);
	union nf_inet_addr addr;
	__be16 port;
	u8 proto;
	unsigned int matchoff, matchlen, coff = 0;
	unsigned int expires = 0;
	int in_contact = 0, ret;

	/* According to RFC 3261, "UAs MUST NOT send a new registration until
	 * they have received a final response from the registrar for the
	 * previous one or the previous REGISTER request has timed out".
	 *
	 * However, some servers fail to detect retransmissions and send late
	 * responses, so we store the sequence number of the last valid
	 * request and compare it here.
	 */
	if (ct_sip_info->register_cseq != cseq)
		return NF_ACCEPT;

	if (code >= 100 && code <= 199)
		return NF_ACCEPT;
	if (code < 200 || code > 299)
		goto flush;

	if (ct_sip_get_header(ct, *dptr, 0, *datalen, SIP_HDR_EXPIRES,
			      &matchoff, &matchlen) > 0)
		expires = simple_strtoul(*dptr + matchoff, NULL, 10);

	while (1) {
		unsigned int c_expires = expires;

		ret = ct_sip_parse_header_uri(ct, *dptr, &coff, *datalen,
					      SIP_HDR_CONTACT, &in_contact,
					      &matchoff, &matchlen,
					      &addr, &port);
		if (ret < 0) {
			nf_ct_helper_log(skb, ct, "cannot parse contact");
			return NF_DROP;
		} else if (ret == 0)
			break;

		/* We don't support third-party registrations */
		if (!nf_inet_addr_cmp(&ct->tuplehash[dir].tuple.dst.u3, &addr))
			continue;

		if (ct_sip_parse_transport(ct, *dptr, matchoff + matchlen,
					   *datalen, &proto) == 0)
			continue;

		ret = ct_sip_parse_numerical_param(ct, *dptr,
						   matchoff + matchlen,
						   *datalen, "expires=",
						   NULL, NULL, &c_expires);
		if (ret < 0) {
			nf_ct_helper_log(skb, ct, "cannot parse expires");
			return NF_DROP;
		}
		if (c_expires == 0)
			break;
		if (refresh_signalling_expectation(ct, &addr, proto, port,
						   c_expires))
			return NF_ACCEPT;
	}

flush:
	flush_expectations(ct, false);
	return NF_ACCEPT;
#else
    enum ip_conntrack_info ctinfo;
    struct nf_conn *ct = nf_ct_get(skb, &ctinfo);
        
    /* Запрошенное время жизни в секундах из пакета */
    int expires = ct_sip_get_expires(ct, *dptr, *datalen);
    
    /* Анализируем текущее состояние */
    switch(ci->register_state) {
        case SIP_REGISTER_SENT:
            /* Мы посылали запрос регистрации */
            switch(code) {
                case SIP_RESPONSE_OK:
                    /* Регистрация прошла успешно */
                    ci->register_state = SIP_REGISTER_COMPLETE;

                    break;
                case SIP_RESPONSE_UNAUTHORIZED:
                    /* Требуется авторизация */
                    ci->register_state = SIP_REGISTER_UNAUTHORIZED;

                    break;
            }

            break;
        case SIP_UNREGISTER_SENT:
            /* Мы посылали запрос отмены регистрации */
            switch(code) {
                case SIP_RESPONSE_OK:
                    /* Регистрация прошла успешно */
                    ci->register_state = SIP_UNREGISTER_COMPLETE;

                    break;
                case SIP_RESPONSE_UNAUTHORIZED:
                    /* Требуется авторизация */
                    ci->register_state = SIP_UNREGISTER_UNAUTHORIZED;

                    break;
            }

            break;
        default:
            /* Запрос регистрации не посылался либо был потерян */

            break;
    }

    switch(ci->register_state) {
        case SIP_REGISTER_COMPLETE:
            /* Регистрация прошла успешно */
            if(expires < 0) {
                /* В ответе отсутствует значение expires, берем желаемое из запроса */
                expires = ci->register_expire_seconds;
            }
            
            if(!expires || (expires > sip_max_callid_lifetime)) {
                /* Устанавливаем максимально допустимое значение */
                expires = sip_max_callid_lifetime;
            }
            
            /* Устанавливаем значение таймера */
            set_callinfo_lifetime(ci, expires * 1000);

            pr_info("EXTSIP: Extend lifetime with %d seconds as REGISTER RESPONSE for Call-ID: %s\n", expires, ci->callid);
            
            break;
        case SIP_UNREGISTER_COMPLETE:
            /* Отмена регистрации прошла успешно, этот сеанс больше не активен! */
            callinfo_remove(ci);
            
            break;
        default:
            break;
    }
    
//        trace_pkt("REGISTER RESPONSE", skb, callinfo);
        
//        update_callid_lifetime(callinfo, ct, *dptr, *datalen, "REGISTER RESPONSE");
        
    return NF_ACCEPT;
#endif
}

/* Locate a SIP header, parse the URI and return the offset and length of
 * the address as well as the address and port themselves. A stream of
 * headers can be parsed by handing in a non-NULL datalen and in_header
 * pointer.
 */
static int ct_sip_parse_header_uri(const struct nf_conn *ct, const char *dptr,
			    unsigned int *dataoff, unsigned int datalen,
			    enum sip_header_types type, int *in_header,
			    unsigned int *matchoff, unsigned int *matchlen,
			    union nf_inet_addr *addr, __be16 *port) {
	const char *c, *limit = dptr + datalen;
	unsigned int p;
	int ret;

	ret = ct_sip_walk_headers(ct, dptr, dataoff ? *dataoff : 0, datalen,
				  type, in_header, matchoff, matchlen);
	WARN_ON(ret < 0);
	if (ret == 0)
		return ret;

	if (!sip_parse_addr(ct, dptr + *matchoff, &c, addr, limit, true))
		return -1;
	if (*c == ':') {
		c++;
		p = simple_strtoul(c, (char **)&c, 10);
		if (p < 1024 || p > 65535)
			return -1;
		*port = htons(p);
	} else
		*port = htons(SIP_PORT);

	if (dataoff)
		*dataoff = c - dptr;
	return 1;
}


/* Walk through headers until a parsable one is found or no header of the
 * given type is left. */
static int ct_sip_walk_headers(const struct nf_conn *ct, const char *dptr,
			       unsigned int dataoff, unsigned int datalen,
			       enum sip_header_types type, int *in_header,
			       unsigned int *matchoff, unsigned int *matchlen) {
	int ret;

	if (in_header && *in_header) {
		while (1) {
			ret = ct_sip_next_header(ct, dptr, dataoff, datalen,
						 type, matchoff, matchlen);
			if (ret > 0)
				return ret;
			if (ret == 0)
				break;
			dataoff += *matchoff;
		}
		*in_header = 0;
	}

	while (1) {
		ret = ct_sip_get_header(ct, dptr, dataoff, datalen,
					type, matchoff, matchlen);
		if (ret > 0)
			break;
		if (ret == 0)
			return ret;
		dataoff += *matchoff;
	}

	if (in_header)
		*in_header = 1;
	return 1;
}

/* Get next header field in a list of comma separated values */
static int ct_sip_next_header(const struct nf_conn *ct, const char *dptr,
			      unsigned int dataoff, unsigned int datalen,
			      enum sip_header_types type,
			      unsigned int *matchoff, unsigned int *matchlen) {
	const struct sip_header *hdr = &ct_sip_hdrs[type];
	const char *start = dptr, *limit = dptr + datalen;
	int shift = 0;

	dptr += dataoff;

	dptr = ct_sip_header_search(dptr, limit, ",", strlen(","));
	if (!dptr)
		return 0;

	dptr = ct_sip_header_search(dptr, limit, hdr->search, hdr->slen);
	if (!dptr)
		return 0;
	dptr += hdr->slen;

	*matchoff = dptr - start;
	*matchlen = hdr->match_len(ct, dptr, limit, &shift);
	if (!*matchlen)
		return -1;
	*matchoff += shift;
	return 1;
}

/**
 * Обновление времени жизни callid
 * 
 * @param ci
 * @param ct
 * @param dptr
 * @param datalen
 * @param reason
 */
static void update_callid_lifetime(struct extsip_callinfo *ci,
                                   const struct nf_conn *ct, 
                                   const char *dptr,
                                   unsigned int datalen,
                                   const char *reason) {
    /* Запрошенное время жизни в секундах из пакета */
    int expires = ct_sip_get_expires(ct, dptr, datalen);
    
    if(expires < 0) {
        /* В пакете время жизни задано не было */
        return;
    }
    
    if(!expires || (expires > sip_max_callid_lifetime)) {
        /* Запрошенное время не соответствует нашим представлениям */
        expires = sip_max_callid_lifetime;
    }
    
    /* Устанавливаем значение таймера */
    set_callinfo_lifetime(ci, expires * 1000);
    
    pr_info("EXTSIP: Extend lifetime with %d seconds as %s for Call-ID: %s\n", expires, reason, ci->callid);
}

/**
 * Получить максимальное время жизни сеанса из SIP-заголовка
 * 
 * @param ct
 * @param dptr
 * @param datalen
 * @return 
 */
static int ct_sip_get_expires(const struct nf_conn *ct, 
                              const char *dptr,
                              unsigned int datalen) {
    unsigned int matchoff, matchlen;

    if(ct_sip_get_header(ct, dptr, 0, datalen, SIP_HDR_EXPIRES,
                          &matchoff, &matchlen) > 0) {
        char *endp;
        unsigned long expires = simple_strtoul(dptr + matchoff, &endp, 10);
        
        if(endp != dptr + matchoff) {
            /* Значение было задано */
            if(expires < (INT_MAX/1000)) {
                /* Декодировано допустимое значение */
                return expires;
            }
        }
    }

    /* Значение отсутствует либо не допустимо */
    return -1;
}

static int ct_sip_get_header(const struct nf_conn *ct, const char *dptr,
		             unsigned int dataoff, unsigned int datalen,
		             enum sip_header_types type,
		             unsigned int *matchoff, unsigned int *matchlen) {
	const struct sip_header *hdr = &ct_sip_hdrs[type];
	const char *start = dptr, *limit = dptr + datalen;
	int shift = 0;

	for (dptr += dataoff; dptr < limit; dptr++) {
		/* Find beginning of line */
		if (*dptr != '\r' && *dptr != '\n')
			continue;
		if (++dptr >= limit)
			break;
		if (*(dptr - 1) == '\r' && *dptr == '\n') {
			if (++dptr >= limit)
				break;
		}

		/* Skip continuation lines */
		if (*dptr == ' ' || *dptr == '\t')
			continue;

		/* Find header. Compact headers must be followed by a
		 * non-alphabetic character to avoid mismatches. */
		if (limit - dptr >= hdr->len &&
		    strncasecmp(dptr, hdr->name, hdr->len) == 0)
			dptr += hdr->len;
		else if (hdr->cname && limit - dptr >= hdr->clen + 1 &&
			 strncasecmp(dptr, hdr->cname, hdr->clen) == 0 &&
			 !isalpha(*(dptr + hdr->clen)))
			dptr += hdr->clen;
		else
			continue;

		/* Find and skip colon */
		dptr = sip_skip_whitespace(dptr, limit);
		if (dptr == NULL)
			break;
		if (*dptr != ':' || ++dptr >= limit)
			break;

		/* Skip whitespace after colon */
		dptr = sip_skip_whitespace(dptr, limit);
		if (dptr == NULL)
			break;

		*matchoff = dptr - start;
		if (hdr->search) {
			dptr = ct_sip_header_search(dptr, limit, hdr->search,
						    hdr->slen);
			if (!dptr)
				return -1;
			dptr += hdr->slen;
		}

		*matchlen = hdr->match_len(ct, dptr, limit, &shift);
		if (!*matchlen)
			return -1;
		*matchoff = dptr - start + shift;
		return 1;
	}
	return 0;
}

static const char *sip_skip_whitespace(const char *dptr, const char *limit) {
	for (; dptr < limit; dptr++) {
		if (*dptr == ' ')
			continue;
		if (*dptr != '\r' && *dptr != '\n')
			break;
		dptr = sip_follow_continuation(dptr, limit);
		if (dptr == NULL)
			return NULL;
	}
	return dptr;
}


/* Search within a SIP header value, dealing with continuation lines */
static const char *ct_sip_header_search(const char *dptr, const char *limit,
					const char *needle, unsigned int len) {
	for (limit -= len; dptr < limit; dptr++) {
		if (*dptr == '\r' || *dptr == '\n') {
			dptr = sip_follow_continuation(dptr, limit);
			if (dptr == NULL)
				break;
			continue;
		}

		if (strncasecmp(dptr, needle, len) == 0)
			return dptr;
	}
	return NULL;
}

static const char *sip_follow_continuation(const char *dptr, const char *limit) {
	/* Walk past newline */
	if (++dptr >= limit)
		return NULL;

	/* Skip '\n' in CR LF */
	if (*(dptr - 1) == '\r' && *dptr == '\n') {
		if (++dptr >= limit)
			return NULL;
	}

	/* Continuation line? */
	if (*dptr != ' ' && *dptr != '\t')
		return NULL;

	/* skip leading whitespace */
	for (; dptr < limit; dptr++) {
		if (*dptr != ' ' && *dptr != '\t')
			break;
	}
	return dptr;
}


/* get address length, skiping user info. */
static int skp_epaddr_len(const struct nf_conn *ct, const char *dptr,
			  const char *limit, int *shift) {
	const char *start = dptr;
	int s = *shift;

	/* Search for @, but stop at the end of the line.
	 * We are inside a sip: URI, so we don't need to worry about
	 * continuation lines. */
	while (dptr < limit &&
	       *dptr != '@' && *dptr != '\r' && *dptr != '\n') {
		(*shift)++;
		dptr++;
	}

	if (dptr < limit && *dptr == '@') {
		dptr++;
		(*shift)++;
	} else {
		dptr = start;
		*shift = s;
	}

	return epaddr_len(ct, dptr, limit, shift);
}

/* skip ip address. returns its length. */
static int epaddr_len(const struct nf_conn *ct, const char *dptr,
		      const char *limit, int *shift) {
	union nf_inet_addr addr;
	const char *aux = dptr;

	if (!sip_parse_addr(ct, dptr, &dptr, &addr, limit, true)) {
		pr_debug("ip: %s parse failed.!\n", dptr);
		return 0;
	}

	/* Port number */
	if (*dptr == ':') {
		dptr++;
		dptr += digits_len(ct, dptr, limit, shift);
	}
	return dptr - aux;
}

static int sip_parse_addr(const struct nf_conn *ct, const char *cp,
			  const char **endp, union nf_inet_addr *addr,
			  const char *limit, bool delim) {
	const char *end;
	int ret;

	if (!ct)
		return 0;

	memset(addr, 0, sizeof(*addr));
	switch (nf_ct_l3num(ct)) {
	case AF_INET:
		ret = in4_pton(cp, limit - cp, (u8 *)&addr->ip, -1, &end);
		if (ret == 0)
			return 0;
		break;
	case AF_INET6:
		if (cp < limit && *cp == '[')
			cp++;
		else if (delim)
			return 0;

		ret = in6_pton(cp, limit - cp, (u8 *)&addr->ip6, -1, &end);
		if (ret == 0)
			return 0;

		if (end < limit && *end == ']')
			end++;
		else if (delim)
			return 0;
		break;
	default:
		BUG();
	}

	if (endp)
		*endp = end;
	return 1;
}

static int callid_len(const struct nf_conn *ct, const char *dptr,
		      const char *limit, int *shift) {
	int len, domain_len;

	len = word_len(dptr, limit);
	dptr += len;
	if (!len || dptr == limit || *dptr != '@')
		return len;
	dptr++;
	len++;

	domain_len = word_len(dptr, limit);
	if (!domain_len)
		return 0;
	return len + domain_len;
}

static int word_len(const char *dptr, const char *limit) {
	int len = 0;
	while (dptr < limit && iswordc(*dptr)) {
		dptr++;
		len++;
	}
	return len;
}

static int digits_len(const struct nf_conn *ct, const char *dptr,
		      const char *limit, int *shift) {
	int len = 0;
	while (dptr < limit && isdigit(*dptr)) {
		dptr++;
		len++;
	}
	return len;
}

static int iswordc(const char c) {
	if (isalnum(c) || c == '!' || c == '"' || c == '%' ||
	    (c >= '(' && c <= '/') || c == ':' || c == '<' || c == '>' ||
	    c == '?' || (c >= '[' && c <= ']') || c == '_' || c == '`' ||
	    c == '{' || c == '}' || c == '~')
		return 1;
	return 0;
}
