/* 
 * File:   dpi_sip.h
 * Author: monster
 *
 * Created on 15 июня 2017 г., 10:26
 */

#ifndef DPI_SIP_H
#define DPI_SIP_H

/* For slab data:
 * kmem_cache_create()
 * kmem_cache_destroy()
 * kmem_cache_alloc()
 * kmem_cache_free()
 * 
 * Debug:
 * cat /proc/slabinfo
 */
#include <linux/slab.h>
#include <net/net_namespace.h>

#include "nf_conntrack_extsip.h"

#define SIP_PORT	5060


/* callinfo.c */
extern void set_callinfo_lifetime(struct extsip_callinfo *ci, 
                                  const unsigned int msec);
void remove_callinfo_timer(struct extsip_callinfo *ci);
extern struct extsip_callinfo *extsip_callinfo_get(struct nf_conn *ct, 
                                                   const char *callid, 
                                                   size_t callidlen);
extern void callinfo_remove(struct extsip_callinfo *ci);
extern void callinfo_put(struct extsip_callinfo *ci);
extern struct nf_ct_extsip_master *extsip_private_get(struct nf_conn *ct);

/* procfs_calls.c */
extern struct pernet_operations extsip_net_ops;

/* dpi_sip.c */
extern int extsip_help_udp(struct sk_buff *skb, unsigned int protoff,
			   struct nf_conn *ct, enum ip_conntrack_info ctinfo);
extern int extsip_help_tcp(struct sk_buff *skb, unsigned int protoff,
			   struct nf_conn *ct, enum ip_conntrack_info ctinfo);

/* nf_conntrack_extsip.c */
extern struct kmem_cache *extsip_callinfo_cachep __read_mostly;
extern unsigned int sip_timeout __read_mostly;
extern unsigned int sip_max_callid_lifetime __read_mostly;
extern void trace_pkt(const char* label, struct sk_buff *skb, struct extsip_callinfo *callinfo);


#endif /* DPI_SIP_H */

