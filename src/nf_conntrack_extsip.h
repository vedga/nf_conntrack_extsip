#ifndef __NF_CONNTRACK_EXTSIP_H__
#define __NF_CONNTRACK_EXTSIP_H__
#ifdef __KERNEL__

#if 0
#include <net/netfilter/nf_conntrack_expect.h>

#include <linux/types.h>

#define SIP_PORT	5060
#define SIP_TIMEOUT	3600

struct nf_ct_sip_master {
	unsigned int	register_cseq;
	unsigned int	invite_cseq;
	__be16		forced_dport;
};

enum sip_expectation_classes {
	SIP_EXPECT_SIGNALLING,
	SIP_EXPECT_AUDIO,
	SIP_EXPECT_VIDEO,
	SIP_EXPECT_IMAGE,
	__SIP_EXPECT_MAX
};
#define SIP_EXPECT_MAX	(__SIP_EXPECT_MAX - 1)

struct sdp_media_type {
	const char			*name;
	unsigned int			len;
	enum sip_expectation_classes	class;
};

#define SDP_MEDIA_TYPE(__name, __class)					\
{									\
	.name	= (__name),						\
	.len	= sizeof(__name) - 1,					\
	.class	= (__class),						\
}

struct sip_handler {
	const char	*method;
	unsigned int	len;
	int		(*request)(struct sk_buff *skb, unsigned int protoff,
				   unsigned int dataoff,
				   const char **dptr, unsigned int *datalen,
				   unsigned int cseq);
	int		(*response)(struct sk_buff *skb, unsigned int protoff,
				    unsigned int dataoff,
				    const char **dptr, unsigned int *datalen,
				    unsigned int cseq, unsigned int code);
};

#define SIP_HANDLER(__method, __request, __response)			\
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

struct nf_nat_sip_hooks {
	unsigned int (*msg)(struct sk_buff *skb,
			    unsigned int protoff,
			    unsigned int dataoff,
			    const char **dptr,
			    unsigned int *datalen);

	void (*seq_adjust)(struct sk_buff *skb,
			   unsigned int protoff, s16 off);

	unsigned int (*expect)(struct sk_buff *skb,
			       unsigned int protoff,
			       unsigned int dataoff,
			       const char **dptr,
			       unsigned int *datalen,
			       struct nf_conntrack_expect *exp,
			       unsigned int matchoff,
			       unsigned int matchlen);

	unsigned int (*sdp_addr)(struct sk_buff *skb,
				 unsigned int protoff,
				 unsigned int dataoff,
				 const char **dptr,
				 unsigned int *datalen,
				 unsigned int sdpoff,
				 enum sdp_header_types type,
				 enum sdp_header_types term,
				 const union nf_inet_addr *addr);

	unsigned int (*sdp_port)(struct sk_buff *skb,
				 unsigned int protoff,
				 unsigned int dataoff,
				 const char **dptr,
				 unsigned int *datalen,
				 unsigned int matchoff,
				 unsigned int matchlen,
				 u_int16_t port);

	unsigned int (*sdp_session)(struct sk_buff *skb,
				    unsigned int protoff,
				    unsigned int dataoff,
				    const char **dptr,
				    unsigned int *datalen,
				    unsigned int sdpoff,
				    const union nf_inet_addr *addr);

	unsigned int (*sdp_media)(struct sk_buff *skb,
				  unsigned int protoff,
				  unsigned int dataoff,
				  const char **dptr,
				  unsigned int *datalen,
				  struct nf_conntrack_expect *rtp_exp,
				  struct nf_conntrack_expect *rtcp_exp,
				  unsigned int mediaoff,
				  unsigned int medialen,
				  union nf_inet_addr *rtp_addr);
};
extern const struct nf_nat_sip_hooks *nf_nat_sip_hooks;

int ct_sip_parse_request(const struct nf_conn *ct, const char *dptr,
			 unsigned int datalen, unsigned int *matchoff,
			 unsigned int *matchlen, union nf_inet_addr *addr,
			 __be16 *port);
int ct_sip_get_header(const struct nf_conn *ct, const char *dptr,
		      unsigned int dataoff, unsigned int datalen,
		      enum sip_header_types type, unsigned int *matchoff,
		      unsigned int *matchlen);
int ct_sip_parse_header_uri(const struct nf_conn *ct, const char *dptr,
			    unsigned int *dataoff, unsigned int datalen,
			    enum sip_header_types type, int *in_header,
			    unsigned int *matchoff, unsigned int *matchlen,
			    union nf_inet_addr *addr, __be16 *port);
int ct_sip_parse_address_param(const struct nf_conn *ct, const char *dptr,
			       unsigned int dataoff, unsigned int datalen,
			       const char *name, unsigned int *matchoff,
			       unsigned int *matchlen, union nf_inet_addr *addr,
			       bool delim);
int ct_sip_parse_numerical_param(const struct nf_conn *ct, const char *dptr,
				 unsigned int off, unsigned int datalen,
				 const char *name, unsigned int *matchoff,
				 unsigned int *matchen, unsigned int *val);

int ct_sip_get_sdp_header(const struct nf_conn *ct, const char *dptr,
			  unsigned int dataoff, unsigned int datalen,
			  enum sdp_header_types type,
			  enum sdp_header_types term,
			  unsigned int *matchoff, unsigned int *matchlen);

#else
//#include <linux/netfilter/nf_conntrack_sip.h>

#include <linux/spinlock.h>
#include <linux/hashtable.h>
#include <linux/timer.h>
#include <linux/rcupdate.h>

#include <asm/atomic.h>

enum extsip_expectation_classes {
    /* REGISTER signalling */
    EXTSIP_EXPECT_REGISTER,
    __EXTSIP_EXPECT_MAX
};
#define EXTSIP_EXPECT_MAX	(__EXTSIP_EXPECT_MAX - 1)

/*
 * Состояния этапов регистрации
 */
enum sip_register_states {
    /* Отправлен запрос SIP REGISTER для регистрации */
    SIP_REGISTER_SENT,
    /* На SIP REGISTER получен 401 Unauthorized */
    SIP_REGISTER_UNAUTHORIZED,
    /* Ошибка регистрации по причине неправильной авторизации */
    SIP_REGISTER_DENIED,
    /* Регистрация прошла успешно */
    SIP_REGISTER_COMPLETE,
    /* Отправлен запрос SIP REGISTER для отмены регистрации */
    SIP_UNREGISTER_SENT,
    /* На SIP REGISTER получен 401 Unauthorized */
    SIP_UNREGISTER_UNAUTHORIZED,
    /* Ошибка отмены регистрации по причине неправильной авторизации */
    SIP_UNREGISTER_DENIED,
    /* Отмена регистрация прошла успешно */
    SIP_UNREGISTER_COMPLETE
};

/*
 * Инкапсуляция уникального SIP Call-ID
 */
struct extsip_callinfo {
    /* Для хранения элемента в hashtable */
    struct hlist_node ci_link;
    /* Для call_rcu, чтобы освобождать ресурс после истечения grace period */
    struct rcu_head rcu;
    /* Кол-во ссылок на структуру (т.к. таймер не совместим с концепцией RCU) */
    atomic_t use;
    /* SIP dialog callid */
    char *callid;
    /* Таймер, отслеживающий время жизни данного callid */
    struct timer_list expired;
    
    /* Состояние SIP REGISTER */
    enum sip_register_states register_state;
    /* Кол-во секунд, через которое сеанс SIP REGISTER будет считаться не валидным */
    int register_expire_seconds;
};

/* Кол-во битов в hashtable, в которой хранятся данные extsip_callinfo */
#define CALLINFO_HASHTABLE_BITS 3

/**
 * Внутренние данные helper, ассоциированные с каждой структурой nf_conn
 */
struct nf_ct_extsip_master {
    /* Кол-во активных структур callinfo. При создании helper это значение будет 0. 
     * А вообще-то нужно применять ->calls = ATOMIC_INIT(0);
     */
    unsigned long state;

    /* Для доступа на запись к полю callinfo */
    spinlock_t callinfo_lock;
    
    /* hash-таблица для хранения extsip_callinfo */
    DECLARE_HASHTABLE(callinfo, CALLINFO_HASHTABLE_BITS);
    
//    struct extsip_callinfo callinfo;
//    unsigned int register_cseq;
//    unsigned int invite_cseq;
    __be16 forced_dport;
};

/* Бит в поле state структуры nf_ct_extsip_master, 
 * означающий завершение инициализации данных */
#define EXTSIP_MASTER_STATE_INIT_COMPLETE_BIT   0



#endif

#endif /* __KERNEL__ */
#endif /* __NF_CONNTRACK_SIP_H__ */
