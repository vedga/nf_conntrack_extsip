#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/rculist_nulls.h>

#include <net/netfilter/nf_conntrack_helper.h>

#include "dpi_sip.h"

#define PROC_EXTSIP "nf_extsip"

/* Данные итератора для последовательного чтения файла */
struct ct_iter_state {
    /* Элемент должен присутствовать и обязательно быть первым! */
    struct seq_net_private p;
    unsigned int bucket;
};

/* Forward local function declarations */
static int __net_init extsip_net_init(struct net *net);
static void __net_exit extsip_net_exit(struct net *net);
static int ct_open(struct inode *inode, struct file *file);
static void *ct_seq_start(struct seq_file *seq, loff_t *pos) __acquires(RCU);
static void *ct_seq_next(struct seq_file *s, void *v, loff_t *pos);
static void ct_seq_stop(struct seq_file *s, void *v)  __releases(RCU);
static int ct_seq_show(struct seq_file *s, void *v);
static struct hlist_nulls_node *ct_get_idx(struct seq_file *seq, loff_t pos);
static struct hlist_nulls_node *ct_get_next(struct seq_file *seq,
                                            struct hlist_nulls_node *head);
static struct hlist_nulls_node *ct_get_first(struct seq_file *seq);

static const char *sip_register_state_name(enum sip_register_states state);

static int is_this_helper(struct nf_conntrack_tuple_hash *hash);

/* Набор операций при создании/удалении network ns */
struct pernet_operations extsip_net_ops = {
    .init = extsip_net_init,
    .exit = extsip_net_exit,
};

/* Набор операций для файла */
static const struct file_operations ct_file_ops = {
    .owner   = THIS_MODULE,
    .open    = ct_open,
    .read    = seq_read,
    .llseek  = seq_lseek,
    .release = seq_release_net,
};

/* Набор операций для последовательного чтения файла */
static const struct seq_operations ct_seq_ops = {
    .start = ct_seq_start,
    .next  = ct_seq_next,
    .stop  = ct_seq_stop,
    .show  = ct_seq_show
};

/**
 * Вызывается при создании net namespace
 * 
 * @param net
 */
static int __net_init extsip_net_init(struct net *net) {
    struct proc_dir_entry *pde;

    /* Создаем "файл" внутри /proc/net */
    pde = proc_create(PROC_EXTSIP, 0440, net->proc_net, &ct_file_ops);
    
    return pde ? 0 : -ENOMEM;
}

/**
 * Вызывается при удалении net namespace
 * 
 * @param net
 */
static void __net_exit extsip_net_exit(struct net *net) {
    /* Удаляем "файл" внутри /proc/net */
    remove_proc_entry(PROC_EXTSIP, net->proc_net);
}

/**
 * Открытие последовательного файла на чтение
 * 
 * @param inode
 * @param file
 * @return 
 */
static int ct_open(struct inode *inode, struct file *file) {
    /* Операция последовательного чтения "файла" */
    return seq_open_net(inode, file, &ct_seq_ops, sizeof(struct ct_iter_state));
}

/**
 * Начало последовательного чтения
 * 
 * @param seq
 * @param pos
 * @return - реализация итератора на позиции *pos или NULL
 */
static void *ct_seq_start(struct seq_file *seq, loff_t *pos) __acquires(RCU) {
    void *v;

    rcu_read_lock();

    v = ct_get_idx(seq, *pos);

//    pr_info("EXTSIP: ct_seq_start(%pK, %lu) == %pK\n", seq, (unsigned long)*pos, v);

    return v;
}

/**
 * Продолжение последовательного чтения
 * 
 * @param s
 * @param v - итератор от предыдущего вызова
 * @param pos - желаемая новая позиция
 * @return - итератор в новой позиции или NULL
 */
static void *ct_seq_next(struct seq_file *s, void *v, loff_t *pos) {
    (*pos)++;

    do {
        v = ct_get_next(s, v);
    } while(v && !is_this_helper((struct nf_conntrack_tuple_hash *)v));

//    pr_info("EXTSIP: ct_seq_next(%pK, ..., %lu) == %llu\n", s, (unsigned long)*pos, (u64)v);

    return v;
}

/**
 * Завершение последовательного чтения
 * 
 * @param s
 * @param v - итератор от seq_start/seq_next
 */
static void ct_seq_stop(struct seq_file *s, void *v)  __releases(RCU) {
//    pr_info("EXTSIP: ct_seq_stop\n");
    rcu_read_unlock();
}

/**
 * Генерация отображаемых данных
 * 
 * @param s
 * @param v - итератор из seq_start или seq_next
 * @return 
 * 
 * Гарантируется, что отображаемый элемент обслуживается этим helper-ом
 * (т.е. он должен содержать nf_ct_extsip_master)
 */
static int ct_seq_show(struct seq_file *s, void *v) {
    struct extsip_callinfo *ci;
    int bkt;

    struct nf_conntrack_tuple_hash *hash = v;
    struct nf_conn *ct = nf_ct_tuplehash_to_ctrack(hash);

    /* Наши (helper's) private data, associated by connection */
    struct nf_ct_extsip_master *master;

    int n = 0;

    master = extsip_private_get(ct);

    rcu_read_lock();
    
    hash_for_each_rcu(master->callinfo, bkt, ci, ci_link) {
        if(n++) {
            seq_printf(s, " ");
        }
        
        seq_printf(s, "%s (%s)", ci->callid, sip_register_state_name(ci->register_state));
    }
    
    rcu_read_unlock();
    
    seq_printf(s, "\n");
    
    return 0;
}

static struct hlist_nulls_node *ct_get_idx(struct seq_file *seq, loff_t pos) {
    struct hlist_nulls_node *head = ct_get_first(seq);

//    pr_info("EXTSIP: ct_get_idx\n");

    while(head) {
        if(is_this_helper((struct nf_conntrack_tuple_hash *)head)) {
            if(!pos) {
                return head;
            }
            
            pos--;
        }
        
        head = ct_get_next(seq, head);
    }
    
    return NULL;
}

static struct hlist_nulls_node *ct_get_next(struct seq_file *seq,
                                            struct hlist_nulls_node *head) {
    struct net *net = seq_file_net(seq);
    struct ct_iter_state *st = seq->private;

//    pr_info("EXTSIP: ct_get_next\n");

    head = rcu_dereference(hlist_nulls_next_rcu(head));
    while(is_a_nulls(head)) {
        if (likely(get_nulls_value(head) == st->bucket)) {
            if (++st->bucket >= net->ct.htable_size) {
                return NULL;
            }
        }

        head = rcu_dereference(hlist_nulls_first_rcu(&net->ct.hash[st->bucket]));
    }
    
    return head;
}

static struct hlist_nulls_node *ct_get_first(struct seq_file *seq) {
    struct net *net = seq_file_net(seq);
    struct ct_iter_state *st = seq->private;
    struct hlist_nulls_node *n;

//    pr_info("EXTSIP: ct_get_first\n");

    for (st->bucket = 0;
         st->bucket < net->ct.htable_size;
         st->bucket++) {
        n = rcu_dereference(hlist_nulls_first_rcu(&net->ct.hash[st->bucket]));
        if (!is_a_nulls(n)) {
            return n;
        }
    }
    
    return NULL;
}

static const char *sip_register_state_name(enum sip_register_states state) {
    switch(state) {
        case SIP_REGISTER_SENT:
            return "REGISTER_PROGRESS";
        case SIP_REGISTER_UNAUTHORIZED:
            return "REGISTER_PROGRESS_AUTH";
        case SIP_REGISTER_DENIED:
            return "REGISTER_PROGRESS_DENIED";
        case SIP_REGISTER_COMPLETE:
            return "REGISTERED";
        case SIP_UNREGISTER_SENT:
            return "UNREGISTER_PROGRESS";
        case SIP_UNREGISTER_UNAUTHORIZED:
            return "UNREGISTER_PROGRESS_AUTH";
        case SIP_UNREGISTER_DENIED:
            return "UNREGISTER_PROGRESS_DENIED";
        case SIP_UNREGISTER_COMPLETE:
            return "UNREGISTERED";
    }
    
    return "REGISTER_BUG";
}

/**
 * Проверка того, что соединение относится к нашему connection helper
 * 
 * @param hash
 * @return 
 */
static int is_this_helper(struct nf_conntrack_tuple_hash *hash) {
    struct nf_conn *ct = nf_ct_tuplehash_to_ctrack(hash);
    struct nf_conn_help *help = nfct_help(ct);
    int this_helper = 0;
    
    if(help) {
        struct nf_conntrack_helper __rcu *helper;
    
        rcu_read_lock();
        
        helper = rcu_dereference(help->helper);
        
        if(helper) {
            this_helper = (strncmp(helper->name, "extsip", NF_CT_HELPER_NAME_LEN) == 0);
        }
        
        rcu_read_unlock();
    }
    
    
    return this_helper;
}
