#include <linux/crc32.h>

#include <net/netfilter/nf_conntrack_helper.h>

#include "dpi_sip.h"

/* seed для вычисления hash на основе CRC32 */
#define HASH_CRC_SEED   0xEDB88320

/* Forward local function declarations */
static void callinfo_free_rcu(struct rcu_head *head);
static struct extsip_callinfo *extsip_callinfo_alloc(const char *callid, size_t callidlen);
static void callid_expired(unsigned long d);
static void extsip_callinfo_free(struct extsip_callinfo *callinfo);
static u32 extsip_callid_hash(const unsigned char *callid, size_t callidlen);

/**
 * Установить время жизни callinfo 
 * @param ci
 * @param msec
 */
void set_callinfo_lifetime(struct extsip_callinfo *ci, const unsigned int msec) {
    /* Т.к. таймер ссылается на callinfo, увеличиваем кол-во ссылок */
    atomic_inc(&ci->use);
    
    /* Удаляем старый таймер, если он был */
    remove_callinfo_timer(ci);
    
    /* Устанавливаем значение таймаута и запускаем таймер */
    mod_timer(&ci->expired, jiffies + msecs_to_jiffies(msec));
    
//    pr_info("Set %ums lifetime for callid=%s\n", msec, ci->callid);
}

/**
 * Удаление таймера ограничения жизни callinfo
 * 
 * @param ci
 */
void remove_callinfo_timer(struct extsip_callinfo *ci) {
    if(del_timer(&ci->expired)) {
//        pr_info("remove_callinfo_timer(0x%llx) with ACTIVE TIMER!\n", (u64)ci);
        
        /* В момент удаления таймера он был активен, уменьшаем кол-во ссылок */
        callinfo_put(ci);
    }
}

/**
 * Получить существующую структуру callinfo или добавить новую по значению callid
 * 
 * @param ct
 * @param callid
 * @param callidlen
 * @return 
 * 
 * После окончания использования данной структуры необходимо уменьшить счетчик
 * использований при помощи вызова функции callinfo_put(...)
 */
struct extsip_callinfo *extsip_callinfo_get(struct nf_conn *ct, 
                                            const char *callid, size_t callidlen) {
    struct extsip_callinfo *ci;
    
    /* Наши (helper's) private data, associated by connection */
    struct nf_ct_extsip_master *master = extsip_private_get(ct);

    /* Вычисляем hash от callid */
    u32 hash = extsip_callid_hash(callid, callidlen);
    
    rcu_read_lock();
    
    /* Выборка всех элементов с совпадающим hash */
    hash_for_each_possible_rcu(master->callinfo, ci, ci_link, hash) {
        if(strlen(ci->callid) == callidlen) {
            /* Длина callid совпала... */
            if(0 == memcmp(ci->callid, callid, callidlen)) {
                /* Т.к. возвращаем указатель, то увеличиваем кол-во ссылок */
                atomic_inc(&ci->use);
                
                rcu_read_unlock();
                
//                pr_info("EXTSIP: extsip_callinfo_get existing callid=%s on ct=0x%llx\n", ci->callid, (u64)ct);
        
                /* callid совпал, возвращаем существующий элемент */
                return ci;
            }
        }
    }
    
    rcu_read_unlock();
    
    /* Это новый callid, создаем новый элемент */
    ci = extsip_callinfo_alloc(callid, callidlen);
    
    /* Т.к. возвращаем указатель, то увеличиваем кол-во ссылок */
    atomic_inc(&ci->use);
    
    spin_lock(&master->callinfo_lock);
    
    /* Добавляем вновь созданный элемент в таблицу */
    hash_add_rcu(master->callinfo, &ci->ci_link, hash);
    
    spin_unlock(&master->callinfo_lock);
    
//    pr_info("EXTSIP: extsip_callinfo_get new callid=%s on ct=0x%llx\n", ci->callid, (u64)ct);
                
    return ci;
}

/**
 * Выполнение удаления элемента extsip_callinfo
 * 
 * @param ci
 */
void callinfo_remove(struct extsip_callinfo *ci) {
    pr_info("EXTSIP: Remove from table Call-ID: %s\n", ci->callid);
    
    rcu_read_lock();

    /* Удаляем таймер времени жизни элемента */
    remove_callinfo_timer(ci);

    /* Удаляем элемент из таблицы */
    hash_del_rcu(&ci->ci_link);

    /* После удаления из таблицы уменьшаем кол-во ссылок */
    callinfo_put(ci);
    
    rcu_read_unlock();
}

/**
 * Уменьшение кол-ва ссылок на ресурс и освобождение его при необходимости
 * 
 * @param ci
 */
void callinfo_put(struct extsip_callinfo *ci) {
//    pr_info("callinfo_put(0x%llx) with usage count %d\n", (u64)ci, atomic_read(&ci->use));
    
    if(atomic_dec_and_test(&ci->use)) {
        /* Структуру можно освобождать после истечения RCU grace period */
        call_rcu(&ci->rcu, callinfo_free_rcu);
    }
}

/**
 * Получить helper's private data из nf_conn
 * 
 * @param ct
 * @return 
 * 
 * При необходимости выполняется инициализация hashtable.
 */
struct nf_ct_extsip_master *extsip_private_get(struct nf_conn *ct) {
    /* Наши (helper's) private data, associated by connection */
    struct nf_ct_extsip_master *master = nfct_help_data(ct);
    
    if(!test_and_set_bit(EXTSIP_MASTER_STATE_INIT_COMPLETE_BIT, &master->state)) {
        /* Требуется выполнить первоначальную инициализацию данных */
        spin_lock_init(&master->callinfo_lock);
        
        hash_init(master->callinfo);
        
        pr_info("EXTSIP: init hash table with ct=0x%llx master=0x%llx\n", (u64)ct, (u64)master);
    }
    
    return master;
}

/**
 * Вызывается после истечения RCU grace period
 * 
 * @param head
 */
static void callinfo_free_rcu(struct rcu_head *head) {
    struct extsip_callinfo *ci;

    ci = container_of(head, struct extsip_callinfo, rcu);

//    pr_info("EXTSIP: free RCU for Call-ID: %s\n", ci->callid);
    
    /* Выполнить освобождение ресурсов */
    extsip_callinfo_free(ci);
}

/**
 * Выделение ресурсов для структуры callinfo
 * 
 * @param callid
 * @param callidlen
 * @return 
 */
static struct extsip_callinfo *extsip_callinfo_alloc(const char *callid, size_t callidlen) {
    struct extsip_callinfo *new;

    new = kmem_cache_alloc(extsip_callinfo_cachep, GFP_ATOMIC);
    if (!new) {
        return NULL;
    }

    new->callid = kmalloc(callidlen + 1, GFP_ATOMIC);
    
    if(new->callid) {
        memcpy(new->callid, callid, callidlen);
        
        *(new->callid + callidlen) = 0;
    } else {
        kmem_cache_free(extsip_callinfo_cachep, new);
        
        return NULL;
    }

    /* В данный момент элемент еще не находится в таблице */
    INIT_HLIST_NODE(&new->ci_link);

    /* Т.к. возвращаем указатель, то устанавливаем кол-во ссылок на него */
    atomic_set(&new->use, 1);
    
    /* Инициализируем таймер, отслеживающий время жизни callid */
    setup_timer(&new->expired, callid_expired, (unsigned long)(void*)new);
    
    /* Регистрация не выполнена */
    new->register_state = SIP_UNREGISTER_COMPLETE;
    
    /* Таймаут 2000 мс - test!!! */
    set_callinfo_lifetime(new, 2000);
    
    return new;
}

/**
 * Вызывается при окончании времени жизни callid
 * 
 * @param d
 */
static void callid_expired(unsigned long d) {
    struct extsip_callinfo *ci = (struct extsip_callinfo *)d;
    
    pr_info("EXTSIP: Kill by timeout Call-ID: %s\n", ci->callid);
    
    /* Т.к. таймер сработал, уменьшаем кол-во ссылок на объект */
    callinfo_put(ci);
    
    /* Запрос удаления этого callid */
    callinfo_remove(ci);
}

/**
 * Освобождение ресурсов из структуры callinfo
 * 
 * @param callinfo
 */
static void extsip_callinfo_free(struct extsip_callinfo *callinfo) {
    WARN_ON(atomic_read(&callinfo->use) != 0);
    WARN_ON(timer_pending(&callinfo->expired));

    if(callinfo->callid) {
        pr_info("EXTSIP: Free resources for Call-ID: %s\n", callinfo->callid);

        kfree(callinfo->callid);
    }

    kmem_cache_free(extsip_callinfo_cachep, callinfo);
}

/**
 * Вычисление hash-функции по значению SIP Call-ID
 * 
 * @param callid
 * @param callidlen
 * @return 
 */
static u32 extsip_callid_hash(const unsigned char *callid, size_t callidlen) {
    return crc32(HASH_CRC_SEED, callid, callidlen);
}
