/*
 *
 */

/*
#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/netfilter.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/ctype.h>
#include <linux/inet.h>

#include <linux/skbuff.h>
#include <linux/in.h>
*/

#include <linux/module.h>
#include <linux/ctype.h>
#include <linux/proc_fs.h>
#include <asm/uaccess.h>

#include <linux/netfilter.h>
#include <net/netfilter/nf_conntrack.h>
#include <net/netfilter/nf_conntrack_core.h>
#include <net/netfilter/nf_conntrack_helper.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Chou Chifeng <cfchou@gmail.com>");
MODULE_DESCRIPTION("conntrack remover");
MODULE_ALIAS("rmct");

#define DEBUGP	printk
#define KFREE(x)	\
do {			\
	kfree(x);	\
	x = NULL;	\
} while (0)		\

#define CLEARANCE_INTERVAL	5

static unsigned int clearance_interval __read_mostly = CLEARANCE_INTERVAL;
module_param(clearance_interval, uint, 0600);
MODULE_PARM_DESC(clearance_interval, "interval in second to clear");

#define RMCT_LIST	"rmct_list"
static struct proc_dir_entry *rmct_entry = NULL;

static spinlock_t rmct_list_lock = SPIN_LOCK_UNLOCKED;
static LIST_HEAD(rmct_list);

static void rmct_work_func(struct work_struct *work);
static DECLARE_DELAYED_WORK(rmct_work, rmct_work_func);

struct rmct_criterion {
	struct list_head list;
	u_int32_t ip;
	u_int16_t port;
	u_int8_t proto;
};

// classic proc_fs
/* remove conntrack matching tuple.dst, presented as
 * network-endian proto:ip:port. proto: 0 for UDP, 1 for TCP.
 * e.g. tuple.dst UDP 10.7.1.115:80 would be:
 * bash>echo '0:0a070173:0050' >/proc/rmct_list
 * here it receives len == 16 bytes(extra '\n' pended)
 */
#define WRITE_ONCE_LEN	16
static int rmct_write(struct file *flip, char const __user *buff,
	unsigned long len, void *data)
{
	char cmd[WRITE_ONCE_LEN + 1];
	u_int32_t ip = 0;
	u_int16_t port = 0;
	u_int8_t proto = 0;
	
	struct rmct_criterion *rc = NULL;

	memset(cmd, 0, sizeof(cmd));

	DEBUGP(KERN_ALERT "[INFO] length %ld.\n", len);
	if (len != WRITE_ONCE_LEN) {
		DEBUGP(KERN_ALERT "[ERR] wrong length.\n");
		return -EFAULT;
	}

	if (copy_from_user(&cmd, buff, WRITE_ONCE_LEN)) {
		DEBUGP(KERN_ALERT "[ERR] copy_from_user.\n");
		return -EFAULT;
	}

	if (3 != sscanf(cmd, "%c:%x:%hx\n", &proto, &ip, &port)) {
		DEBUGP(KERN_ALERT "[ERR] wrong format.\n");
		return -EFAULT;
	}
	DEBUGP(KERN_ALERT "input %c:%x:%x\n", proto, ip, port);
	proto -= '0';
	/*
	if (port > htonl(65535)) {
		DEBUGP(KERN_ALERT "[ERR] wrong port.\n");
		return -EFAULT;
	}
	*/
	if (0 != proto && 1 != proto) {
		DEBUGP(KERN_ALERT "[ERR] wrong proto.\n");
		return -EFAULT;
	}

	if (NULL == (rc = kmalloc(sizeof(struct rmct_criterion), GFP_KERNEL))) {
		DEBUGP(KERN_ALERT "[ERR] kmalloc failed.\n");
		return -EFAULT;
		//return -ENOMEM;
	}

	memset(rc, 0, sizeof(struct rmct_criterion));
	INIT_LIST_HEAD(&rc->list);
	rc->ip = ip;
	rc->port = port;
	rc->proto = proto;

	spin_lock_bh(rmct_list_lock);
	list_add(&rc->list, &rmct_list);
	spin_unlock_bh(rmct_list_lock);

	// return total avoiding further callbacks 
	return len;
}

static int rmct_read(char *page, char **start, off_t off, int count, int *eof,
	void *data)
{
	int len = 0;
	char buf[WRITE_ONCE_LEN + 1];
	struct rmct_criterion *tmp = NULL;
	page[0] = 0;
	spin_lock_bh(rmct_list_lock);
	list_for_each_entry(tmp, &rmct_list, list) {
		if (PAGE_SIZE <= len + WRITE_ONCE_LEN) {
			DEBUGP(KERN_ALERT "[WARNING] too large\n");
			break;
		}
		len += snprintf(buf, sizeof(buf), "%c:%08x:%04x\n",
			tmp->proto + '0', tmp->ip, tmp->port);
		strcat(page, buf);
	}
	spin_unlock_bh(rmct_list_lock);
	return len;
}

static void find_conntrack_put(struct rmct_criterion const *rc)
{
	struct nf_conntrack_tuple tp;
	struct nf_conn *ct = NULL;
	struct nf_conntrack_tuple_hash *hh = NULL;
	struct hlist_node *nn = NULL;
	int found = 0;
	int i = 0;
	
	memset(&tp, 0, sizeof(tp));
	tp.dst.u3.ip = htonl(rc->ip);
	tp.dst.u.tcp.port = htons(rc->port);
	tp.dst.protonum = rc->proto ? 0x06 : 0x11;

	DEBUGP(KERN_ALERT "matching dst(%hd): " NIPQUAD_FMT ":%d\n",
		tp.dst.protonum, NIPQUAD(tp.dst.u3.all), ntohs(tp.dst.u.all));
	// reference to:
	// nf_conntrack_find_get
	// nf_conntrack_set_hashsize
	// nf_ct_iterate_cleanup
	do {
		found = 0;
		spin_lock_bh(&nf_conntrack_lock);
		for (i = 0; i < nf_conntrack_htable_size; i++) {
			hlist_for_each_entry(hh, nn, &nf_conntrack_hash[i],
				hnode) {
				//
				DEBUGP(KERN_ALERT "src: " NIPQUAD_FMT ":%d -> "
					"dst(%hd): " NIPQUAD_FMT ":%d\n",
					NIPQUAD(hh->tuple.src.u3.all),
					ntohs(hh->tuple.src.u.all),
					hh->tuple.dst.protonum,
					NIPQUAD(hh->tuple.dst.u3.all),
					ntohs(hh->tuple.dst.u.all));
				if (!__nf_ct_tuple_dst_equal(&hh->tuple, &tp)) {
					continue;
				}
				ct = nf_ct_tuplehash_to_ctrack(hh);
				if (unlikely(!atomic_inc_not_zero(
					&ct->ct_general.use)))
					continue;
				found = 1;
			}
		}
		spin_unlock_bh(&nf_conntrack_lock);
		if (!found) {
			DEBUGP(KERN_ALERT "[INFO] found none ;(\n");
			break;
		}
		DEBUGP(KERN_ALERT "[INFO] found one ;p\n");
		if (del_timer(&ct->timeout))
			ct->timeout.function((unsigned long)ct);
		nf_ct_put(ct);
	} while (found);
}

static void rmct_work_func(struct work_struct *work)
{
	struct rmct_criterion *rc = NULL;

	while (1) {
		spin_lock_bh(rmct_list_lock);
		if (list_empty(&rmct_list)) {
			spin_unlock_bh(rmct_list_lock);
			break;
		}
		rc = list_entry((&rmct_list)->next, struct rmct_criterion,
			list); 
		list_del_init(&rc->list);
		spin_unlock_bh(rmct_list_lock);

		DEBUGP(KERN_ALERT "[INFO] kill by criterion: %c:%x:%x\n",
			rc->proto + '0', rc->ip, rc->port);
		find_conntrack_put(rc);
		KFREE(rc);
	}
	if (clearance_interval) {
		// to keventd
		schedule_delayed_work(&rmct_work, clearance_interval * HZ);
	}
}

static void rmct_fini(void)
{
	struct rmct_criterion *rc, *tmp;
	DEBUGP(KERN_ALERT "[INFO] rmct_fini\n");
	remove_proc_entry(RMCT_LIST, NULL);
	spin_lock_bh(rmct_list_lock);
	list_for_each_entry_safe(rc, tmp, &rmct_list, list) {
		list_del_init(&rc->list);
		KFREE(rc);
	}
	spin_unlock_bh(rmct_list_lock);
	if (clearance_interval) {
		cancel_delayed_work_sync(&rmct_work);
	}
}

static int __init rmct_init(void)
{
	DEBUGP(KERN_ALERT "[INFO] rmct_init clearance_interval=%u\n",
		clearance_interval);

	if (NULL == (rmct_entry = create_proc_entry(RMCT_LIST, S_IWUSR,
		NULL))) {
		DEBUGP(KERN_ALERT "[ERR] create_proc_entry %s failed!\n",
			RMCT_LIST);
		goto fail_init;
	}
	rmct_entry->read_proc = rmct_read;
	rmct_entry->write_proc = rmct_write;

	if (clearance_interval) {
		// to keventd
		schedule_delayed_work(&rmct_work, clearance_interval * HZ);
	}
	return 0;
fail_init:
	rmct_fini();
	return -ENOMEM;
}

module_init(rmct_init);
module_exit(rmct_fini);
