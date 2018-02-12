#include <linux/module.h>
#include <linux/types.h>
#include <linux/kernel.h>
#include <linux/jiffies.h>
#include <linux/string.h>
#include <linux/in.h>
#include <linux/bitops.h>
#include <linux/errno.h>
#include <linux/init.h>
#include <linux/skbuff.h>
#include <linux/slab.h>
#include <linux/prefetch.h>
#include <linux/vmalloc.h>
#include <net/netlink.h>
#include <net/pkt_sched.h>
#include <net/sock.h>
#include <net/tcp_states.h>
#include <net/tcp.h>

/*
 * Per flow structure, dynamically allocated
 */
struct gq_bucket {
	struct sk_buff	*head;		/* list of skbs for this flow : first skb */
	struct sk_buff  *tail;		/* last skb in the list */
	int		qlen;		/* number of packets in flow queue */
};

struct curvature_desc {
	unsigned long a;
	u64 c;
	u64 abcI;
	u64 wwI;
};

struct gradient_queue {
	unsigned long	       head_ts;
	u64                    grnlrty;
	u64                    num_of_elements;
	u64                    num_of_buckets;
	unsigned long          h, w, l, s;
	u64                    main_ts, max_ts, horizon;
	struct gq_bucket       *main_buckets;
};


struct gq_sched_data {
	struct gradient_queue  *gq;
	struct qdisc_watchdog  watchdog;
};

// Underlying linked list

inline struct sk_buff *gq_bucket_dequeue_head(struct gq_bucket *bucket)
{
	struct sk_buff *skb = bucket->head;

	if (skb) {
		bucket->head = skb->next;
		skb->next = NULL;
		bucket->qlen--;
	}
	return skb;
}

inline void bucket_queue_add(struct gq_bucket *bucket, struct sk_buff *skb)
{
	struct sk_buff *head = bucket->head;
	skb->next = NULL;
	bucket->qlen++;

	if (!head) {
		bucket->head = skb;
		bucket->tail = skb;
		return;
	}

	bucket->tail->next = skb;
	bucket->tail = skb;
}

// circular gradient queue
inline unsigned long time_to_index(struct gradient_queue *gq,
					unsigned long time) {
	return (time/gq->grnlrty) % gq->num_of_buckets;
}
inline void gq_push (struct gradient_queue *gq, struct sk_buff *skb) {
	unsigned long index = 0;

	if (skb->trans_time < gq->head_ts)
		skb->trans_time = gq->head_ts;
	if (skb->trans_time > gq->max_ts)
		skb->trans_time = gq->max_ts;

	index = time_to_index(gq, skb->trans_time);

	gq->num_of_elements++;

	bucket_queue_add(&(gq->main_buckets[index]), skb);
}

/*inline void get_min_index2 (struct gradient_queue *gq) {
	unsigned long index = time_to_index(gq, gq->head_ts);
	gq->main_ts = gq->head_ts;
	while (!gq->main_buckets[index].qlen && gq->main_ts <= gq->max_ts) {
		index++;
		index = index % gq->num_of_buckets;
		gq->main_ts += gq->grnlrty;
	}
}*/

inline unsigned long get_min_index (struct gradient_queue *gq, uint64_t now) {
	unsigned long index = time_to_index(gq, gq->head_ts);
	unsigned long index_now = time_to_index(gq, gq->head_ts);
	while (!gq->main_buckets[index].qlen && index < index_now) {
		//index++;
		//index = index % gq->num_of_buckets;
		gq->head_ts ++;
		index = time_to_index(gq, gq->head_ts);
	}
	return index;
}

inline struct sk_buff *gq_extract(struct gradient_queue *gq, uint64_t now) {
	unsigned long index = 0;
	struct sk_buff *ret_skb;

	if(!gq->num_of_elements) {
		gq->head_ts = now;
		gq->main_ts = now;
		gq->max_ts = now + gq->horizon;
		return NULL;
	}	

	index = get_min_index(gq, now);
		
	if (!gq->main_buckets[index].qlen)
		return NULL;

	gq->num_of_elements--;

	ret_skb = gq_bucket_dequeue_head(&(gq->main_buckets[index]));

	return ret_skb;
}

// qdisc api

static int gq_enqueue(struct sk_buff *skb, struct Qdisc *sch,
		      struct sk_buff **to_free)
{
	struct gq_sched_data *q = qdisc_priv(sch);
	u64 now = ktime_get_ns();

	if (!q->gq->num_of_elements) {
		q->gq->head_ts = now;
		q->gq->main_ts = now;
		q->gq->max_ts = now + q->gq->horizon;
	}

	if (unlikely(q->gq->num_of_elements >= sch->limit)) {
		return qdisc_drop(skb, sch, to_free);
	}

	qdisc_qstats_backlog_inc(sch, skb);

	if (skb->sk) {
		if (!skb->sk->sk_time_of_last_sent_pkt ||
			skb->sk->sk_time_of_last_sent_pkt < now)
			skb->sk->sk_time_of_last_sent_pkt = now;
		skb->trans_time = skb->sk->sk_time_of_last_sent_pkt;
	} else {
		skb->trans_time = now;
	}

	gq_push (q->gq, skb);

	sch->q.qlen++;

	return NET_XMIT_SUCCESS;
}

static struct sk_buff *gq_dequeue(struct Qdisc *sch)
{
	struct gq_sched_data *q = qdisc_priv(sch);
	u64 now = ktime_get_ns();
	struct sk_buff *skb;
	//u64 time_of_min_pkt;

	skb = gq_extract(q->gq, now);
	if(!skb) {	

		if (!(q->gq->num_of_elements))
			return NULL;

		//get_min_index2(q->gq);
		//time_of_min_pkt = q->gq->main_ts;

		//if (time_of_min_pkt > q->watchdog.last_expires
		//	&& time_of_min_pkt < now)
		//	return NULL;

		//qdisc_watchdog_schedule_ns(&q->watchdog, time_of_min_pkt);
		qdisc_watchdog_schedule_ns(&q->watchdog, now + q->gq->grnlrty);

		return NULL;
	}

	if (skb->sk) {
		u32 rate = skb->sk->sk_pacing_rate;
		if (rate != ~0U) {
			u64 len = ((u64)qdisc_pkt_len(skb)) * NSEC_PER_SEC;
			if (likely(rate))
				do_div(len, rate);
			if (unlikely(len > NSEC_PER_SEC))
				len = NSEC_PER_SEC;
			if (now > skb->trans_time && (((now - skb->trans_time) / len) > 25)) {
				skb->sk->sk_time_of_last_sent_pkt += now - skb->trans_time;
			}
			skb->sk->sk_time_of_last_sent_pkt += len;
		}
	}

	sch->q.qlen--;

	qdisc_qstats_backlog_dec(sch, skb);
	qdisc_bstats_update(sch, skb);

	return skb;
}

static void gq_reset(struct Qdisc *sch)
{
	struct gq_sched_data *q = qdisc_priv(sch);

	sch->q.qlen = 0;
	sch->qstats.backlog = 0;

	memset(q->gq->main_buckets, 0,
		sizeof(struct gq_bucket) * q->gq->num_of_buckets);
}

static int gq_change(struct Qdisc *sch, struct nlattr *opt)
{
	return -1;
}

static void gq_destroy(struct Qdisc *sch)
{
	struct gq_sched_data *q = qdisc_priv(sch);
	struct gradient_queue *gq_p = q->gq;

	gq_reset(sch);

	kvfree(gq_p->main_buckets);
	kvfree(gq_p);

	qdisc_watchdog_cancel(&q->watchdog);
}

// initializer
static int gq_init(struct Qdisc *sch, struct nlattr *opt)
{
	struct gq_sched_data *q = qdisc_priv(sch);
	struct gradient_queue *gq_p;
	int i = 0;
	u64 granularity =        10000;
	u64 horizon =      20000000000;
	u64 now = ktime_get_ns();

	gq_p = kmalloc_node(sizeof(struct gradient_queue),
			GFP_KERNEL | __GFP_REPEAT | __GFP_NOWARN,
			netdev_queue_numa_node_read(sch->dev_queue));

	gq_p->head_ts = now;
	gq_p->main_ts = now;
	gq_p->max_ts = now + horizon;

	gq_p->horizon = horizon;
	gq_p->grnlrty = granularity;
	gq_p->num_of_buckets = horizon / granularity;
	gq_p->num_of_elements = 0;

	gq_p->main_buckets = kmalloc_node(
			sizeof(struct gq_bucket) * gq_p->num_of_buckets,
			GFP_KERNEL | __GFP_REPEAT | __GFP_NOWARN,
			netdev_queue_numa_node_read(sch->dev_queue));

	if(!gq_p->main_buckets)
		gq_p->main_buckets = vmalloc_node(
			sizeof(struct gq_bucket) * gq_p->num_of_buckets,
			netdev_queue_numa_node_read(sch->dev_queue));

	if(!gq_p->main_buckets)
		return -1;

	for (i =0; i< gq_p->num_of_buckets; i++) {
		gq_p->main_buckets[i].qlen = 0;
		gq_p->main_buckets[i].head = NULL;
		gq_p->main_buckets[i].tail = NULL;
		
	}

	q->gq = gq_p;
	sch->limit		= 80000;
	qdisc_watchdog_init(&q->watchdog, sch);

	return 0;
}

static int gq_dump(struct Qdisc *sch, struct sk_buff *skb)
{
	return -1;
}

static int gq_dump_stats(struct Qdisc *sch, struct gnet_dump *d)
{
	struct tc_fq_qd_stats st;

	return gnet_stats_copy_app(d, &st, sizeof(st));
}

static struct Qdisc_ops gq_qdisc_ops __read_mostly = {
	.id		=	"gq",
	.priv_size	=	sizeof(struct gq_sched_data),

	.enqueue	=	gq_enqueue,
	.dequeue	=	gq_dequeue,
	.peek		=	qdisc_peek_dequeued,
	.init		=	gq_init,
	.reset		=	gq_reset,
	.destroy	=	gq_destroy,
	.change		=	gq_change,
	.dump		=	gq_dump,
	.dump_stats	=	gq_dump_stats,
	.owner		=	THIS_MODULE,
};

static int __init gq_module_init(void)
{
	int ret;

	ret = register_qdisc(&gq_qdisc_ops);

	return ret;
}

static void __exit gq_module_exit(void)
{
	unregister_qdisc(&gq_qdisc_ops);
}

module_init(gq_module_init)
module_exit(gq_module_exit)
MODULE_AUTHOR("Ahmed Saeed");
MODULE_LICENSE("GPL");
