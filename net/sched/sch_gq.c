/*
 * net/sched/sch_fq.c Fair Queue Packet Scheduler (per flow pacing)
 *
 *  Copyright (C) 2013-2015 Eric Dumazet <edumazet@google.com>
 *
 *	This program is free software; you can redistribute it and/or
 *	modify it under the terms of the GNU General Public License
 *	as published by the Free Software Foundation; either version
 *	2 of the License, or (at your option) any later version.
 *
 *  Meant to be mostly used for locally generated traffic :
 *  Fast classification depends on skb->sk being set before reaching us.
 *  If not, (router workload), we use rxhash as fallback, with 32 bits wide hash.
 *  All packets belonging to a socket are considered as a 'flow'.
 *
 *  Flows are dynamically allocated and stored in a hash table of RB trees
 *  They are also part of one Round Robin 'queues' (new or old flows)
 *
 *  Burst avoidance (aka pacing) capability :
 *
 *  Transport (eg TCP) can set in sk->sk_pacing_rate a rate, enqueue a
 *  bunch of packets, and this packet scheduler adds delay between
 *  packets to respect rate limitation.
 *
 *  enqueue() :
 *   - lookup one RB tree (out of 1024 or more) to find the flow.
 *     If non existent flow, create it, add it to the tree.
 *     Add skb to the per flow list of skb (fifo).
 *   - Use a special fifo for high prio packets
 *
 *  dequeue() : serves flows in Round Robin
 *  Note : When a flow becomes empty, we do not immediately remove it from
 *  rb trees, for performance reasons (its expected to send additional packets,
 *  or SLAB cache will reuse socket for another flow)
 */

#include <linux/module.h>
#include <linux/types.h>
#include <linux/kernel.h>
#include <linux/jiffies.h>
#include <linux/string.h>
#include <linux/in.h>
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
	struct sk_buff *tail;	/* last skb in the list */
	int		qlen;		/* number of packets in flow queue */
};

struct curvature_desc {
	u64 a;
	u64 b;
	u64 c;
	u64 abcI;
	u64 wwI;
};

struct precalc_a_b {
	u64 a;
	u64 b;
};

struct gradient_queue {
	u64 head_ts;
	u64 grnlrty;
	u64 num_of_elements;
	u64 num_of_buckets;
	u64 side;
	u64 h, w, l, s;
	struct gq_bucket *buckets;
	struct curvature_desc *meta1;
	struct curvature_desc *meta2;
	struct precalc_a_b *meta_tmp;
};


struct gq_sched_data {
	u64		time_next_delayed_wake_up;

	struct gradient_queue *gq;
	struct qdisc_watchdog watchdog;
};

// Underlying linked list

static struct sk_buff *gq_bucket_dequeue_head(struct gq_bucket *bucket)
{
	struct sk_buff *skb = bucket->head;

	if (skb) {
		bucket->head = skb->next;
		skb->next = NULL;
		bucket->qlen--;
	}
	return skb;
}

static void bucket_queue_add(struct gq_bucket *bucket, struct sk_buff *skb)
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

// Gradient queue maintenance

struct curvature_desc *gq_side(struct gradient_queue *gq, uint64_t *in_index) {
	uint64_t ts_index = gq->head_ts;
	ts_index = gq->num_of_buckets - ts_index - 1;
	if ((int64_t)ts_index < 0)
		ts_index = ts_index + gq->num_of_buckets * (gq->head_ts/gq->num_of_buckets + 1);
	ts_index = ts_index % gq->num_of_buckets;

	if (ts_index >= *in_index) {
		if (*in_index >= gq->num_of_buckets / 2) {
			return gq->meta1;
		} else {
			return gq->meta2;
		}
	} else {
		if (*in_index >= gq->num_of_buckets / 2 && ts_index >= gq->num_of_buckets / 2) {
			*in_index = 0;
			return gq->meta2;
		} else if (*in_index < gq->num_of_buckets / 2 && ts_index < gq->num_of_buckets / 2) {
			*in_index = gq->num_of_buckets / 2;
			return gq->meta1;
		} else {
			return gq->meta1;
		}
	}
}

void gq_inc_meta(struct gradient_queue *gq, uint64_t *index) {
	struct curvature_desc *meta;
	int i = 0;
	int done = 0;

	meta = gq_side(gq, index);

	if (!gq->buckets[*index].qlen) {
		uint64_t parentI = ((gq->s + *index - 1) / gq->w);
		uint64_t wI = (gq->s + *index - 1) % gq->w;
		for (i = 0; i < gq->l; i++) {
			if (!done) {
				meta[parentI].a += gq->meta_tmp[wI].a;
				meta[parentI].b += gq->meta_tmp[wI].b;
			}
			meta[parentI].c++;
			if(meta[parentI].c > 1)
				done = 1;

			wI = meta[parentI].wwI;
			parentI = meta[parentI].abcI;
		}
	}
}

void gq_dec_meta(struct gradient_queue *gq, uint64_t *index) {
	struct curvature_desc *meta;
	int i = 0;
	int done = 0;

	meta = gq_side(gq, index);

	if (!gq->buckets[*index].qlen) {
		uint64_t parentI = ((gq->s + *index - 1) / gq->w);
		uint64_t wI = (gq->s + *index - 1) % gq->w;
		for (i = 0; i < gq->l; i++) {
			if (!done) {
				meta[parentI].a -= gq->meta_tmp[wI].a;
				meta[parentI].b -= gq->meta_tmp[wI].b;
			}
			meta[parentI].c--;
			if (meta[parentI].c > 0)
				done = 1;

			wI = meta[parentI].wwI;
			parentI = meta[parentI].abcI;
		}
	}
}

// Timing Wheel wrapper

void gq_push (struct gradient_queue *gq, struct sk_buff *skb, uint64_t ts) {
	uint64_t index = 0;
	int im = 0;
	ts = ts / gq->grnlrty;
	if (ts <= gq->head_ts) {
		ts = gq->head_ts;
		printk(KERN_DEBUG "SCHED IN PAST\n");
	} else if (ts > gq->head_ts + gq->num_of_buckets - 1) {
		ts = gq->head_ts + gq->num_of_buckets - 1;
		printk(KERN_DEBUG "HORIZON NOT ENOUGH, %ld, %ld\n", ts, gq->head_ts, gq->head_ts + gq->num_of_buckets - 1);
	}
	gq->num_of_elements++;
	im = gq->num_of_buckets - ts - 1;
	if (im < 0)
		im = im + gq->num_of_buckets * (gq->head_ts/gq->num_of_buckets + 1);
	index = im % gq->num_of_buckets;
	gq_inc_meta(gq, &index);
	bucket_queue_add(&(gq->buckets[index]), skb);
}

static struct sk_buff *gq_extract(struct gradient_queue *gq, uint64_t now) {
	now = now / gq->grnlrty;
	while (now >= gq->head_ts) {
		int len;
		uint64_t index = gq->head_ts;
		index = gq->num_of_buckets - index - 1;

		if ((int64_t)index < 0)
			index = index + gq->num_of_buckets * (gq->head_ts/gq->num_of_buckets + 1);
		index = index % gq->num_of_buckets;

		len = gq->buckets[index].qlen;
		if (!len) {
			gq->head_ts++;
		} else {
			struct sk_buff *tmp = gq_bucket_dequeue_head(&(gq->buckets[index]));
			gq_dec_meta(gq, &index);

			gq->num_of_elements--;
			return tmp;
		}
	}
	return NULL;
}


int64_t gq_get_min_index(struct gradient_queue *gq) {
	int64_t I = 0, i = 0;
	struct curvature_desc *meta;
	int64_t ts_index = gq->head_ts;
	ts_index = gq->num_of_buckets - ts_index - 1;
	if (ts_index < 0)
		ts_index = ts_index + gq->num_of_buckets * (gq->head_ts/gq->num_of_buckets + 1);
	ts_index = ts_index % gq->num_of_buckets;

	if (ts_index >= gq->num_of_buckets / 2 && gq->meta1[0].c > 0) {
		meta = gq->meta1;
	} else if (gq->meta2[0].c > 0) {
		meta = gq->meta2;
	} else if (gq->meta2[0].c <= 0 && gq->meta1[0].c <= 0){
		//printf("empty queue! %ld\n", gq->num_of_elements);
		return ts_index;
	} else if (gq->meta2[0].c <= 0) {
		return 0;
	} else if (gq->meta2[0].c <= 0) {
		return gq->num_of_buckets / 2;
	} else {
		//printf("SHOULD NEVER HAPPEN\n");
	}

	I = ((meta[0].b+meta[0].a-1)/(meta[0].a)) + 1;
	for (i = 1; i < gq->l; i++) {
		I = gq->w * I + ((meta[I].b+meta[I].a-1)/meta[I].a) + 1;
	}
	return I - gq->s;
}

int64_t gq_index_to_ts (struct gradient_queue *gq, int64_t index) {
	int64_t l = 0, p = 0;
	l = (gq->num_of_buckets - index - 1);
	p = gq->head_ts / gq->num_of_buckets;
	while (p > 0) {
		l += gq->num_of_buckets;
		p--;
	}
	return l * gq->grnlrty;
}

// initializer

unsigned int log_approx(uint32_t v) {
	const unsigned int b[] = {0x2, 0xC, 0xF0, 0xFF00, 0xFFFF0000};
	const unsigned int S[] = {1, 2, 4, 8, 16};
	int i;

	unsigned int r = 0; // result of log2(v) will go here
	for (i = 4; i >= 0; i--) // unroll for speed...
	{
  	if (v & b[i])
  	{
    	v >>= S[i];
    	r |= S[i];
  	}
	}
	return r;
}

static int gq_enqueue(struct sk_buff *skb, struct Qdisc *sch,
		      struct sk_buff **to_free)
{
	struct gq_sched_data *q = qdisc_priv(sch);
	u64 tx_time, now = ktime_get_ns();

	if (unlikely(sch->q.qlen >= sch->limit))
		return qdisc_drop(skb, sch, to_free);

	qdisc_qstats_backlog_inc(sch, skb);
	if (skb->trans_time) {
		printk(KERN_DEBUG "insertion time %ld\n", skb->trans_time);
		tx_time = skb->trans_time;
	} else {
		tx_time = now;
	}

	gq_push (q->gq, skb, tx_time);

	sch->q.qlen++;

	return NET_XMIT_SUCCESS;
}

static struct sk_buff *gq_dequeue(struct Qdisc *sch)
{
	struct gq_sched_data *q = qdisc_priv(sch);
	u64 tx_time, now = ktime_get_ns();
	struct sk_buff *skb;

	skb = gq_extract(q->gq, now);
	if(!skb) {
		printk(KERN_DEBUG "NO PACKETS IN GQ\n");
		if (q->gq->num_of_elements) {
			qdisc_watchdog_cancel(&q->watchdog);
			tx_time = gq_index_to_ts(q->gq, gq_get_min_index(q->gq));
			qdisc_watchdog_schedule_ns(&q->watchdog, tx_time);
			q->time_next_delayed_wake_up = tx_time;
		}
		return NULL;
	}

	qdisc_qstats_backlog_dec(sch, skb);
	qdisc_bstats_update(sch, skb);
	return skb;
}

static void gq_reset(struct Qdisc *sch)
{
	struct gq_sched_data *q = qdisc_priv(sch);
	struct sk_buff *skb;

	sch->q.qlen = 0;
	sch->qstats.backlog = 0;

	while(q->gq->num_of_elements) {
		skb = gq_extract(q->gq, gq_index_to_ts(q->gq, gq_get_min_index(q->gq)));
	}
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

	kvfree(gq_p->buckets);
	kvfree(gq_p->meta1);
	kvfree(gq_p->meta2);
	kvfree(gq_p->meta_tmp);
	kvfree(gq_p);

	qdisc_watchdog_cancel(&q->watchdog);
}

static int gq_init(struct Qdisc *sch, struct nlattr *opt)
{
	struct gq_sched_data *q = qdisc_priv(sch);
	struct gradient_queue *gq_p;
	int i = 0;
	u64 granularity = 10000;
	u64 horizon = 1000000000;
	u32 base = 32;
	u64 now = ktime_get_ns();

	gq_p = kmalloc_node(sizeof(struct gradient_queue),
			GFP_KERNEL | __GFP_REPEAT | __GFP_NOWARN,
			netdev_queue_numa_node_read(sch->dev_queue));

	gq_p->head_ts = now / granularity;
	gq_p->grnlrty = granularity;
	gq_p->num_of_buckets = horizon / granularity;
	gq_p->num_of_elements = 0;
	gq_p->w = base;
	gq_p->l = ((log_approx(gq_p->num_of_buckets)
				+ log_approx(gq_p->w) - 1) / log_approx(gq_p->w));
	gq_p->s = 1;
	for (i = 0; i < gq_p->l; i++)
		gq_p->s *= gq_p->w;
	gq_p->s = (gq_p->s - 1) / (gq_p->w - 1);

	gq_p->buckets = kmalloc_node(sizeof(struct gq_bucket) * gq_p->num_of_buckets,
			GFP_KERNEL | __GFP_REPEAT | __GFP_NOWARN,
			netdev_queue_numa_node_read(sch->dev_queue));

	gq_p->meta1 = kmalloc_node(sizeof(struct curvature_desc) * gq_p->s,
			GFP_KERNEL | __GFP_REPEAT | __GFP_NOWARN,
			netdev_queue_numa_node_read(sch->dev_queue));
	gq_p->meta2 = kmalloc_node(sizeof(struct curvature_desc) * gq_p->s,
			GFP_KERNEL | __GFP_REPEAT | __GFP_NOWARN,
			netdev_queue_numa_node_read(sch->dev_queue));
	memset(gq_p->meta1, 0, sizeof(struct curvature_desc)*gq_p->s);
	memset(gq_p->meta2, 0, sizeof(struct curvature_desc)*gq_p->s);

	gq_p->meta_tmp = kmalloc_node(sizeof(struct precalc_a_b) * (gq_p->w + 1),
			GFP_KERNEL | __GFP_REPEAT | __GFP_NOWARN,
			netdev_queue_numa_node_read(sch->dev_queue));

	for (i = 0; i <= base; i++) {
		if (!i)
			gq_p->meta_tmp[i].a = 1;
		else
			gq_p->meta_tmp[i].a = gq_p->meta_tmp[i-1].a * 2;
		gq_p->meta_tmp[i].b = i * gq_p->meta_tmp[i].a;
	}
	for (i = gq_p->s - 1; i >= 0; i--) {
		gq_p->meta1[i].abcI = ((i - 1) / gq_p->w);
		gq_p->meta1[i].wwI = (i-1) % gq_p->w;
		gq_p->meta2[i].abcI = ((i - 1) / gq_p->w);
		gq_p->meta2[i].wwI = (i-1) % gq_p->w;
	}
	q->gq = gq_p;
	sch->limit		= 10000;
	q->time_next_delayed_wake_up = now;
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
