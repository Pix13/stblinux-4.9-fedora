// SPDX-License-Identifier: GPL-2.0
/*
 * System Control and Management Interface (SCMI) Message Protocol driver
 *
 * SCMI Message Protocol is used between the System Control Processor(SCP)
 * and the Application Processors(AP). The Message Handling Unit(MHU)
 * provides a mechanism for inter-processor communication between SCP's
 * Cortex M3 and AP.
 *
 * SCP offers control and management of the core/cluster power states,
 * various power domain DVFS including the core/cluster, certain system
 * clocks configuration, thermal sensors and many others.
 *
 * Copyright (C) 2018 ARM Ltd.
 */

#include <linux/bitmap.h>
#include <linux/export.h>
#include <linux/io.h>
#include <linux/kernel.h>
#include <linux/ktime.h>
#include <linux/hashtable.h>
#include <linux/mailbox_client.h>
#include <linux/module.h>
#include <linux/of_address.h>
#include <linux/of_device.h>
#include <linux/processor.h>
#include <linux/semaphore.h>
#include <linux/slab.h>

#include "common.h"

#define MSG_ID_SHIFT		0
#define MSG_ID_MASK		0xff
#define MSG_TYPE_SHIFT		8
#define MSG_TYPE_MASK		0x3
#define MSG_PROTOCOL_ID_SHIFT	10
#define MSG_PROTOCOL_ID_MASK	0xff
#define MSG_TOKEN_ID_SHIFT	18
#define MSG_TOKEN_ID_MASK	0x3ff

#define MSG_TYPE_COMMAND	0
#define MSG_TYPE_DELAYED	2
#define MSG_TYPE_NOTIFY		3

#define MSG_XTRACT_ID(header)	\
	(((header) >> MSG_ID_SHIFT) & MSG_ID_MASK)
#define MSG_XTRACT_TYPE(header)	\
	(((header) >> MSG_TYPE_SHIFT) & MSG_TYPE_MASK)
#define MSG_XTRACT_PROT_ID(header)	\
	(((header) >> MSG_PROTOCOL_ID_SHIFT) & MSG_PROTOCOL_ID_MASK)
#define MSG_XTRACT_TOKEN(header)	\
	(((header) >> MSG_TOKEN_ID_SHIFT) & MSG_TOKEN_ID_MASK)
#define MSG_TOKEN_MAX		(MSG_TOKEN_ID_MASK + 1)

enum scmi_error_codes {
	SCMI_SUCCESS = 0,	/* Success */
	SCMI_ERR_SUPPORT = -1,	/* Not supported */
	SCMI_ERR_PARAMS = -2,	/* Invalid Parameters */
	SCMI_ERR_ACCESS = -3,	/* Invalid access/permission denied */
	SCMI_ERR_ENTRY = -4,	/* Not found */
	SCMI_ERR_RANGE = -5,	/* Value out of range */
	SCMI_ERR_BUSY = -6,	/* Device busy */
	SCMI_ERR_COMMS = -7,	/* Communication Error */
	SCMI_ERR_GENERIC = -8,	/* Generic Error */
	SCMI_ERR_HARDWARE = -9,	/* Hardware Error */
	SCMI_ERR_PROTOCOL = -10,/* Protocol Error */
	SCMI_ERR_MAX
};

/* List of all  SCMI devices active in system */
static LIST_HEAD(scmi_list);
/* Protection for the entire list */
static DEFINE_MUTEX(scmi_list_mutex);
/* Track the unique id for the transfers for debug & profiling purpose */
static atomic_t transfer_last_id;

static int max_rx_timeout_ms;
module_param(max_rx_timeout_ms, int, 0664);

static struct scmi_xfer *scmi_one_xfer_get(const struct scmi_handle *handle,
					   bool set_pending);

/**
 * struct scmi_xfers_info - Structure to manage transfer information
 *
 * @xfer_alloc_table: Bitmap table for allocated messages.
 *	Index of this bitmap table is also used for message
 *	sequence identifier.
 * @xfer_lock: Protection for message allocation
 * @free_xfers: A free list for available to use xfers. It is initialized with
 *		a number of xfers equal to the maximum allowed in-flight
 *		messages.
 * @pending_xfers: An hashtable, indexed by msg_hdr.seq, used to keep all the
 *		   currently in-flight messages.
 */
struct scmi_xfers_info {
	unsigned long *xfer_alloc_table;
	/* protect transfer allocation */
	spinlock_t xfer_lock;
	struct hlist_head free_xfers;
	DECLARE_HASHTABLE(pending_xfers, SCMI_PENDING_XFERS_HT_ORDER_SZ);
};

/**
 * struct scmi_desc - Description of SoC integration
 *
 * @max_rx_timeout_ms: Timeout for communication with SoC (in Milliseconds)
 * @max_msg: Maximum number of messages that can be pending
 *	simultaneously in the system
 * @max_msg_size: Maximum size of data per message that can be handled.
 */
struct scmi_desc {
	int max_rx_timeout_ms;
	int max_msg;
	int max_msg_size;
};

/**
 * struct scmi_chan_info - Structure representing a SCMI channel informfation
 *
 * @cl: Mailbox Client
 * @chan: Transmit/Receive mailbox channel
 * @payload: Transmit/Receive mailbox channel payload area
 * @dev: Reference to device in the SCMI hierarchy corresponding to this
 *	 channel
 */
struct scmi_chan_info {
	struct mbox_client cl;
	struct mbox_chan *chan;
	void __iomem *payload;
	struct device *dev;
	struct scmi_handle *handle;
};

/**
 * struct scmi_info - Structure representing a  SCMI instance
 *
 * @dev: Device pointer
 * @desc: SoC description for this instance
 * @handle: Instance of SCMI handle to send to clients
 * @version: SCMI revision information containing protocol version,
 *	implementation version and (sub-)vendor identification.
 * @minfo: Message info
 * @tx_idr: IDR object to map protocol id to channel info pointer
 * @protocols_imp: list of protocols implemented, currently maximum of
 *	MAX_PROTOCOLS_IMP elements allocated by the base protocol
 * @node: list head
 * @users: Number of users of this instance
 */
struct scmi_info {
	struct device *dev;
	const struct scmi_desc *desc;
	struct scmi_revision_info version;
	struct scmi_handle handle;
	struct scmi_xfers_info minfo;
	struct idr tx_idr;
	u8 *protocols_imp;
	struct list_head node;
	int users;
};

#define client_to_scmi_chan_info(c) container_of(c, struct scmi_chan_info, cl)
#define handle_to_scmi_info(h)	container_of(h, struct scmi_info, handle)

/*
 * SCMI specification requires all parameters, message headers, return
 * arguments or any protocol data to be expressed in little endian
 * format only.
 */
struct scmi_shared_mem {
	__le32 reserved;
	__le32 channel_status;
#define SCMI_SHMEM_CHAN_STAT_CHANNEL_ERROR	BIT(1)
#define SCMI_SHMEM_CHAN_STAT_CHANNEL_FREE	BIT(0)
	__le32 reserved1[2];
	__le32 flags;
#define SCMI_SHMEM_FLAG_INTR_ENABLED	BIT(0)
	__le32 length;
	__le32 msg_header;
	u8 msg_payload[0];
};

static const int scmi_linux_errmap[] = {
	/* better than switch case as long as return value is continuous */
	0,			/* SCMI_SUCCESS */
	-EOPNOTSUPP,		/* SCMI_ERR_SUPPORT */
	-EINVAL,		/* SCMI_ERR_PARAM */
	-EACCES,		/* SCMI_ERR_ACCESS */
	-ENOENT,		/* SCMI_ERR_ENTRY */
	-ERANGE,		/* SCMI_ERR_RANGE */
	-EBUSY,			/* SCMI_ERR_BUSY */
	-ECOMM,			/* SCMI_ERR_COMMS */
	-EIO,			/* SCMI_ERR_GENERIC */
	-EREMOTEIO,		/* SCMI_ERR_HARDWARE */
	-EPROTO,		/* SCMI_ERR_PROTOCOL */
};

static inline int scmi_to_linux_errno(int errno)
{
	if (errno < SCMI_SUCCESS && errno > SCMI_ERR_MAX)
		return scmi_linux_errmap[-errno];
	return -EIO;
}

/**
 * scmi_dump_header_dbg() - Helper to dump a message header.
 *
 * @dev: Device pointer corresponding to the SCMI entity
 * @hdr: pointer to header.
 */
static inline void scmi_dump_header_dbg(struct device *dev,
					struct scmi_msg_hdr *hdr)
{
	dev_dbg(dev, "Command ID: %x Sequence ID: %x Protocol: %x\n",
		hdr->id, hdr->seq, hdr->protocol_id);
}

static void scmi_fetch_response(struct scmi_xfer *xfer,
				struct scmi_shared_mem __iomem *mem)
{
	xfer->hdr.status = ioread32(mem->msg_payload);
	/* Skip the length of header and statues in payload area i.e 8 bytes*/
	xfer->rx.len = min_t(size_t, xfer->rx.len, ioread32(&mem->length) - 8);

	/* Take a copy to the rx buffer.. */
	memcpy_fromio(xfer->rx.buf, mem->msg_payload + 4, xfer->rx.len);
}

/**
 * scmi_xfer_lookup_unlocked  -  Helper to lookup an xfer_id
 *
 * @minfo: Pointer to Tx/Rx Message management info based on channel type
 * @xfer_id: Token ID to lookup in @pending_xfers
 *
 * Refcounting is untouched.
 *
 * Context: Assumes to be called with @xfer_lock already acquired.
 *
 * Return: A valid xfer on Success or error otherwise
 */
static struct scmi_xfer *
scmi_xfer_lookup_unlocked(struct scmi_xfers_info *minfo, u16 xfer_id)
{
	struct scmi_xfer *xfer = NULL;

	if (test_bit(xfer_id, minfo->xfer_alloc_table))
		xfer = XFER_FIND(minfo->pending_xfers, xfer_id);

	return xfer ?: ERR_PTR(-EINVAL);
}

/**
 * scmi_a2p_rx_callback() - mailbox client callback for receive messages
 *
 * @cl: client pointer
 * @m: mailbox message
 *
 * Processes one received message to appropriate transfer information and
 * signals completion of the transfer.
 *
 * NOTE: This function will be invoked in IRQ context, hence should be
 * as optimal as possible.
 */
static void scmi_a2p_rx_callback(struct mbox_client *cl, void *m)
{
	unsigned long flags;
	struct scmi_xfer *xfer;
	struct scmi_chan_info *cinfo = client_to_scmi_chan_info(cl);
	struct device *dev = cinfo->dev;
	struct scmi_info *info = handle_to_scmi_info(cinfo->handle);
	struct scmi_xfers_info *minfo = &info->minfo;
	struct scmi_shared_mem __iomem *mem = cinfo->payload;
	u32 hdr = ioread32(&mem->msg_header);
	u16 xfer_id;
	u8 msg_type;

	xfer_id = MSG_XTRACT_TOKEN(hdr);
	msg_type = MSG_XTRACT_TYPE(hdr);

	/* Are we even expecting this? */
	spin_lock_irqsave(&minfo->xfer_lock, flags);
	xfer = scmi_xfer_lookup_unlocked(minfo, xfer_id);
	spin_unlock_irqrestore(&minfo->xfer_lock, flags);
	if (IS_ERR(xfer)) {
		dev_err(dev, "message for %d is not expected!\n", xfer_id);
		return;
	}

	scmi_dump_header_dbg(dev, &xfer->hdr);

	/* Is the message of valid length? */
	if (xfer->rx.len > info->desc->max_msg_size) {
		dev_err(dev, "unable to handle %zu xfer(max %d)\n",
			xfer->rx.len, info->desc->max_msg_size);
		return;
	}

	scmi_fetch_response(xfer, mem);
	complete(&xfer->done);
}

/**
 * pack_scmi_header() - packs and returns 32-bit header
 *
 * @hdr: pointer to header containing all the information on message id,
 *	protocol id and sequence id.
 */
static inline u32 pack_scmi_header(struct scmi_msg_hdr *hdr)
{
	return ((hdr->id & MSG_ID_MASK) << MSG_ID_SHIFT) |
	   ((hdr->seq & MSG_TOKEN_ID_MASK) << MSG_TOKEN_ID_SHIFT) |
	   ((hdr->protocol_id & MSG_PROTOCOL_ID_MASK) << MSG_PROTOCOL_ID_SHIFT);
}

/**
 * scmi_a2p_tx_prepare() - mailbox client callback to prepare for the transfer
 *
 * @cl: client pointer
 * @m: mailbox message
 *
 * This function prepares the shared memory which contains the header and the
 * payload.
 */
static void scmi_a2p_tx_prepare(struct mbox_client *cl, void *m)
{
	struct scmi_xfer *t = m;
	struct scmi_chan_info *cinfo = client_to_scmi_chan_info(cl);
	struct scmi_shared_mem __iomem *mem = cinfo->payload;

	/* Mark channel busy + clear error */
	iowrite32(0x0, &mem->channel_status);
	iowrite32(t->hdr.poll_completion ? 0 : SCMI_SHMEM_FLAG_INTR_ENABLED,
		  &mem->flags);
	iowrite32(sizeof(mem->msg_header) + t->tx.len, &mem->length);
	iowrite32(pack_scmi_header(&t->hdr), &mem->msg_header);
	if (t->tx.buf)
		memcpy_toio(mem->msg_payload, t->tx.buf, t->tx.len);
}

/**
 * scmi_p2a_tx_prepare() - mailbox client callback to prepare for the transfer
 *
 * @cl: client pointer
 * @m: mailbox message
 *
 */
static void scmi_p2a_tx_prepare(struct mbox_client *cl, void *m)
{
	struct scmi_chan_info *cinfo = client_to_scmi_chan_info(cl);
	struct scmi_shared_mem __iomem *mem = cinfo->payload;

	/* Mark channel clear + clear error */
	iowrite32(SCMI_SHMEM_CHAN_STAT_CHANNEL_FREE, &mem->channel_status);
}

/**
 * scmi_p2a_rx_callback() - mailbox client callback for receive messages
 *
 * @cl: client pointer
 * @m: mailbox message
 *
 * Processes one received message to appropriate transfer information and
 * signals completion of the transfer.
 *
 */
static void scmi_p2a_rx_callback(struct mbox_client *cl, void *m)
{
	struct scmi_xfer *xfer;
	struct scmi_chan_info *cinfo = client_to_scmi_chan_info(cl);
	struct device *dev = cinfo->dev;
	struct scmi_info *info = handle_to_scmi_info(cinfo->handle);
	struct scmi_shared_mem __iomem *mem = cinfo->payload;
	u32 hdr = ioread32(&mem->msg_header);
	u8 msg_type, prot_id, msg_id;
	scmi_cback_fn_t prot_callback;

	msg_type = MSG_XTRACT_TYPE(hdr);
	msg_id = MSG_XTRACT_ID(hdr);
	prot_id = MSG_XTRACT_PROT_ID(hdr);

	if (msg_type == MSG_TYPE_NOTIFY) {
		xfer = scmi_one_xfer_get(cinfo->handle, false);
		if (IS_ERR(xfer)) {
			dev_err(dev, "P2A notification xfer alloc fail! prot=%x, msg=%x\n",
				prot_id, msg_id);
			return;
		}

		xfer->hdr.id = msg_id;
		xfer->hdr.protocol_id = prot_id;
		scmi_dump_header_dbg(dev, &xfer->hdr);

		xfer->rx.len = info->desc->max_msg_size;
		scmi_fetch_response(xfer, mem);

		prot_callback = idr_find(&scmi_prot_ntfy_cback, prot_id);
		if (unlikely(!prot_callback)) {
			dev_err(dev, "P2A notification no prot callback fn! prot=%x, msg=%x\n",
				prot_id, msg_id);
                        scmi_one_xfer_put(cinfo->handle, xfer);
		} else {
			/* Callback is expected to call xfer put */
			prot_callback(xfer);
		}
	} else {
		dev_err(dev, "Unexpected P2A message, prot=%x, msg=%x.  Discarding...\n",
				prot_id, msg_id);
	}

	/* Acknowlege the message */
	scmi_p2a_tx_prepare(&cinfo->cl, NULL);
}

/**
 * scmi_xfer_token_set  - Reserve and set new token for the xfer at hand
 *
 * @minfo: Pointer to Tx/Rx Message management info based on channel type
 * @xfer: The xfer to act upon
 *
 * Pick the next unused monotonically increasing token and set it into
 * xfer->hdr.seq: picking a monotonically increasing value avoids immediate
 * reuse of freshly completed or timed-out xfers, thus mitigating the risk
 * of incorrect association of a late and expired xfer with a live in-flight
 * transaction, both happening to re-use the same token identifier.
 *
 * Since platform is NOT required to answer our request in-order we should
 * account for a few rare but possible scenarios:
 *
 *  - exactly 'next_token' may be NOT available so pick xfer_id >= next_token
 *    using find_next_zero_bit() starting from candidate next_token bit
 *
 *  - all tokens ahead upto (MSG_TOKEN_ID_MASK - 1) are used in-flight but we
 *    are plenty of free tokens at start, so try a second pass using
 *    find_next_zero_bit() and starting from 0.
 *
 *  X = used in-flight
 *
 * Normal
 * ------
 *
 *		|- xfer_id picked
 *   -----------+----------------------------------------------------------
 *   | | |X|X|X| | | | | | ... ... ... ... ... ... ... ... ... ... ...|X|X|
 *   ----------------------------------------------------------------------
 *		^
 *		|- next_token
 *
 * Out-of-order pending at start
 * -----------------------------
 *
 *	  |- xfer_id picked, last_token fixed
 *   -----+----------------------------------------------------------------
 *   |X|X| | | | |X|X| ... ... ... ... ... ... ... ... ... ... ... ...|X| |
 *   ----------------------------------------------------------------------
 *    ^
 *    |- next_token
 *
 *
 * Out-of-order pending at end
 * ---------------------------
 *
 *	  |- xfer_id picked, last_token fixed
 *   -----+----------------------------------------------------------------
 *   |X|X| | | | |X|X| ... ... ... ... ... ... ... ... ... ... |X|X|X||X|X|
 *   ----------------------------------------------------------------------
 *								^
 *								|- next_token
 *
 * Context: Assumes to be called with @xfer_lock already acquired.
 *
 * Return: 0 on Success or error
 */
static int scmi_xfer_token_set(struct scmi_xfers_info *minfo,
			       struct scmi_xfer *xfer)
{
	unsigned long xfer_id, next_token;

	/*
	 * Pick a candidate monotonic token in range [0, MSG_TOKEN_MAX - 1]
	 * using the pre-allocated transfer_id as a base.
	 * Note that the global transfer_id is shared across all message types
	 * so there could be holes in the allocated set of monotonic sequence
	 * numbers, but that is going to limit the effectiveness of the
	 * mitigation only in very rare limit conditions.
	 */
	next_token = (xfer->transfer_id & (MSG_TOKEN_MAX - 1));

	/* Pick the next available xfer_id >= next_token */
	xfer_id = find_next_zero_bit(minfo->xfer_alloc_table,
				     MSG_TOKEN_MAX, next_token);
	if (xfer_id == MSG_TOKEN_MAX) {
		/*
		 * After heavily out-of-order responses, there are no free
		 * tokens ahead, but only at start of xfer_alloc_table so
		 * try again from the beginning.
		 */
		xfer_id = find_next_zero_bit(minfo->xfer_alloc_table,
					     MSG_TOKEN_MAX, 0);
		/*
		 * Something is wrong if we got here since there can be a
		 * maximum number of (MSG_TOKEN_MAX - 1) in-flight messages
		 * but we have not found any free token [0, MSG_TOKEN_MAX - 1].
		 */
		if (WARN_ON_ONCE(xfer_id == MSG_TOKEN_MAX))
			return -ENOMEM;
	}

	/* Update +/- last_token accordingly if we skipped some hole */
	if (xfer_id != next_token)
		atomic_add((int)(xfer_id - next_token), &transfer_last_id);

	/* Set in-flight */
	set_bit(xfer_id, minfo->xfer_alloc_table);
	xfer->hdr.seq = (u16)xfer_id;

	return 0;
}

/**
 * scmi_xfer_token_clear  - Release the token
 *
 * @minfo: Pointer to Tx/Rx Message management info based on channel type
 * @xfer: The xfer to act upon
 */
static inline void scmi_xfer_token_clear(struct scmi_xfers_info *minfo,
					 struct scmi_xfer *xfer)
{
	clear_bit(xfer->hdr.seq, minfo->xfer_alloc_table);
}

/**
 * scmi_one_xfer_get() - Allocate one message
 *
 * @handle: SCMI entity handle
 * @set_pending: If true a monotonic token is picked and the xfer is added to
 *		 the pending hash table.
 *
 * Helper function which is used by various command functions that are
 * exposed to clients of this driver for allocating a message traffic event.
 *
 * This function can sleep depending on pending requests already in the system
 * for the SCMI entity. Further, this also holds a spinlock to maintain
 * integrity of internal data structures.
 *
 * Return: 0 if all went fine, else corresponding error.
 */
static struct scmi_xfer *scmi_one_xfer_get(const struct scmi_handle *handle,
					   bool set_pending)
{
	int ret;
	unsigned long flags;
	struct scmi_xfer *xfer;
	struct scmi_info *info = handle_to_scmi_info(handle);
	struct scmi_xfers_info *minfo = &info->minfo;

	spin_lock_irqsave(&minfo->xfer_lock, flags);
	if (hlist_empty(&minfo->free_xfers)) {
		spin_unlock_irqrestore(&minfo->xfer_lock, flags);
		return ERR_PTR(-ENOMEM);
	}

	/* grab an xfer from the free_list */
	xfer = hlist_entry(minfo->free_xfers.first, struct scmi_xfer, node);
	hlist_del_init(&xfer->node);

	/*
	 * Allocate transfer_id early so that can be used also as base for
	 * monotonic sequence number generation if needed.
	 */
	xfer->transfer_id = atomic_inc_return(&transfer_last_id);

	if (set_pending) {
		/* Pick and set monotonic token */
		ret = scmi_xfer_token_set(minfo, xfer);
		if (!ret) {
			hash_add(minfo->pending_xfers, &xfer->node,
				 xfer->hdr.seq);
			xfer->pending = true;
		} else {
			dev_err(handle->dev,
				"Failed to get monotonic token %d\n", ret);
			hlist_add_head(&xfer->node, &minfo->free_xfers);
			xfer = ERR_PTR(ret);
		}
	}
	spin_unlock_irqrestore(&minfo->xfer_lock, flags);

	return xfer;
}

/**
 * scmi_one_xfer_put() - Release a message
 *
 * @minfo: transfer info pointer
 * @xfer: message that was reserved by scmi_one_xfer_get
 *
 * This holds a spinlock to maintain integrity of internal data structures.
 */
void scmi_one_xfer_put(const struct scmi_handle *handle, struct scmi_xfer *xfer)
{
	unsigned long flags;
	struct scmi_info *info = handle_to_scmi_info(handle);
	struct scmi_xfers_info *minfo = &info->minfo;

	spin_lock_irqsave(&minfo->xfer_lock, flags);
	if (xfer->pending) {
		scmi_xfer_token_clear(minfo, xfer);
		hash_del(&xfer->node);
		xfer->pending = false;
	}
	hlist_add_head(&xfer->node, &minfo->free_xfers);
	spin_unlock_irqrestore(&minfo->xfer_lock, flags);
}

static bool
scmi_xfer_poll_done(const struct scmi_chan_info *cinfo, struct scmi_xfer *xfer)
{
	struct scmi_shared_mem __iomem *mem = cinfo->payload;
	u16 xfer_id = MSG_XTRACT_TOKEN(ioread32(&mem->msg_header));

	if (xfer->hdr.seq != xfer_id)
		return false;

	return ioread32(&mem->channel_status) &
		(SCMI_SHMEM_CHAN_STAT_CHANNEL_ERROR |
		SCMI_SHMEM_CHAN_STAT_CHANNEL_FREE);
}

#define SCMI_MAX_POLL_TO_NS	(100 * NSEC_PER_USEC)

static bool scmi_xfer_done_no_timeout(const struct scmi_chan_info *cinfo,
				      struct scmi_xfer *xfer, ktime_t stop)
{
	ktime_t __cur = ktime_get();

	return scmi_xfer_poll_done(cinfo, xfer) || ktime_after(__cur, stop);
}

/**
 * scmi_do_xfer() - Do one transfer
 *
 * @info: Pointer to SCMI entity information
 * @xfer: Transfer to initiate and wait for response
 *
 * Return: -ETIMEDOUT in case of no response, if transmit error,
 *   return corresponding error, else if all goes well,
 *   return 0.
 */
int scmi_do_xfer(const struct scmi_handle *handle, struct scmi_xfer *xfer)
{
	int ret;
	int timeout;
	struct scmi_info *info = handle_to_scmi_info(handle);
	struct device *dev = info->dev;
	struct scmi_chan_info *cinfo;

	reinit_completion(&xfer->done);
	cinfo = idr_find(&info->tx_idr, xfer->hdr.protocol_id);
	if (unlikely(!cinfo))
		return -EINVAL;

	ret = mbox_send_message(cinfo->chan, xfer);
	if (ret < 0) {
		dev_dbg(dev, "mbox send fail %d\n", ret);
		return ret;
	}

	/* mbox_send_message returns non-negative value on success, so reset */
	ret = 0;

	if (xfer->hdr.poll_completion) {
		ktime_t stop = ktime_add_ns(ktime_get(), SCMI_MAX_POLL_TO_NS);

		spin_until_cond(scmi_xfer_done_no_timeout(cinfo, xfer, stop));

		if (ktime_before(ktime_get(), stop))
			scmi_fetch_response(xfer, cinfo->payload);
		else
			ret = -ETIMEDOUT;
	} else {
		/* And we wait for the response. */
		timeout = msecs_to_jiffies(max_rx_timeout_ms ? max_rx_timeout_ms
					   : info->desc->max_rx_timeout_ms);
		if (!wait_for_completion_timeout(&xfer->done, timeout)) {
			dev_err(dev, "mbox timed out in resp(caller: %pS)\n",
				(void *)_RET_IP_);
			ret = -ETIMEDOUT;
		}
	}

	if (!ret && xfer->hdr.status)
		ret = scmi_to_linux_errno(xfer->hdr.status);

	/*
	 * NOTE: we might prefer not to need the mailbox ticker to manage the
	 * transfer queueing since the protocol layer queues things by itself.
	 * Unfortunately, we have to kick the mailbox framework after we have
	 * received our message.
	 */
	mbox_client_txdone(cinfo->chan, ret);

	return ret;
}

/**
 * scmi_one_xfer_init() - Allocate and initialise one message
 *
 * @handle: SCMI entity handle
 * @msg_id: Message identifier
 * @msg_prot_id: Protocol identifier for the message
 * @tx_size: transmit message size
 * @rx_size: receive message size
 * @p: pointer to the allocated and initialised message
 *
 * This function allocates the message using @scmi_one_xfer_get and
 * initialise the header.
 *
 * Return: 0 if all went fine with @p pointing to message, else
 *	corresponding error.
 */
int scmi_one_xfer_init(const struct scmi_handle *handle, u8 msg_id, u8 prot_id,
		       size_t tx_size, size_t rx_size, struct scmi_xfer **p)
{
	int ret;
	struct scmi_xfer *xfer;
	struct scmi_info *info = handle_to_scmi_info(handle);
	struct device *dev = info->dev;

	/* Ensure we have sane transfer sizes */
	if (rx_size > info->desc->max_msg_size ||
	    tx_size > info->desc->max_msg_size)
		return -ERANGE;

	xfer = scmi_one_xfer_get(handle, true);
	if (IS_ERR(xfer)) {
		ret = PTR_ERR(xfer);
		dev_err(dev, "failed to get free message slot(%d)\n", ret);
		return ret;
	}

	xfer->tx.len = tx_size;
	xfer->rx.len = rx_size ? : info->desc->max_msg_size;
	xfer->hdr.id = msg_id;
	xfer->hdr.protocol_id = prot_id;
	xfer->hdr.poll_completion = false;

	*p = xfer;
	return 0;
}

/**
 * scmi_version_get() - command to get the revision of the SCMI entity
 *
 * @handle: Handle to SCMI entity information
 *
 * Updates the SCMI information in the internal data structure.
 *
 * Return: 0 if all went fine, else return appropriate error.
 */
int scmi_version_get(const struct scmi_handle *handle, u8 protocol,
		     u32 *version)
{
	int ret;
	__le32 *rev_info;
	struct scmi_xfer *t;

	ret = scmi_one_xfer_init(handle, PROTOCOL_VERSION, protocol, 0,
				 sizeof(*version), &t);
	if (ret)
		return ret;

	ret = scmi_do_xfer(handle, t);
	if (!ret) {
		rev_info = t->rx.buf;
		*version = le32_to_cpu(*rev_info);
	}

	scmi_one_xfer_put(handle, t);
	return ret;
}

void scmi_setup_protocol_implemented(const struct scmi_handle *handle,
				     u8 *prot_imp)
{
	struct scmi_info *info = handle_to_scmi_info(handle);

	info->protocols_imp = prot_imp;
}

static bool
scmi_is_protocol_implemented(const struct scmi_handle *handle, u8 prot_id)
{
	int i;
	struct scmi_info *info = handle_to_scmi_info(handle);

	if (!info->protocols_imp)
		return false;

	for (i = 0; i < MAX_PROTOCOLS_IMP; i++)
		if (info->protocols_imp[i] == prot_id)
			return true;
	return false;
}

/**
 * scmi_handle_get() - Get the  SCMI handle for a device
 *
 * @dev: pointer to device for which we want SCMI handle
 *
 * NOTE: The function does not track individual clients of the framework
 * and is expected to be maintained by caller of  SCMI protocol library.
 * scmi_handle_put must be balanced with successful scmi_handle_get
 *
 * Return: pointer to handle if successful, NULL on error
 */
struct scmi_handle *scmi_handle_get(struct device *dev)
{
	struct list_head *p;
	struct scmi_info *info;
	struct scmi_handle *handle = NULL;

	mutex_lock(&scmi_list_mutex);
	list_for_each(p, &scmi_list) {
		info = list_entry(p, struct scmi_info, node);
		if (dev->parent == info->dev) {
			handle = &info->handle;
			info->users++;
			break;
		}
	}
	mutex_unlock(&scmi_list_mutex);

	return handle;
}

/**
 * scmi_handle_put() - Release the handle acquired by scmi_handle_get
 *
 * @handle: handle acquired by scmi_handle_get
 *
 * NOTE: The function does not track individual clients of the framework
 * and is expected to be maintained by caller of  SCMI protocol library.
 * scmi_handle_put must be balanced with successful scmi_handle_get
 *
 * Return: 0 is successfully released
 *	if null was passed, it returns -EINVAL;
 */
int scmi_handle_put(const struct scmi_handle *handle)
{
	struct scmi_info *info;

	if (!handle)
		return -EINVAL;

	info = handle_to_scmi_info(handle);
	mutex_lock(&scmi_list_mutex);
	if (!WARN_ON(!info->users))
		info->users--;
	mutex_unlock(&scmi_list_mutex);

	return 0;
}

static const struct scmi_desc scmi_generic_desc = {
	.max_rx_timeout_ms = 120,	/* we may increase this if required */
	.max_msg = 20,		/* Limited by MBOX_TX_QUEUE_LEN */
	.max_msg_size = 128,
};

/* Each compatible listed below must have descriptor associated with it */
static const struct of_device_id scmi_of_match[] = {
	{ .compatible = "arm,scmi", .data = &scmi_generic_desc },
	{ /* Sentinel */ },
};

MODULE_DEVICE_TABLE(of, scmi_of_match);

static int scmi_xfer_info_init(struct scmi_info *sinfo)
{
	int i;
	struct scmi_xfer *xfer;
	struct device *dev = sinfo->dev;
	const struct scmi_desc *desc = sinfo->desc;
	struct scmi_xfers_info *info = &sinfo->minfo;

	/* Pre-allocated messages, no more than what hdr.seq can support */
	if (WARN_ON(desc->max_msg >= (MSG_TOKEN_ID_MASK + 1))) {
		dev_err(dev, "Maximum message of %d exceeds supported %d\n",
			desc->max_msg, MSG_TOKEN_ID_MASK + 1);
		return -EINVAL;
	}

	hash_init(info->pending_xfers);

	/* Allocate a bitmask sized to hold MSG_TOKEN_MAX tokens */
	info->xfer_alloc_table = devm_kcalloc(dev, BITS_TO_LONGS(MSG_TOKEN_MAX),
					      sizeof(long), GFP_KERNEL);
	if (!info->xfer_alloc_table)
		return -ENOMEM;

	bitmap_zero(info->xfer_alloc_table, MSG_TOKEN_MAX);

	/*
	 * Preallocate a number of xfers equal to max inflight messages,
	 * pre-initialize the buffer pointer to pre-allocated buffers and
	 * attach all of them to the free list
	 */
	INIT_HLIST_HEAD(&info->free_xfers);
	for (i = 0; i < desc->max_msg; i++) {
		xfer = devm_kzalloc(dev, sizeof(*xfer), GFP_KERNEL);
		if (!xfer)
			return -ENOMEM;

		xfer->rx.buf = devm_kcalloc(dev, sizeof(u8), desc->max_msg_size,
					    GFP_KERNEL);
		if (!xfer->rx.buf)
			return -ENOMEM;

		xfer->tx.buf = xfer->rx.buf;
		init_completion(&xfer->done);

		/* Add initialized xfer to the free list */
		hlist_add_head(&xfer->node, &info->free_xfers);
	}

	spin_lock_init(&info->xfer_lock);

	return 0;
}

static int scmi_mailbox_check(struct device_node *np)
{
	struct of_phandle_args arg;

	return of_parse_phandle_with_args(np, "mboxes", "#mbox-cells", 0, &arg);
}

static int scmi_mbox_free_channel(int id, void *p, void *data)
{
	struct scmi_chan_info *cinfo = p;
	struct idr *idr = data;

	if (!IS_ERR_OR_NULL(cinfo->chan)) {
		mbox_free_channel(cinfo->chan);
		cinfo->chan = NULL;
	}

	idr_remove(idr, id);

	return 0;
}

static int scmi_remove(struct platform_device *pdev)
{
	int ret = 0;
	struct scmi_info *info = platform_get_drvdata(pdev);
	struct idr *idr = &info->tx_idr;

	mutex_lock(&scmi_list_mutex);
	if (info->users)
		ret = -EBUSY;
	else
		list_del(&info->node);
	mutex_unlock(&scmi_list_mutex);

	if (!ret) {
		/* Safe to free channels since no more users */
		ret = idr_for_each(idr, scmi_mbox_free_channel, idr);
		idr_destroy(&info->tx_idr);
	}

	return ret;
}

static inline int
scmi_mbox_chan_setup(struct scmi_info *info, struct device *dev, int prot_id)
{
	int ret;
	struct resource res;
	resource_size_t size;
	struct device_node *shmem, *np = dev->of_node;
	struct scmi_chan_info *cinfo;
	struct mbox_client *cl;
	void __iomem *pyld;

	if (scmi_mailbox_check(np)) {
		cinfo = idr_find(&info->tx_idr, SCMI_PROTOCOL_BASE);
		goto idr_alloc;
	}

	cinfo = devm_kzalloc(info->dev, 2 * sizeof(struct scmi_chan_info),
			     GFP_KERNEL);

	cinfo[0].dev = dev;
	cl = &cinfo[0].cl;
	cl->dev = dev;
	cl->rx_callback = scmi_a2p_rx_callback;
	cl->tx_prepare = scmi_a2p_tx_prepare;
	cl->tx_block = false;
	cl->knows_txdone = true;

	cinfo[1].dev = dev;
	cl = &cinfo[1].cl;
	cl->dev = dev;
	cl->rx_callback = scmi_p2a_rx_callback;
	cl->tx_prepare = scmi_p2a_tx_prepare;
	cl->tx_block = false;
	cl->knows_txdone = true;

	shmem = of_parse_phandle(np, "shmem", 0);
	ret = of_address_to_resource(shmem, 0, &res);
	of_node_put(shmem);
	if (ret) {
		dev_err(dev, "failed to get SCMI Tx payload mem resource\n");
		return ret;
	}

	size = resource_size(&res);
	pyld = devm_ioremap(info->dev, res.start, size);
	if (!pyld) {
		dev_err(dev, "failed to ioremap SCMI Tx/Rx payload\n");
		return -EADDRNOTAVAIL;
	}
	cinfo[0].payload = pyld;
	cinfo[1].payload = pyld + (size / 2);

	/* a2p channel is first entry i.e. index 0 */
	cinfo[0].chan = mbox_request_channel(&cinfo[0].cl, 0);
	if (IS_ERR(cinfo[0].chan)) {
		ret = PTR_ERR(cinfo[0].chan);
		if (ret != -EPROBE_DEFER)
			dev_err(dev, "failed to request SCMI Tx mailbox\n");
		return ret;
	}

	/* p2a channel is second entry i.e. index 1 */
	cinfo[1].chan = mbox_request_channel(&cinfo[1].cl, 1);
	if (IS_ERR(cinfo[1].chan)) {
		ret = PTR_ERR(cinfo[1].chan);
		if (ret == -EPROBE_DEFER)
			return ret;
		dev_warn(dev, "failed to request SCMI Rx mailbox\n");
	}

	cinfo[0].handle = &info->handle;
	cinfo[1].handle = &info->handle;

idr_alloc:
	ret = idr_alloc(&info->tx_idr, &cinfo[0], prot_id, prot_id + 1,
			GFP_KERNEL);
	if (ret != prot_id) {
		dev_err(dev, "unable to allocate SCMI idr slot err %d\n", ret);
		return ret;
	}
	return 0;
}

static inline void
scmi_create_protocol_device(struct device_node *np, struct scmi_info *info,
			    int prot_id)
{
	struct scmi_device *sdev;

	sdev = scmi_device_create(np, info->dev, prot_id);
	if (!sdev) {
		dev_err(info->dev, "failed to create %d protocol device\n",
			prot_id);
		return;
	}

	if (scmi_mbox_chan_setup(info, &sdev->dev, prot_id)) {
		dev_err(&sdev->dev, "failed to setup transport\n");
		scmi_device_destroy(sdev);
	}

	/* setup handle now as the transport is ready */
	scmi_set_handle(sdev);
}

static int scmi_probe(struct platform_device *pdev)
{
	int ret;
	struct scmi_handle *handle;
	const struct scmi_desc *desc;
	struct scmi_info *info;
	struct device *dev = &pdev->dev;
	struct device_node *child, *np = dev->of_node;

	/* Only mailbox method supported, check for the presence of one */
	if (scmi_mailbox_check(np)) {
		dev_err(dev, "no mailbox found in %pOF\n", np);
		return -EINVAL;
	}

	desc = of_match_device(scmi_of_match, dev)->data;

	info = devm_kzalloc(dev, sizeof(*info), GFP_KERNEL);
	if (!info)
		return -ENOMEM;

	info->dev = dev;
	info->desc = desc;
	INIT_LIST_HEAD(&info->node);

	ret = scmi_xfer_info_init(info);
	if (ret)
		return ret;

	platform_set_drvdata(pdev, info);
	idr_init(&info->tx_idr);

	handle = &info->handle;
	handle->dev = info->dev;
	handle->version = &info->version;

	ret = scmi_mbox_chan_setup(info, dev, SCMI_PROTOCOL_BASE);
	if (ret)
		return ret;

	ret = scmi_base_protocol_init(handle);
	if (ret) {
		dev_err(dev, "unable to communicate with SCMI(%d)\n", ret);
		return ret;
	}

	mutex_lock(&scmi_list_mutex);
	list_add_tail(&info->node, &scmi_list);
	mutex_unlock(&scmi_list_mutex);

	for_each_available_child_of_node(np, child) {
		u32 prot_id;

		if (of_property_read_u32(child, "reg", &prot_id))
			continue;

		prot_id &= MSG_PROTOCOL_ID_MASK;

		if (!scmi_is_protocol_implemented(handle, prot_id)) {
			dev_err(dev, "SCMI protocol %d not implemented\n",
				prot_id);
			continue;
		}

		scmi_create_protocol_device(child, info, prot_id);
	}

	return 0;
}

static struct platform_driver scmi_driver = {
	.driver = {
		   .name = "arm-scmi",
		   .of_match_table = scmi_of_match,
		   },
	.probe = scmi_probe,
	.remove = scmi_remove,
};

module_platform_driver(scmi_driver);

MODULE_ALIAS("platform: arm-scmi");
MODULE_AUTHOR("Sudeep Holla <sudeep.holla@arm.com>");
MODULE_DESCRIPTION("ARM SCMI protocol driver");
MODULE_LICENSE("GPL v2");
