// SPDX-License-Identifier: GPL-2.0
/*
 * System Control and Management Interface (SCMI) Message Protocol
 * driver common header file containing some definitions, structures
 * and function prototypes used in all the different SCMI protocols.
 *
 * Copyright (C) 2018 ARM Ltd.
 */

#include <linux/completion.h>
#include <linux/device.h>
#include <linux/errno.h>
#include <linux/hashtable.h>
#include <linux/list.h>
#include <linux/kernel.h>
#include <linux/scmi_protocol.h>
#include <linux/types.h>
#include <linux/workqueue.h>
#include <linux/idr.h>

#define PROTOCOL_REV_MINOR_BITS	16
#define PROTOCOL_REV_MINOR_MASK	((1U << PROTOCOL_REV_MINOR_BITS) - 1)
#define PROTOCOL_REV_MAJOR(x)	((x) >> PROTOCOL_REV_MINOR_BITS)
#define PROTOCOL_REV_MINOR(x)	((x) & PROTOCOL_REV_MINOR_MASK)
#define MAX_PROTOCOLS_IMP	16
#define MAX_OPPS		16

enum scmi_common_cmd {
	PROTOCOL_VERSION = 0x0,
	PROTOCOL_ATTRIBUTES = 0x1,
	PROTOCOL_MESSAGE_ATTRIBUTES = 0x2,
};

/* Holds the notify callback func for each protocol */
extern struct idr scmi_prot_ntfy_cback;

/**
 * struct scmi_msg_resp_prot_version - Response for a message
 *
 * @major_version: Major version of the ABI that firmware supports
 * @minor_version: Minor version of the ABI that firmware supports
 *
 * In general, ABI version changes follow the rule that minor version increments
 * are backward compatible. Major revision changes in ABI may not be
 * backward compatible.
 *
 * Response to a generic message with message type SCMI_MSG_VERSION
 */
struct scmi_msg_resp_prot_version {
	__le16 minor_version;
	__le16 major_version;
};

/*
 * Size of @pending_xfers hashtable included in @scmi_xfers_info; ideally, in
 * order to minimize space and collisions, this should equal max_msg, i.e. the
 * maximum number of in-flight messages on a specific platform, but such value
 * is only available at runtime while kernel hashtables are statically sized:
 * pick instead as a fixed static size the maximum number of entries that can
 * fit the whole table into one 4k page.
 */
#define SCMI_PENDING_XFERS_HT_ORDER_SZ		9

/**
 * struct scmi_msg_hdr - Message(Tx/Rx) header
 *
 * @id: The identifier of the command being sent
 * @protocol_id: The identifier of the protocol used to send @id command
 * @seq: The token to identify the message. when a message/command returns,
 *       the platform returns the whole message header unmodified including
 *	 the token.
 * @pending: True for xfers added to @pending_xfers hashtable
 * @node: An hlist_node reference used to store this xfer, alternatively, on
 *	  the free list @free_xfers or in the @pending_xfers hashtable
 */
struct scmi_msg_hdr {
	u8 id;
	u8 protocol_id;
	u16 seq;
	u32 status;
	bool poll_completion;
	bool pending;
	struct hlist_node node;
};

/*
 * An helper macro to lookup an xfer from the @pending_xfers hashtable
 * using the message sequence number token as a key.
 */
#define XFER_FIND(__ht, __k)					\
({								\
	typeof(__k) k_ = __k;					\
	struct scmi_xfer *xfer_ = NULL;				\
								\
	hash_for_each_possible((__ht), xfer_, node, k_)		\
		if (xfer_->hdr.seq == k_)			\
			break;					\
	xfer_;							\
})

/**
 * struct scmi_msg - Message(Tx/Rx) structure
 *
 * @buf: Buffer pointer
 * @len: Length of data in the Buffer
 */
struct scmi_msg {
	void *buf;
	size_t len;
};

/**
 * struct scmi_xfer - Structure representing a message flow
 *
 * @transfer_id: Unique ID for debug & profiling purpose
 * @hdr: Transmit message header
 * @tx: Transmit message
 * @rx: Receive message, the buffer should be pre-allocated to store
 *	message. If request-ACK protocol is used, we can reuse the same
 *	buffer for the rx path as we use for the tx path.
 * @done: completion event
 * @async_agent_callback -- callback after command executes
 * @defer_async_callback -- defer the callback via workqueue.
 * @work -- only used if async_agent_callback is non-NULL and
 *      defer_async_callback is true;
 * @pending: True for xfers added to @pending_xfers hashtable
 * @node: An hlist_node reference used to store this xfer, alternatively, on
 *	  the free list @free_xfers or in the @pending_xfers hashtable
 */

struct scmi_xfer {
	int transfer_id;
	void *con_priv;
	struct scmi_msg_hdr hdr;
	struct scmi_msg tx;
	struct scmi_msg rx;
	struct completion done;
	bool pending;
	struct hlist_node node;
};

void scmi_one_xfer_put(const struct scmi_handle *h, struct scmi_xfer *xfer);
int scmi_do_xfer(const struct scmi_handle *h, struct scmi_xfer *xfer);
int scmi_one_xfer_init(const struct scmi_handle *h, u8 msg_id, u8 prot_id,
		       size_t tx_size, size_t rx_size, struct scmi_xfer **p);
int scmi_handle_put(const struct scmi_handle *handle);
struct scmi_handle *scmi_handle_get(struct device *dev);
void scmi_set_handle(struct scmi_device *scmi_dev);
int scmi_version_get(const struct scmi_handle *h, u8 protocol, u32 *version);
void scmi_setup_protocol_implemented(const struct scmi_handle *handle,
				     u8 *prot_imp);

int scmi_base_protocol_init(struct scmi_handle *h);
