// SPDX-License-Identifier: GPL-2.0
#ifndef __BCMASP_H
#define __BCMASP_H

#include <linux/netdevice.h>
#include <uapi/linux/ethtool.h>

#define ASP_INTR2_OFFSET			0x1000
#define  ASP_INTR2_STATUS			0x0
#define  ASP_INTR2_SET				0x4
#define  ASP_INTR2_CLEAR			0x8
#define  ASP_INTR2_MASK_STATUS			0xc
#define  ASP_INTR2_MASK_SET			0x10
#define  ASP_INTR2_MASK_CLEAR			0x14

#define ASP_INTR2_NUM_INTR			6
#define ASP_INTR2_RX_ECH(intr)			BIT(intr)
#define ASP_INTR2_TX_DESC(intr)			BIT((intr) + 14)
#define ASP_INTR2_UMC0_WAKE			BIT(22)
#define ASP_INTR2_UMC1_WAKE			BIT(28)


#define ASP_TX_ANALYTICS_OFFSET			0x4c000
#define  ASP_TX_ANALYTICS_CTRL			0x0

#define ASP_RX_ANALYTICS_OFFSET			0x98000
#define  ASP_RX_ANALYTICS_CTRL			0x0

#define ASP_RX_CTRL_OFFSET			0x9f000
#define ASP_RX_CTRL_UMAC_0_FRAME_COUNT		0x8
#define ASP_RX_CTRL_UMAC_1_FRAME_COUNT		0xc
#define ASP_RX_CTRL_FB_0_FRAME_COUNT		0x14
#define ASP_RX_CTRL_FB_1_FRAME_COUNT		0x18
#define ASP_RX_CTRL_FB_8_FRAME_COUNT		0x1c
#define ASP_RX_CTRL_FB_OUT_FRAME_COUNT		0x20
#define ASP_RX_CTRL_FB_FILT_OUT_FRAME_COUNT	0x24
#define ASP_RX_CTRL_FLUSH			0x28
#define  ASP_CTRL_UMAC0_FLUSH_MASK		0x1001
#define  ASP_CTRL_UMAC1_FLUSH_MASK		0x2002
#define ASP_RX_CTRL_FB_RX_FIFO_DEPTH		0x30
#define ASP_RX_CTRL_S2F				0x44
#define  ASP_RX_CTRL_S2F_OPUT_EN		BIT(0)
#define  ASP_RX_CTRL_S2F_VLN_EN			BIT(1)
#define  ASP_RX_CTRL_S2F_SNP_EN			BIT(2)
#define  ASP_RX_CTRL_S2F_BCM_TAG_EN		BIT(3)
#define  ASP_RX_CTRL_S2F_CHID_SHIFT		8
#define  ASP_RX_CTRL_S2F_DEFAULT_EN		\
		(ASP_RX_CTRL_S2F_OPUT_EN |	\
		ASP_RX_CTRL_S2F_VLN_EN |	\
		ASP_RX_CTRL_S2F_SNP_EN)

#define ASP_RX_FILTER_OFFSET			0x80000
#define  ASP_RX_FILTER_BLK_CTRL			0x0
#define   ASP_RX_FILTER_OPUT_EN			BIT(0)
#define   ASP_RX_FILTER_MDA_EN			BIT(1)
#define   ASP_RX_FILTER_LNR_MD			BIT(2)
#define   ASP_RX_FILTER_GEN_WK_EN		BIT(3)
#define   ASP_RX_FILTER_GEN_WK_CLR		BIT(4)
#define   ASP_RX_FILTER_NT_FLT_EN		BIT(5)
#define  ASP_RX_FILTER_MDA_CFG(sel)		(((sel) * 0x14) + 0x100)
#define   ASP_RX_FILTER_MDA_CFG_EN_SHIFT	8
#define   ASP_RX_FILTER_MDA_CFG_UMC_SEL(sel)	((sel) > 1 ? BIT(17) : BIT((sel) + 9))
#define  ASP_RX_FILTER_MDA_PAT_H(sel)		(((sel) * 0x14) + 0x104)
#define  ASP_RX_FILTER_MDA_PAT_L(sel)		(((sel) * 0x14) + 0x108)
#define  ASP_RX_FILTER_MDA_MSK_H(sel)		(((sel) * 0x14) + 0x10c)
#define  ASP_RX_FILTER_MDA_MSK_L(sel)		(((sel) * 0x14) + 0x110)
#define  ASP_RX_FILTER_MDA_CFG(sel)		(((sel) * 0x14) + 0x100)
#define  ASP_RX_FILTER_MDA_PAT_H(sel)		(((sel) * 0x14) + 0x104)
#define  ASP_RX_FILTER_MDA_PAT_L(sel)		(((sel) * 0x14) + 0x108)
#define  ASP_RX_FILTER_MDA_MSK_H(sel)		(((sel) * 0x14) + 0x10c)
#define  ASP_RX_FILTER_MDA_MSK_L(sel)		(((sel) * 0x14) + 0x110)
#define  ASP_RX_FILTER_NET_CFG(sel)		(((sel) * 0xa04) + 0x400)
#define   ASP_RX_FILTER_NET_CFG_CH(sel)		((sel) << 0)
#define   ASP_RX_FILTER_NET_CFG_EN		BIT(9)
#define   ASP_RX_FILTER_NET_CFG_L2_EN		BIT(10)
#define   ASP_RX_FILTER_NET_CFG_L3_EN		BIT(11)
#define   ASP_RX_FILTER_NET_CFG_L4_EN		BIT(12)
#define   ASP_RX_FILTER_NET_CFG_L3_FRM(sel)	((sel) << 13)
#define   ASP_RX_FILTER_NET_CFG_L4_FRM(sel)	((sel) << 15)
#define   ASP_RX_FILTER_NET_CFG_UMC(sel)	BIT((sel) + 19)
#define   ASP_RX_FILTER_NET_CFG_DMA_EN		BIT(27)

enum asp_rx_net_filter_block {
	ASP_RX_FILTER_L2 = 0,
	ASP_RX_FILTER_L3_0,
	ASP_RX_FILTER_L3_1,
	ASP_RX_FILTER_L4,
	ASP_RX_FILTER_NET_BLOCK_MAX
};

#define  ASP_RX_FILTER_NET_OFFSET_MAX		32
#define  ASP_RX_FILTER_NET_PAT(sel, block, off) \
		(((sel) * 0xa04) + ((block) * 0x200) + (off) + 0x600)
#define  ASP_RX_FILTER_NET_MASK(sel, block, off) \
		(((sel) * 0xa04) + ((block) * 0x200) + (off) + 0x700)

#define  ASP_RX_FILTER_NET_OFFSET(sel)		(((sel) * 0xa04) + 0xe00)
#define   ASP_RX_FILTER_NET_OFFSET_L2(val)	((val) << 0)
#define   ASP_RX_FILTER_NET_OFFSET_L3_0(val)	((val) << 8)
#define   ASP_RX_FILTER_NET_OFFSET_L3_1(val)	((val) << 16)
#define   ASP_RX_FILTER_NET_OFFSET_L4(val)	((val) << 24)

#define NUM_MDA_FILTERS				32
#define NUM_NET_FILTERS				32

#define ASP_EDPKT_OFFSET			0x9c000
#define  ASP_EDPKT_ENABLE			0x4
#define   ASP_EDPKT_ENABLE_EN			BIT(0)
#define  ASP_EDPKT_HDR_CFG			0xc
#define   ASP_EDPKT_HDR_SZ_SHIFT		2
#define   ASP_EDPKT_HDR_SZ_32			0
#define   ASP_EDPKT_HDR_SZ_64			1
#define   ASP_EDPKT_HDR_SZ_96			2
#define   ASP_EDPKT_HDR_SZ_128			3
#define ASP_EDPKT_BURST_BUF_PSCAL_TOUT		0x10
#define ASP_EDPKT_BURST_BUF_WRITE_TOUT		0x14
#define ASP_EDPKT_BURST_BUF_READ_TOUT		0x18
#define ASP_EDPKT_RX_TS_COUNTER			0x38
#define  ASP_EDPKT_ENDI				0x48
#define   ASP_EDPKT_ENDI_DESC_SHIFT		8
#define   ASP_EDPKT_ENDI_NO_BT_SWP		0
#define   ASP_EDPKT_ENDI_BT_SWP_WD		1
#define ASP_EDPKT_RX_PKT_CNT			0x138
#define ASP_EDPKT_HDR_EXTR_CNT			0x13c
#define ASP_EDPKT_HDR_OUT_CNT			0x140

#define ASP_CTRL				0x101000
#define  ASP_CTRL_ASP_SW_INIT			0x04
#define   ASP_CTRL_ASP_SW_INIT_ACPUSS_CORE	BIT(0)
#define   ASP_CTRL_ASP_SW_INIT_ASP_TX		BIT(1)
#define   ASP_CTRL_ASP_SW_INIT_AS_RX		BIT(2)
#define   ASP_CTRL_ASP_SW_INIT_ASP_RGMII_UMAC0	BIT(3)
#define   ASP_CTRL_ASP_SW_INIT_ASP_RGMII_UMAC1	BIT(4)
#define   ASP_CTRL_ASP_SW_INIT_ASP_XMEMIF	BIT(5)
#define  ASP_CTRL_CLOCK_CTRL			0x04
#define   ASP_CTRL_CLOCK_CTRL_ASP_TX_DISABLE	BIT(0)
#define   ASP_CTRL_CLOCK_CTRL_ASP_RX_DISABLE	BIT(1)
#define   ASP_CTRL_CLOCK_CTRL_ASP_RGMII_SHIFT	2
#define   ASP_CTRL_CLOCK_CTRL_ASP_RGMII_MASK	(0x3 << ASP_CTRL_CLOCK_CTRL_ASP_RGMII_SHIFT)
#define   ASP_CTRL_CLOCK_CTRL_ASP_RGMII_DIS(x)	BIT(ASP_CTRL_CLOCK_CTRL_ASP_RGMII_SHIFT + (x))
#define   ASP_CTRL_CLOCK_CTRL_ASP_ALL_DISABLE	GENMASK(3, 0)
#define  ASP_CTRL_CORE_CLOCK_SELECT		0x08
#define   ASP_CTRL_CORE_CLOCK_SELECT_MAIN	BIT(0)

struct bcmasp_tx_cb {
	struct sk_buff		*skb;
	unsigned int		bytes_sent;
	bool			last;

	DEFINE_DMA_UNMAP_ADDR(dma_addr);
	DEFINE_DMA_UNMAP_LEN(dma_len);
};

struct bcmasp_res {
	/* Per interface resources */
	/* Port */
	void __iomem		*umac;
	void __iomem		*umac2fb;
	void __iomem		*rgmii;

	/* TX slowpath/configuration */
	void __iomem		*tx_spb_ctrl;
	void __iomem		*tx_spb_top;
	void __iomem		*tx_epkt_core;
	void __iomem		*tx_pause_ctrl;
};

#define DESC_ADDR(x)		((x) & GENMASK_ULL(39, 0))
#define DESC_FLAGS(x)		((x) & GENMASK_ULL(63, 40))

struct bcmasp_desc {
	u64		buf;
	#define DESC_CHKSUM	BIT_ULL(40)
	#define DESC_CRC_ERR	BIT_ULL(41)
	#define DESC_RX_SYM_ERR	BIT_ULL(42)
	#define DESC_NO_OCT_ALN BIT_ULL(43)
	#define DESC_PKT_TRUC	BIT_ULL(44)
	/*  39:0 (TX/RX) bits 0-39 of buf addr
	 *    40 (RX) checksum
	 *    41 (RX) crc_error
	 *    42 (RX) rx_symbol_error
	 *    43 (RX) non_octet_aligned
	 *    44 (RX) pkt_truncated
	 *    45 Reserved
	 * 56:46 (RX) mac_filter_id
	 * 60:57 (RX) rx_port_num (0-unicmac0, 1-unimac1, 8-wifi)
	 *    61 Reserved
	 * 63:62 (TX) forward CRC, overwrite CRC
	 */
	u32		size;
	u32		flags;
	#define DESC_INT_EN     BIT(0)
	#define DESC_SOF	BIT(1)
	#define DESC_EOF	BIT(2)
	#define DESC_EPKT_CMD   BIT(3)
	#define DESC_SCRAM_ST   BIT(8)
	#define DESC_SCRAM_END  BIT(9)
	#define DESC_PCPP       BIT(10)
	#define DESC_PPPP       BIT(11)
	/*     0 (TX) tx_int_en
	 *     1 (TX/RX) SOF
	 *     2 (TX/RX) EOF
	 *     3 (TX) epkt_command
	 *   6:4 (TX) PA
	 *     7 (TX) pause at desc end
	 *     8 (TX) scram_start
	 *     9 (TX) scram_end
	 *    10 (TX) PCPP
	 *    11 (TX) PPPP
	 * 14:12 Reserved
	 *    15 (TX) pid ch Valid
	 * 19:16 (TX) data_pkt_type
	 * 32:20 (TX) pid_channel (RX) nw_filter_id
	 */
};

/* Rx/Tx common counter group */
struct bcmasp_pkt_counters {
	u32	cnt_64;		/* RO Received/Transmited 64 bytes packet */
	u32	cnt_127;	/* RO Rx/Tx 127 bytes packet */
	u32	cnt_255;	/* RO Rx/Tx 65-255 bytes packet */
	u32	cnt_511;	/* RO Rx/Tx 256-511 bytes packet */
	u32	cnt_1023;	/* RO Rx/Tx 512-1023 bytes packet */
	u32	cnt_1518;	/* RO Rx/Tx 1024-1518 bytes packet */
	u32	cnt_mgv;	/* RO Rx/Tx 1519-1522 good VLAN packet */
	u32	cnt_2047;	/* RO Rx/Tx 1522-2047 bytes packet*/
	u32	cnt_4095;	/* RO Rx/Tx 2048-4095 bytes packet*/
	u32	cnt_9216;	/* RO Rx/Tx 4096-9216 bytes packet*/
};

/* RSV, Receive Status Vector */
struct bcmasp_rx_counters {
	struct  bcmasp_pkt_counters pkt_cnt;
	u32	pkt;		/* RO (0x428) Received pkt count*/
	u32	bytes;		/* RO Received byte count */
	u32	mca;		/* RO # of Received multicast pkt */
	u32	bca;		/* RO # of Receive broadcast pkt */
	u32	fcs;		/* RO # of Received FCS error  */
	u32	cf;		/* RO # of Received control frame pkt*/
	u32	pf;		/* RO # of Received pause frame pkt */
	u32	uo;		/* RO # of unknown op code pkt */
	u32	aln;		/* RO # of alignment error count */
	u32	flr;		/* RO # of frame length out of range count */
	u32	cde;		/* RO # of code error pkt */
	u32	fcr;		/* RO # of carrier sense error pkt */
	u32	ovr;		/* RO # of oversize pkt*/
	u32	jbr;		/* RO # of jabber count */
	u32	mtue;		/* RO # of MTU error pkt*/
	u32	pok;		/* RO # of Received good pkt */
	u32	uc;		/* RO # of unicast pkt */
	u32	ppp;		/* RO # of PPP pkt */
	u32	rcrc;		/* RO (0x470),# of CRC match pkt */
};

/* TSV, Transmit Status Vector */
struct bcmasp_tx_counters {
	struct bcmasp_pkt_counters pkt_cnt;
	u32	pkts;		/* RO (0x4a8) Transmited pkt */
	u32	mca;		/* RO # of xmited multicast pkt */
	u32	bca;		/* RO # of xmited broadcast pkt */
	u32	pf;		/* RO # of xmited pause frame count */
	u32	cf;		/* RO # of xmited control frame count */
	u32	fcs;		/* RO # of xmited FCS error count */
	u32	ovr;		/* RO # of xmited oversize pkt */
	u32	drf;		/* RO # of xmited deferral pkt */
	u32	edf;		/* RO # of xmited Excessive deferral pkt*/
	u32	scl;		/* RO # of xmited single collision pkt */
	u32	mcl;		/* RO # of xmited multiple collision pkt*/
	u32	lcl;		/* RO # of xmited late collision pkt */
	u32	ecl;		/* RO # of xmited excessive collision pkt*/
	u32	frg;		/* RO # of xmited fragments pkt*/
	u32	ncl;		/* RO # of xmited total collision count */
	u32	jbr;		/* RO # of xmited jabber count*/
	u32	bytes;		/* RO # of xmited byte count */
	u32	pok;		/* RO # of xmited good pkt */
	u32	uc;		/* RO (0x0x4f0)# of xmited unitcast pkt */
};

struct bcmasp_mib_counters {
	struct bcmasp_rx_counters rx;
	struct bcmasp_tx_counters tx;
	u32	rx_runt_cnt;
	u32	rx_runt_fcs;
	u32	rx_runt_fcs_align;
	u32	rx_runt_bytes;
	u32	edpkt_ts;
	u32	edpkt_rx_pkt_cnt;
	u32	edpkt_hdr_ext_cnt;
	u32	edpkt_hdr_out_cnt;
	u32	umac_frm_cnt;
	u32	fb_frm_cnt;
	u32	fb_out_frm_cnt;
	u32	fb_filt_out_frm_cnt;
	u32	fb_rx_fifo_depth;
	u32	alloc_rx_buff_failed;
	u32	alloc_rx_skb_failed;
	u32	rx_dma_failed;
	u32	tx_dma_failed;
	u32	mc_filters_full_cnt;
	u32	uc_filters_full_cnt;
	u32	filters_combine_cnt;
	u32	promisc_filters_cnt;
	u32	tx_realloc_offload_failed;
	u32	tx_realloc_offload;
};

struct bcmasp_intf {
	struct net_device	*ndev;
	struct bcmasp_priv	*parent;

	/* ASP Ch */
	int			channel;
	int			port;

	struct napi_struct	tx_napi;
	/* TX ring, starts on a new cacheline boundary */
	void __iomem		*tx_spb_dma;
	int			tx_spb_index;
	int			tx_spb_clean_index;
	struct bcmasp_desc	*tx_spb_cpu;
	dma_addr_t		tx_spb_dma_addr;
	dma_addr_t		tx_spb_dma_valid;
	dma_addr_t		tx_spb_dma_read;
	struct bcmasp_tx_cb	*tx_cbs;
	spinlock_t		tx_lock;

	/* RX ring, starts on a new cacheline boundary */
	void __iomem		*rx_edpkt_cfg;
	void __iomem		*rx_edpkt_dma;
	int			rx_edpkt_index;
	int			rx_buf_order;
	struct bcmasp_desc	*rx_edpkt_cpu;
	dma_addr_t		rx_edpkt_dma_addr;
	dma_addr_t		rx_edpkt_dma_read;

	/* RX buffer prefetcher ring*/
	void			*rx_ring_cpu;
	dma_addr_t		rx_ring_dma;
	dma_addr_t		rx_ring_dma_valid;
	struct napi_struct	rx_napi;

	struct bcmasp_res	res;
	unsigned int		crc_fwd;

	/* PHY device */
	struct device_node	*phy_dn;
	struct device_node	*ndev_dn;
	phy_interface_t		phy_interface;
	bool			internal_phy;
	int			old_pause;
	int			old_link;
	int			old_duplex;

	u32			msg_enable;
	/* MIB counters */
	struct bcmasp_mib_counters mib;

	/* Wake-on-LAN */
	u32			wolopts;
	u8			sopass[SOPASS_MAX];
	int			wol_irq;
	unsigned int		wol_irq_disabled:1;
	unsigned int		wol_keep_rx_en:1;

	struct ethtool_eee	eee;
};

#define __BCMASP_IO_MACRO(name, m)					\
static inline u32 name##_rl(struct bcmasp_intf *intf, u32 off)		\
{									\
	u32 reg = readl_relaxed(intf->m + off);			\
	return reg;							\
}									\
static inline void name##_wl(struct bcmasp_intf *intf, u32 val, u32 off)\
{									\
	writel_relaxed(val, intf->m + off);				\
}

#define BCMASP_IO_MACRO(name)		__BCMASP_IO_MACRO(name, res.name)
#define BCMASP_FP_IO_MACRO(name)	__BCMASP_IO_MACRO(name, name)

BCMASP_IO_MACRO(umac);
BCMASP_IO_MACRO(umac2fb);
BCMASP_IO_MACRO(rgmii);
BCMASP_FP_IO_MACRO(tx_spb_dma);
BCMASP_IO_MACRO(tx_spb_ctrl);
BCMASP_IO_MACRO(tx_spb_top);
BCMASP_IO_MACRO(tx_epkt_core);
BCMASP_IO_MACRO(tx_pause_ctrl);
BCMASP_FP_IO_MACRO(rx_edpkt_dma);
BCMASP_FP_IO_MACRO(rx_edpkt_cfg);

#define __BCMASP_FP_IO_MACRO_Q(name, m)					\
static inline u64 name##_rq(struct bcmasp_intf *intf, u32 off)		\
{									\
	u64 reg = readq_relaxed(intf->m + off);				\
	return reg;							\
}									\
static inline void name##_wq(struct bcmasp_intf *intf, u64 val, u32 off)\
{									\
	writeq_relaxed(val, intf->m + off);				\
}

#define BCMASP_FP_IO_MACRO_Q(name)	__BCMASP_FP_IO_MACRO_Q(name, name)

BCMASP_FP_IO_MACRO_Q(tx_spb_dma);
BCMASP_FP_IO_MACRO_Q(rx_edpkt_dma);
BCMASP_FP_IO_MACRO_Q(rx_edpkt_cfg);

#define ASP_RX_NET_FILTER_MAX		32
#define ASP_MAX_FILTER_SIZE		128
struct bcmasp_net_filter {
	struct ethtool_rx_flow_spec	fs;

	bool				reserved;
	bool				claimed;
	bool				wake_filter;

	int				port;
	unsigned int			hw_index;
};

#define ASP_RX_FILTER_MAX		32
struct bcmasp_mda_filter {
	/* Current owner of this filter */
	int		port;
	bool		en;
	u8		addr[ETH_ALEN];
	u8		mask[ETH_ALEN];
};

struct bcmasp_priv {
	struct platform_device		*pdev;
	struct clk			*clk;

	int				irq;
	u32				irq_mask;

	void __iomem			*base;

	unsigned int			intf_count;
	struct bcmasp_intf		**intfs;

	struct bcmasp_mda_filter	mda_filters[ASP_RX_FILTER_MAX];
	unsigned int			filters_count;
	/* MAC destination address filters lock */
	spinlock_t			mda_lock;

	/* Protects accesses to ASP_CTRL_CLOCK_CTRL */
	spinlock_t			clk_lock;

	struct bcmasp_net_filter	net_filters[ASP_RX_NET_FILTER_MAX];
	/* Max amount of filters minus reserved filters */
	unsigned int			net_filters_count_max;
	struct mutex			net_lock;
};

#define PKT_OFFLOAD_NOP			(0 << 28)
#define PKT_OFFLOAD_HDR_OP		(1 << 28)
#define  PKT_OFFLOAD_HDR_WRBACK		BIT(19)
#define  PKT_OFFLOAD_HDR_COUNT(x)	((x) << 16)
#define  PKT_OFFLOAD_HDR_SIZE_1(x)	((x) << 4)
#define  PKT_OFFLOAD_HDR_SIZE_2(x)	(x)
#define  PKT_OFFLOAD_HDR2_SIZE_2(x)	((x) << 24)
#define  PKT_OFFLOAD_HDR2_SIZE_3(x)	((x) << 12)
#define  PKT_OFFLOAD_HDR2_SIZE_4(x)	(x)
#define PKT_OFFLOAD_EPKT_OP		(2 << 28)
#define  PKT_OFFLOAD_EPKT_WRBACK	BIT(23)
#define  PKT_OFFLOAD_EPKT_IP(x)		((x) << 21)
#define  PKT_OFFLOAD_EPKT_TP(x)		((x) << 19)
#define  PKT_OFFLOAD_EPKT_LEN(x)	((x) << 16)
#define  PKT_OFFLOAD_EPKT_CSUM_L3	BIT(15)
#define  PKT_OFFLOAD_EPKT_CSUM_L2	BIT(14)
#define  PKT_OFFLOAD_EPKT_ID(x)		((x) << 12)
#define  PKT_OFFLOAD_EPKT_SEQ(x)	((x) << 10)
#define  PKT_OFFLOAD_EPKT_TS(x)		((x) << 8)
#define  PKT_OFFLOAD_EPKT_BLOC(x)	(x)
#define PKT_OFFLOAD_END_OP		(7 << 28)

struct bcmasp_pkt_offload {
	u32		nop;
	u32		header;
	u32		header2;
	u32		epkt;
	u32		end;
};

#define BCMASP_CORE_IO_MACRO(name, offset)				\
static inline u32 name##_core_rl(struct bcmasp_priv *priv,		\
				 u32 off)				\
{									\
	u32 reg = readl_relaxed(priv->base + (offset) + off);		\
	return reg;							\
}									\
static inline void name##_core_wl(struct bcmasp_priv *priv,		\
				  u32 val, u32 off)			\
{									\
	writel_relaxed(val, priv->base + (offset) + off);		\
}

BCMASP_CORE_IO_MACRO(intr2, ASP_INTR2_OFFSET);
BCMASP_CORE_IO_MACRO(tx_analytics, ASP_TX_ANALYTICS_OFFSET);
BCMASP_CORE_IO_MACRO(rx_analytics, ASP_RX_ANALYTICS_OFFSET);
BCMASP_CORE_IO_MACRO(rx_ctrl, ASP_RX_CTRL_OFFSET);
BCMASP_CORE_IO_MACRO(rx_filter, ASP_RX_FILTER_OFFSET);
BCMASP_CORE_IO_MACRO(rx_edpkt, ASP_EDPKT_OFFSET);
BCMASP_CORE_IO_MACRO(ctrl, ASP_CTRL);

struct bcmasp_intf *bcmasp_interface_create(struct bcmasp_priv *priv,
					    struct device_node *ndev_dn);

void bcmasp_interface_destroy(struct bcmasp_intf *intf, bool unregister);

void bcmasp_enable_tx_irq(struct bcmasp_intf *intf, int en);

void bcmasp_enable_rx_irq(struct bcmasp_intf *intf, int en);

void bcmasp_flush_rx_port(struct bcmasp_intf *intf);

extern const struct ethtool_ops bcmasp_ethtool_ops;

int bcmasp_interface_suspend(struct bcmasp_intf *intf, bool *wol_keep_rx_en);

int bcmasp_interface_resume(struct bcmasp_intf *intf);

void bcmasp_set_promisc(struct bcmasp_intf *intf, bool en);

void bcmasp_set_allmulti(struct bcmasp_intf *intf, bool en);

void bcmasp_set_broad(struct bcmasp_intf *intf, bool en);

void bcmasp_set_oaddr(struct bcmasp_intf *intf, unsigned char *addr, bool en);

int bcmasp_set_en_mda_filter(struct bcmasp_intf *intf, unsigned char *addr,
			     unsigned char *mask);

void bcmasp_disable_all_filters(struct bcmasp_intf *intf);

void bcmasp_core_clock_set_intf(struct bcmasp_intf *intf, bool en);

struct bcmasp_net_filter *bcmasp_netfilt_get_init(struct bcmasp_intf *intf,
						  int loc, bool wake_filter,
						  bool init);

int bcmasp_netfilt_check_dup(struct bcmasp_intf *intf,
			     struct ethtool_rx_flow_spec *fs);

void bcmasp_netfilt_release(struct bcmasp_intf *intf,
			    struct bcmasp_net_filter *nfilt);

int bcmasp_netfilt_get_active(struct bcmasp_intf *intf);

void bcmasp_netfilt_get_all_active(struct bcmasp_intf *intf, u32 *rule_locs,
				   u32 *rule_cnt);

int bcmasp_netfilt_get_max(struct bcmasp_intf *intf);

void bcmasp_netfilt_suspend(struct bcmasp_intf *intf);

void bcmasp_eee_enable_set(struct bcmasp_intf *intf, bool enable);

#endif
