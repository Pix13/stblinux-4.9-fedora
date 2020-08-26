// SPDX-License-Identifier: GPL-2.0
#define pr_fmt(fmt)				"bcmasp_ethtool: " fmt

#include <linux/ethtool.h>
#include <linux/netdevice.h>
#include <linux/platform_device.h>

#include "bcmasp.h"
#include "bcmasp_intf_defs.h"

/* standard ethtool support functions. */
enum bcmasp_stat_type {
	BCMASP_STAT_NETDEV = -1,
	BCMASP_STAT_MIB_RX,
	BCMASP_STAT_MIB_TX,
	BCMASP_STAT_RUNT,
	BCMASP_STAT_RX_EDPKT,
	BCMASP_STAT_RX_CTRL,
	BCMASP_STAT_SOFT,
};

struct bcmasp_stats {
	char stat_string[ETH_GSTRING_LEN];
	int stat_sizeof;
	int stat_offset;
	enum bcmasp_stat_type type;
	/* register offset from base for misc counters */
	u16 reg_offset;
};

#define STAT_NETDEV(m) { \
	.stat_string = __stringify(m), \
	.stat_sizeof = sizeof(((struct net_device_stats *)0)->m), \
	.stat_offset = offsetof(struct net_device_stats, m), \
	.type = BCMASP_STAT_NETDEV, \
}

#define STAT_BCMASP_MIB(str, m, _type) { \
	.stat_string = str, \
	.stat_sizeof = sizeof(((struct bcmasp_intf *)0)->m), \
	.stat_offset = offsetof(struct bcmasp_intf, m), \
	.type = _type, \
}

#define STAT_BCMASP_OFFSET(str, m, _type, offset) { \
	.stat_string = str, \
	.stat_sizeof = sizeof(((struct bcmasp_intf *)0)->m), \
	.stat_offset = offsetof(struct bcmasp_intf, m), \
	.type = _type, \
	.reg_offset = offset, \
}

#define STAT_BCMASP_MIB_RX(str, m) \
	STAT_BCMASP_MIB(str, m, BCMASP_STAT_MIB_RX)
#define STAT_BCMASP_MIB_TX(str, m) \
	STAT_BCMASP_MIB(str, m, BCMASP_STAT_MIB_TX)
#define STAT_BCMASP_RUNT(str, m) \
	STAT_BCMASP_MIB(str, m, BCMASP_STAT_RUNT)
#define STAT_BCMASP_RX_EDPKT(str, m, offset) \
	STAT_BCMASP_OFFSET(str, m, BCMASP_STAT_RX_EDPKT, offset)
#define STAT_BCMASP_RX_CTRL(str, m, offset) \
	STAT_BCMASP_OFFSET(str, m, BCMASP_STAT_RX_CTRL, offset)
#define STAT_BCMASP_SOFT_MIB(m) \
	STAT_BCMASP_MIB(__stringify(m), mib.m, BCMASP_STAT_SOFT)

/* There is a 0x10 gap in hardware between the end of RX and beginning of TX
 * stats and then between the end of TX stats and the beginning of the RX RUNT.
 * The software structure already accounts for sizeof(u32) between members so
 * need to add 0xc to offset correctly into the hardware register.
 */
#define BCMASP_STAT_OFFSET	0xc

/* Hardware counters must be kept in sync because the order/offset
 * is important here (order in structure declaration = order in hardware)
 */
static const struct bcmasp_stats bcmasp_gstrings_stats[] = {
	/* general stats */
	STAT_NETDEV(rx_packets),
	STAT_NETDEV(tx_packets),
	STAT_NETDEV(rx_bytes),
	STAT_NETDEV(tx_bytes),
	STAT_NETDEV(rx_errors),
	STAT_NETDEV(tx_errors),
	STAT_NETDEV(rx_dropped),
	STAT_NETDEV(tx_dropped),
	STAT_NETDEV(multicast),
	/* UniMAC RSV counters */
	STAT_BCMASP_MIB_RX("rx_64_octets", mib.rx.pkt_cnt.cnt_64),
	STAT_BCMASP_MIB_RX("rx_65_127_oct", mib.rx.pkt_cnt.cnt_127),
	STAT_BCMASP_MIB_RX("rx_128_255_oct", mib.rx.pkt_cnt.cnt_255),
	STAT_BCMASP_MIB_RX("rx_256_511_oct", mib.rx.pkt_cnt.cnt_511),
	STAT_BCMASP_MIB_RX("rx_512_1023_oct", mib.rx.pkt_cnt.cnt_1023),
	STAT_BCMASP_MIB_RX("rx_1024_1518_oct", mib.rx.pkt_cnt.cnt_1518),
	STAT_BCMASP_MIB_RX("rx_vlan_1519_1522_oct", mib.rx.pkt_cnt.cnt_mgv),
	STAT_BCMASP_MIB_RX("rx_1522_2047_oct", mib.rx.pkt_cnt.cnt_2047),
	STAT_BCMASP_MIB_RX("rx_2048_4095_oct", mib.rx.pkt_cnt.cnt_4095),
	STAT_BCMASP_MIB_RX("rx_4096_9216_oct", mib.rx.pkt_cnt.cnt_9216),
	STAT_BCMASP_MIB_RX("rx_pkts", mib.rx.pkt),
	STAT_BCMASP_MIB_RX("rx_bytes", mib.rx.bytes),
	STAT_BCMASP_MIB_RX("rx_multicast", mib.rx.mca),
	STAT_BCMASP_MIB_RX("rx_broadcast", mib.rx.bca),
	STAT_BCMASP_MIB_RX("rx_fcs", mib.rx.fcs),
	STAT_BCMASP_MIB_RX("rx_control", mib.rx.cf),
	STAT_BCMASP_MIB_RX("rx_pause", mib.rx.pf),
	STAT_BCMASP_MIB_RX("rx_unknown", mib.rx.uo),
	STAT_BCMASP_MIB_RX("rx_align", mib.rx.aln),
	STAT_BCMASP_MIB_RX("rx_outrange", mib.rx.flr),
	STAT_BCMASP_MIB_RX("rx_code", mib.rx.cde),
	STAT_BCMASP_MIB_RX("rx_carrier", mib.rx.fcr),
	STAT_BCMASP_MIB_RX("rx_oversize", mib.rx.ovr),
	STAT_BCMASP_MIB_RX("rx_jabber", mib.rx.jbr),
	STAT_BCMASP_MIB_RX("rx_mtu_err", mib.rx.mtue),
	STAT_BCMASP_MIB_RX("rx_good_pkts", mib.rx.pok),
	STAT_BCMASP_MIB_RX("rx_unicast", mib.rx.uc),
	STAT_BCMASP_MIB_RX("rx_ppp", mib.rx.ppp),
	STAT_BCMASP_MIB_RX("rx_crc", mib.rx.rcrc),
	/* UniMAC TSV counters */
	STAT_BCMASP_MIB_TX("tx_64_octets", mib.tx.pkt_cnt.cnt_64),
	STAT_BCMASP_MIB_TX("tx_65_127_oct", mib.tx.pkt_cnt.cnt_127),
	STAT_BCMASP_MIB_TX("tx_128_255_oct", mib.tx.pkt_cnt.cnt_255),
	STAT_BCMASP_MIB_TX("tx_256_511_oct", mib.tx.pkt_cnt.cnt_511),
	STAT_BCMASP_MIB_TX("tx_512_1023_oct", mib.tx.pkt_cnt.cnt_1023),
	STAT_BCMASP_MIB_TX("tx_1024_1518_oct", mib.tx.pkt_cnt.cnt_1518),
	STAT_BCMASP_MIB_TX("tx_vlan_1519_1522_oct", mib.tx.pkt_cnt.cnt_mgv),
	STAT_BCMASP_MIB_TX("tx_1522_2047_oct", mib.tx.pkt_cnt.cnt_2047),
	STAT_BCMASP_MIB_TX("tx_2048_4095_oct", mib.tx.pkt_cnt.cnt_4095),
	STAT_BCMASP_MIB_TX("tx_4096_9216_oct", mib.tx.pkt_cnt.cnt_9216),
	STAT_BCMASP_MIB_TX("tx_pkts", mib.tx.pkts),
	STAT_BCMASP_MIB_TX("tx_multicast", mib.tx.mca),
	STAT_BCMASP_MIB_TX("tx_broadcast", mib.tx.bca),
	STAT_BCMASP_MIB_TX("tx_pause", mib.tx.pf),
	STAT_BCMASP_MIB_TX("tx_control", mib.tx.cf),
	STAT_BCMASP_MIB_TX("tx_fcs_err", mib.tx.fcs),
	STAT_BCMASP_MIB_TX("tx_oversize", mib.tx.ovr),
	STAT_BCMASP_MIB_TX("tx_defer", mib.tx.drf),
	STAT_BCMASP_MIB_TX("tx_excess_defer", mib.tx.edf),
	STAT_BCMASP_MIB_TX("tx_single_col", mib.tx.scl),
	STAT_BCMASP_MIB_TX("tx_multi_col", mib.tx.mcl),
	STAT_BCMASP_MIB_TX("tx_late_col", mib.tx.lcl),
	STAT_BCMASP_MIB_TX("tx_excess_col", mib.tx.ecl),
	STAT_BCMASP_MIB_TX("tx_frags", mib.tx.frg),
	STAT_BCMASP_MIB_TX("tx_total_col", mib.tx.ncl),
	STAT_BCMASP_MIB_TX("tx_jabber", mib.tx.jbr),
	STAT_BCMASP_MIB_TX("tx_bytes", mib.tx.bytes),
	STAT_BCMASP_MIB_TX("tx_good_pkts", mib.tx.pok),
	STAT_BCMASP_MIB_TX("tx_unicast", mib.tx.uc),
	/* UniMAC RUNT counters */
	STAT_BCMASP_RUNT("rx_runt_pkts", mib.rx_runt_cnt),
	STAT_BCMASP_RUNT("rx_runt_valid_fcs", mib.rx_runt_fcs),
	STAT_BCMASP_RUNT("rx_runt_inval_fcs_align", mib.rx_runt_fcs_align),
	STAT_BCMASP_RUNT("rx_runt_bytes", mib.rx_runt_bytes),
	/* EDPKT counters */
	STAT_BCMASP_RX_EDPKT("edpkt_ts", mib.edpkt_ts,
			     ASP_EDPKT_RX_TS_COUNTER),
	STAT_BCMASP_RX_EDPKT("edpkt_rx_pkt_cnt", mib.edpkt_rx_pkt_cnt,
			     ASP_EDPKT_RX_PKT_CNT),
	STAT_BCMASP_RX_EDPKT("edpkt_hdr_ext_cnt", mib.edpkt_hdr_ext_cnt,
			     ASP_EDPKT_HDR_EXTR_CNT),
	STAT_BCMASP_RX_EDPKT("edpkt_hdr_out_cnt", mib.edpkt_hdr_out_cnt,
			     ASP_EDPKT_HDR_OUT_CNT),
	/* ASP RX control */
	STAT_BCMASP_RX_CTRL("umac_frm_cnt", mib.umac_frm_cnt,
			    ASP_RX_CTRL_UMAC_0_FRAME_COUNT),
	STAT_BCMASP_RX_CTRL("fb_out_frm_cnt", mib.fb_out_frm_cnt,
			    ASP_RX_CTRL_FB_OUT_FRAME_COUNT),
	STAT_BCMASP_RX_CTRL("fb_filt_out_frm_cnt", mib.fb_filt_out_frm_cnt,
			    ASP_RX_CTRL_FB_FILT_OUT_FRAME_COUNT),
	/* Software maintained statistics */
	STAT_BCMASP_SOFT_MIB(alloc_rx_buff_failed),
	STAT_BCMASP_SOFT_MIB(alloc_rx_skb_failed),
	STAT_BCMASP_SOFT_MIB(rx_dma_failed),
	STAT_BCMASP_SOFT_MIB(tx_dma_failed),
	STAT_BCMASP_SOFT_MIB(mc_filters_full_cnt),
	STAT_BCMASP_SOFT_MIB(uc_filters_full_cnt),
	STAT_BCMASP_SOFT_MIB(filters_combine_cnt),
	STAT_BCMASP_SOFT_MIB(promisc_filters_cnt),

};

#define BCMASP_STATS_LEN	ARRAY_SIZE(bcmasp_gstrings_stats)

static int bcmasp_get_sset_count(struct net_device *dev, int string_set)
{
	switch (string_set) {
	case ETH_SS_STATS:
		return BCMASP_STATS_LEN;
	default:
		return -EOPNOTSUPP;
	}
}

static void bcmasp_get_strings(struct net_device *dev, u32 stringset,
			       u8 *data)
{
	int i;

	switch (stringset) {
	case ETH_SS_STATS:
		for (i = 0; i < BCMASP_STATS_LEN; i++) {
			memcpy(data + i * ETH_GSTRING_LEN,
			       bcmasp_gstrings_stats[i].stat_string,
			       ETH_GSTRING_LEN);
		}
		break;
	}
}

static void bcmasp_update_mib_counters(struct bcmasp_intf *priv)
{
	int i, j = 0;

	for (i = 0; i < BCMASP_STATS_LEN; i++) {
		const struct bcmasp_stats *s;
		u16 offset = 0;
		u32 val = 0;
		char *p;

		s = &bcmasp_gstrings_stats[i];
		switch (s->type) {
		case BCMASP_STAT_NETDEV:
		case BCMASP_STAT_SOFT:
			continue;
		case BCMASP_STAT_RUNT:
			offset += BCMASP_STAT_OFFSET;
			/* fall through */
		case BCMASP_STAT_MIB_TX:
			offset += BCMASP_STAT_OFFSET;
			/* fall through */
		case BCMASP_STAT_MIB_RX:
			val = umac_rl(priv, UMC_MIB_START + j + offset);
			offset = 0;	/* Reset Offset */
			break;
		case BCMASP_STAT_RX_EDPKT:
			val = rx_edpkt_core_rl(priv->parent, s->reg_offset);
			break;
		case BCMASP_STAT_RX_CTRL:
			offset = s->reg_offset;
			if (offset == ASP_RX_CTRL_UMAC_0_FRAME_COUNT)
				offset += sizeof(u32) * priv->port;
			val = rx_ctrl_core_rl(priv->parent, offset);
			break;
		}

		j += s->stat_sizeof;
		p = (char *)priv + s->stat_offset;
		*(u32 *)p = val;
	}
}

static void bcmasp_get_ethtool_stats(struct net_device *dev,
				     struct ethtool_stats *stats,
				     u64 *data)
{
	struct bcmasp_intf *priv = netdev_priv(dev);
	int i;

	if (netif_running(dev))
		bcmasp_update_mib_counters(priv);

	dev->netdev_ops->ndo_get_stats(dev);

	for (i = 0; i < BCMASP_STATS_LEN; i++) {
		const struct bcmasp_stats *s;
		char *p;

		s = &bcmasp_gstrings_stats[i];
		if (s->type == BCMASP_STAT_NETDEV)
			p = (char *)&dev->stats;
		else
			p = (char *)priv;
		p += s->stat_offset;
		if (sizeof(unsigned long) != sizeof(u32) &&
		    s->stat_sizeof == sizeof(unsigned long))
			data[i] = *(unsigned long *)p;
		else
			data[i] = *(u32 *)p;
	}
}

static void bcmasp_get_drvinfo(struct net_device *dev,
			       struct ethtool_drvinfo *info)
{
	strlcpy(info->driver, "bcmasp", sizeof(info->driver));
	strlcpy(info->version, "v2.0", sizeof(info->version));
}

static int bcmasp_get_link_ksettings(struct net_device *dev,
				      struct ethtool_link_ksettings *cmd)
{
	if (!netif_running(dev))
		return -EINVAL;

	if (!dev->phydev)
		return -ENODEV;

	return phy_ethtool_ksettings_get(dev->phydev, cmd);
}

static int bcmasp_set_link_ksettings(struct net_device *dev,
				      const struct ethtool_link_ksettings *cmd)
{
	if (!netif_running(dev))
		return -EINVAL;

	if (!dev->phydev)
		return -ENODEV;

	return phy_ethtool_ksettings_set(dev->phydev, cmd);
}

static u32 bcmasp_get_msglevel(struct net_device *dev)
{
	struct bcmasp_intf *intf = netdev_priv(dev);

	return intf->msg_enable;
}

static void bcmasp_set_msglevel(struct net_device *dev, u32 level)
{
	struct bcmasp_intf *intf = netdev_priv(dev);

	intf->msg_enable = level;
}

static int bcmasp_nway_reset(struct net_device *dev)
{
	if (!dev->phydev)
		return -ENODEV;

	return genphy_restart_aneg(dev->phydev);
}

static void bcmasp_get_wol(struct net_device *dev, struct ethtool_wolinfo *wol)
{
	struct bcmasp_intf *intf = netdev_priv(dev);

	wol->supported = WAKE_MAGIC | WAKE_MAGICSECURE;
	wol->wolopts = intf->wolopts;
	memset(wol->sopass, 0, sizeof(wol->sopass));

	if (wol->wolopts & WAKE_MAGICSECURE)
		memcpy(wol->sopass, intf->sopass, sizeof(intf->sopass));
}

static int bcmasp_set_wol(struct net_device *dev, struct ethtool_wolinfo *wol)
{
	struct bcmasp_intf *intf = netdev_priv(dev);
	struct device *kdev = &intf->parent->pdev->dev;

	if (!device_can_wakeup(kdev))
		return -EOPNOTSUPP;

	if (wol->wolopts & ~(WAKE_MAGIC | WAKE_MAGICSECURE))
		return -EINVAL;

	if (wol->wolopts & WAKE_MAGICSECURE)
		memcpy(intf->sopass, wol->sopass, sizeof(wol->sopass));

	if (wol->wolopts) {
		device_set_wakeup_enable(kdev, 1);
		if (intf->wol_irq_disabled)
			enable_irq_wake(intf->wol_irq);
		intf->wol_irq_disabled = false;
	} else {
		device_set_wakeup_enable(kdev, 0);
		if (!intf->wol_irq_disabled)
			disable_irq_wake(intf->wol_irq);
		intf->wol_irq_disabled = true;
	}

	intf->wolopts = wol->wolopts;

	return 0;
}

const struct ethtool_ops bcmasp_ethtool_ops = {
	.get_drvinfo		= bcmasp_get_drvinfo,
	.get_wol		= bcmasp_get_wol,
	.set_wol		= bcmasp_set_wol,
	.get_link		= ethtool_op_get_link,
	.get_strings		= bcmasp_get_strings,
	.get_ethtool_stats	= bcmasp_get_ethtool_stats,
	.get_sset_count		= bcmasp_get_sset_count,
	.get_link_ksettings	= bcmasp_get_link_ksettings,
	.set_link_ksettings	= bcmasp_set_link_ksettings,
	.get_msglevel		= bcmasp_get_msglevel,
	.set_msglevel		= bcmasp_set_msglevel,
	.nway_reset		= bcmasp_nway_reset,
};
