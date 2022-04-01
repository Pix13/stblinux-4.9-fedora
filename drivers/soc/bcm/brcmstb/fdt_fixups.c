// SPDX-License-Identifier: GPL-2.0-only
#include <linux/of.h>
#include <linux/slab.h>
#include <linux/kernel.h>

static int __init brcmstb_fixup_scmi(void)
{
	struct property *prop, *new;
	struct device_node *dn;

	dn = of_find_compatible_node(NULL, NULL, "arm,scmi");
	if (!dn)
		return 0;

	prop = of_find_property(dn, "arm,smc-id", NULL);
	if (!prop)
		goto out;

	prop = of_find_property(dn, "brcm,mboxes", NULL);
	if (!prop)
		goto out;

	new = kzalloc(sizeof(*new), GFP_KERNEL);
	if (!new)
		goto out;

	new->name = kstrdup("mboxes", GFP_KERNEL);
	if (!new->name)
		goto out_free;

	new->length = prop->length;
	new->value = kmalloc(new->length, GFP_KERNEL);
	if (!new->value)
		goto out_free_name;

	memcpy(new->value, prop->value, prop->length);
	of_update_property(dn, new);
	goto out;

out_free_name:
	kfree(new->value);
out_free:
	kfree(new);
out:
	of_node_put(dn);
	return 0;
}

static int __init brcmstb_fdt_fixups(void)
{
	return brcmstb_fixup_scmi();
}
arch_initcall(brcmstb_fdt_fixups);
