// SPDX-License-Identifier: BSD-2-Clause-Views
/*
 * Copyright (c) 2021-2023 The Regents of the University of California
 */

#include "mqnic.h"

struct register_description
{
	u32 type;
	u32 version;
	const char* description;
};

struct register_description s_registers[] = {
		{0x0, 0x0, "Null register block"},
		{0xFFFFFFFF, 0x00000100, "Firmware ID register block"},
		{0x0000C000, 0x00000100, "Interface register block"},
		{0x0000C001, 0x00000400, "Interface control register block"},
		{0x0000C002, 0x00000200, "Port register block"},
		{0x0000C003, 0x00000200, "Port control register block"},
		{0x0000C004, 0x00000300, "Scheduler block register block"},
		{0x0000C005, 0x00000200, "App info register block"},
		{0x0000C006, 0x00000100, "stats"},
		{0x0000C007, 0x00000100, "IRQ config"},
		{0x0000C008, 0x00000100, "Clock info register block"},
		{0x0000C010, 0x00000400, "Event queue manager register block"},
		{0x0000C020, 0x00000400, "Completion queue manager register block"},
		{0x0000C030, 0x00000400, "Transmit queue manager register block"},
		{0x0000C031, 0x00000400, "Receive queue manager register block"},
		{0x0000C040, 0x00000100, "Round-robin scheduler register block"},
		{0x0000C050, 0x00000100, "TDMA scheduler controller register block"},
		{0x0000C060, 0x00000100, "TDMA scheduler register block"},
		{0x0000C080, 0x00000100, "PTP hardware clock register block"},
		{0x0000C081, 0x00000100, "PTP period output register block"},
		{0x0000C090, 0x00000200, "RX queue map register block"},
		{0x0000C100, 0x00000100, "GPIO register block"},
		{0x0000C110, 0x00000100, "I2C register block"},
		{0x0000C120, 0x00000200, "SPI flash register block"},
		{0x0000C121, 0x00000200, "BPI flash register block"},
		{0x0000C140, 0x00000100, "Alveo BMC register block"},
		{0x0000C141, 0x00000100, "Gecko BMC register block"},
		{0x0000C150, 0x00000100, "DRP register block"},
		{0x0, 0x0, 0x0}
};

const struct register_description* find_reg_description(u32 reg_type)
{
	struct register_description *reg = s_registers;
	for (; reg->description != NULL; ++reg)
	{
		if (reg->type == reg_type)
			break;
	}

	return reg;
}

struct mqnic_reg_block *mqnic_enumerate_reg_block_list(u8 __iomem *base, size_t offset, size_t size)
{
	int max_count = 8;
	struct mqnic_reg_block *reg_block_list = kzalloc(max_count * sizeof(struct mqnic_reg_block), GFP_KERNEL);
	int count = 0;
	int k;

	u8 __iomem *ptr;

	u32 rb_type;
	u32 rb_version;
	const struct register_description *reg_description = 0;

	if (!reg_block_list)
		return NULL;

	while (1) {
		reg_block_list[count].type = 0;
		reg_block_list[count].version = 0;
		reg_block_list[count].base = 0;
		reg_block_list[count].regs = 0;

		if ((offset == 0 && count != 0) || offset >= size)
			break;

		ptr = base + offset;

		for (k = 0; k < count; k++)
		{
			if (ptr == reg_block_list[k].regs)
			{
				pr_err("Register blocks form a loop");
				goto fail;
			}
		}

		rb_type = ioread32(ptr + MQNIC_RB_REG_TYPE);
		rb_version = ioread32(ptr + MQNIC_RB_REG_VER);
		offset = ioread32(ptr + MQNIC_RB_REG_NEXT_PTR);

		reg_block_list[count].type = rb_type;
		reg_block_list[count].version = rb_version;
		reg_block_list[count].base = base;
		reg_block_list[count].regs = ptr;

		reg_description = find_reg_description(rb_type);
		printk(KERN_INFO "OFFSET 0x%08lx TYPE 0x%08x (%s) "
						 "VERSION: 0x%08x VERSION_DOC: 0x%08x", ptr-base, rb_type, reg_description->description,
			   rb_version, reg_description->version);

		count++;

		if (count >= max_count) {
			struct mqnic_reg_block *tmp;
			max_count += 4;
			tmp = krealloc(reg_block_list, max_count * sizeof(struct mqnic_reg_block), GFP_KERNEL);
			if (!tmp)
				goto fail;
			reg_block_list = tmp;
		}
	}

	printk(KERN_INFO "mqnic_reg_block count %i", count);
	return reg_block_list;
fail:
	kfree(reg_block_list);
	return NULL;
}
EXPORT_SYMBOL(mqnic_enumerate_reg_block_list);

struct mqnic_reg_block *mqnic_find_reg_block(struct mqnic_reg_block *list, u32 type, u32 version, int index)
{
	struct mqnic_reg_block *rb = list;

	while (rb->regs) {
		if (rb->type == type && (!version || rb->version == version)) {
			if (index > 0)
				index--;
			else
				return rb;
		}

		rb++;
	}

	return NULL;
}
EXPORT_SYMBOL(mqnic_find_reg_block);

void mqnic_free_reg_block_list(struct mqnic_reg_block *list)
{
	kfree(list);
}
EXPORT_SYMBOL(mqnic_free_reg_block_list);
