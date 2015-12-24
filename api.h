/*
 * Copyright (c) 2015 Dmitry Osipenko <digetx@gmail.com>
 *
 *  This program is free software; you can redistribute it and/or modify it
 *  under the terms of the GNU General Public License as published by the
 *  Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful, but WITHOUT
 *  ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 *  FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License
 *  for more details.
 *
 *  You should have received a copy of the GNU General Public License along
 *  with this program; if not, see <http://www.gnu.org/licenses/>.
 */

#define __pak	__attribute__((packed, aligned(1)))

#define REMOTE_IO_PKT_SIZE	10

#define REMOTE_IO_READ		0x0

struct __pak remote_io_read_req {
	uint8_t magic;
	uint32_t address;
	unsigned size:7;
	unsigned on_avp:1;
	uint32_t __pad32;
};

#define REMOTE_IO_READ_RESP	0x1

struct __pak remote_io_read_resp {
	uint8_t magic;
	uint32_t data;
	uint32_t __pad32;
	uint8_t __pad8;
};

#define REMOTE_IO_WRITE		0x2

struct __pak remote_io_write_req {
	uint8_t magic;
	uint32_t address;
	uint32_t value;
	unsigned size:7;
	unsigned on_avp:1;
};

#define REMOTE_IO_IRQ_WATCH	0x3

struct __pak remote_io_irq_watch_req {
	uint8_t magic;
	uint32_t irq_nb;
	uint32_t __pad32;
	uint8_t __pad8;
};

#define REMOTE_IO_IRQ_STS	0x4

struct __pak remote_io_irq_notify {
	uint8_t magic;
	uint8_t bank;
	uint32_t upd;
	uint32_t sts;
};
