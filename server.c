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

#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <strings.h>
#include <unistd.h>

#include <arpa/inet.h>
#include <sys/mman.h>

#include "api.h"

#define PRI_ICTLR_IRQ_LATCHED		0x60004010

#define FOREACH_BIT_SET(val, itr, size)     \
    if (val != 0)                           \
        for (itr = 0; itr < size; itr++)    \
            if ((val >> itr) & 1)

static int csock;

static pthread_mutex_t irq_upd_mutex = PTHREAD_MUTEX_INITIALIZER;

static uint32_t irqs_to_watch[4];
static uint32_t irqs_status[4];

static void *mem_virt;

static void map_mem(off_t phys_address, off_t size)
{
	off_t PageOffset, PageAddress;
	size_t PagesSize;
	int mem_dev;

	mem_dev = open("/dev/mem", O_RDWR | O_SYNC);
	assert(mem_dev != -1);

	PageOffset  = phys_address % getpagesize();
	PageAddress = phys_address - PageOffset;
	PagesSize   = ((size / getpagesize()) + 1) * getpagesize();

	mem_virt = mmap(NULL, PagesSize, PROT_READ | PROT_WRITE,
			MAP_SHARED, mem_dev, PageAddress);

	assert(mem_virt != MAP_FAILED);

	mem_virt += PageOffset >> 2;
}

static uint32_t mem_read(uint32_t offset, int size)
{
	switch (size) {
	case 8:
		return *(volatile uint8_t*)(mem_virt + offset);
	case 16:
		return *(volatile uint16_t*)(mem_virt + offset);
	case 32:
		return *(volatile uint32_t*)(mem_virt + offset);
	default:
		abort();
	}
}

static void mem_write(uint32_t value, uint32_t offset, int size)
{
	switch (size) {
	case 8:
		*(volatile uint8_t*)(mem_virt + offset) = value;
		break;
	case 16:
		*(volatile uint16_t*)(mem_virt + offset) = value;
		break;
	case 32:
		*(volatile uint32_t*)(mem_virt + offset) = value;
		break;
	default:
		abort();
	}
}

static uint32_t cpu_read(uint32_t offset, int size)
{
	uint32_t ret;

	printf("CPU read%d:  [0x%08X] = ", size, offset);

	ret = mem_read(offset, size);

	printf("0x%08X\n", ret);

	return ret;
}

static void cpu_write(uint32_t value, uint32_t offset, int size)
{
	printf("CPU write%d: [0x%08X] = 0x%08X\n", size, offset, value);
	mem_write(value, offset, size);
}

static int recv_all(int fd, void *_buf, int len1)
{
	int ret, len;
	uint8_t *buf = _buf;

	len = len1;
	while ((len > 0) && (ret = read(fd, buf, len)) != 0) {
		if (ret < 0) {
			if (errno != EINTR && errno != EAGAIN) {
				return -1;
			}
			continue;
		} else {
			buf += ret;
			len -= ret;
		}
	}
	return len1 - len;
}

static int send_all(int fd, const void *_buf, int len1)
{
	int ret, len;
	const uint8_t *buf = _buf;

	len = len1;
	while (len > 0) {
		ret = write(fd, buf, len);
		if (ret < 0) {
			if (errno != EINTR && errno != EAGAIN)
				return -1;
		} else if (ret == 0) {
			break;
		} else {
			buf += ret;
			len -= ret;
		}
	}
	return len1 - len;
}

static void irq_sts_upd_poll(void)
{
	uint32_t new_sts;
	uint32_t upd_sts;
	int bank;
	int i;

	if (pthread_mutex_trylock(&irq_upd_mutex) != 0) {
		return;
	}

	for (bank = 0; bank < 4; bank++) {
		struct remote_io_irq_notify notify = {
			.magic = REMOTE_IO_IRQ_STS,
		};

		if (irqs_to_watch[bank] == 0) {
			continue;
		}

		new_sts = mem_read(PRI_ICTLR_IRQ_LATCHED + bank * 0x100, 32);
		new_sts = new_sts & irqs_to_watch[bank];
		upd_sts = irqs_status[bank] ^ new_sts;

		if (upd_sts == 0) {
			continue;
		}

		FOREACH_BIT_SET(upd_sts, i, 32) {
			int irq_nb = bank * 32 + i;

			printf("IRQ %d update %d\n",
				   irq_nb, !!(new_sts & (1 << i)));
		}

		irqs_status[bank] = new_sts;

		notify.bank = bank;
		notify.sts  = new_sts;
		notify.upd  = upd_sts;

		send_all(csock, &notify, sizeof(notify));
	}

	pthread_mutex_unlock(&irq_upd_mutex);

	if (errno != 0) {
		perror("");
	}
}

static void * irq_watcher(void *arg)
{
	for (;;) {
		irq_sts_upd_poll();
		usleep(1000);
	}

	return NULL;
}

static int setup_socket(int portno)
{
	struct sockaddr_in serveraddr = {
		.sin_family = AF_INET,
		.sin_addr.s_addr = htonl(INADDR_ANY),
		.sin_port = htons(portno),
	};
	int optval = 1;
	int psock;

	psock = socket(AF_INET, SOCK_STREAM, 0);
	assert(errno == 0);

	setsockopt(psock, SOL_SOCKET, SO_REUSEADDR,
		   (const void *)&optval , sizeof(int));

	bind(psock, (struct sockaddr *) &serveraddr, sizeof(serveraddr));
	assert(errno == 0);

	listen(psock, 1);
	assert(errno == 0);

	return psock;
}

int main(void)
{
	pthread_t irq_poll_thread;
	int psock;

	map_mem(0x0, 0x70000000);
	psock = setup_socket(45312);

	assert(pthread_create(&irq_poll_thread, NULL, irq_watcher, NULL) == 0);

	setbuf(stdout, NULL);

	for (;;) {
		printf("Waiting for connection...\n");

		csock = accept(psock, NULL, NULL);

		if (csock == -1) {
			abort();
		}

		for (;;) {
			char buf[REMOTE_IO_PKT_SIZE];
			int magic;

			magic = recv_all(csock, buf, sizeof(buf));

			if (errno != 0 || magic != sizeof(buf)) {
				break;
			}

			magic = buf[0];

			switch (magic) {
			case REMOTE_IO_READ:
			{
				struct remote_io_read_req *req = (void *) buf;
				struct remote_io_read_resp resp = {
					.magic = REMOTE_IO_READ_RESP,
					.data = cpu_read(req->address, req->size),
				};

				send_all(csock, &resp, sizeof(resp));

				if (errno != 0) {
					break;
				}

				irq_sts_upd_poll();
				break;
			}
			case REMOTE_IO_WRITE:
			{
				struct remote_io_write_req *req = (void *) buf;

				cpu_write(req->value, req->address, req->size);

				irq_sts_upd_poll();
				break;
			}
			case REMOTE_IO_IRQ_WATCH:
			{
				struct remote_io_irq_watch_req *req = (void *) buf;
				unsigned bank = req->irq_nb >> 5;

				if (bank > 3) {
					abort();
				}

				irqs_to_watch[bank] |= 1 << (req->irq_nb & 0x1F);

				printf("Enabled watch for IRQ %d\n", req->irq_nb);

				break;
			}
			default:
				fprintf(stderr, "Bad magic %X\n", magic);
				errno = EINVAL;
				break;
			}

			if (errno != 0) {
				break;
			}
		}

		pthread_mutex_lock(&irq_upd_mutex);

		bzero(irqs_to_watch, sizeof(irqs_to_watch));
		bzero(irqs_status, sizeof(irqs_status));

		pthread_mutex_unlock(&irq_upd_mutex);

		perror("Closing connection");
		close(csock);
	}

	return 0;
}
