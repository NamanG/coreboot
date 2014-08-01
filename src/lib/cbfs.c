/*
 * This file is part of the coreboot project.
 *
 * Copyright (C) 2008, Jordan Crouse <jordan@cosmicpenguin.net>
 * Copyright (C) 2013 The Chromium OS Authors. All rights reserved.
 * Copyright (C) 2014, Naman Govil <namangov@gmail.com>
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; version 2 of the License.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA, 02110-1301 USA
 */

#ifdef LIBPAYLOAD
# include <libpayload-config.h>
# ifdef CONFIG_LZMA
#  include <lzma.h>
#  define CBFS_CORE_WITH_LZMA
# endif
# define CBFS_MINI_BUILD
#elif defined(__SMM__)
# define CBFS_MINI_BUILD
#elif defined(__BOOT_BLOCK__)
  /* No LZMA in boot block. */
#elif defined(__PRE_RAM__) && !CONFIG_COMPRESS_RAMSTAGE
  /* No LZMA in romstage if ramstage is not compressed. */
#else
# define CBFS_CORE_WITH_LZMA
# include <lib.h>
#endif

#include <cbfs.h>
#include <string.h>
#include <cbmem.h>

#ifdef LIBPAYLOAD
# include <stdio.h>
# define DEBUG(x...)
# define LOG(x...) printf(x)
# define ERROR(x...) printf(x)
#else
# include <console/console.h>
# define ERROR(x...) printk(BIOS_ERR, "CBFS: " x)
# define LOG(x...) printk(BIOS_INFO, "CBFS: " x)
# if CONFIG_DEBUG_CBFS
#  define DEBUG(x...) printk(BIOS_SPEW, "CBFS: " x)
# else
#  define DEBUG(x...)
# endif
#endif

#if defined(CONFIG_CBFS_HEADER_ROM_OFFSET) && (CONFIG_CBFS_HEADER_ROM_OFFSET)
# define CBFS_HEADER_ROM_ADDRESS (CONFIG_CBFS_HEADER_ROM_OFFSET)
#else
// Indirect address: only works on 32bit top-aligned systems.
# define CBFS_HEADER_ROM_ADDRESS (*(uint32_t *)0xfffffffc)
#endif

#include "cbfs_core.c"

#ifndef __SMM__
static inline int tohex4(unsigned int c)
{
	return (c <= 9) ? (c + '0') : (c - 10 + 'a');
}

static void tohex16(unsigned int val, char* dest)
{
	dest[0] = tohex4(val>>12);
	dest[1] = tohex4((val>>8) & 0xf);
	dest[2] = tohex4((val>>4) & 0xf);
	dest[3] = tohex4(val & 0xf);
}

void *cbfs_load_optionrom(struct cbfs_media *media, uint16_t vendor,
			  uint16_t device, void *dest)
{
	char name[17] = "pciXXXX,XXXX.rom";
	struct cbfs_optionrom *orom;
	uint8_t *src;

	tohex16(vendor, name+3);
	tohex16(device, name+8);

	orom = (struct cbfs_optionrom *)
	  cbfs_get_file_content(media, name, CBFS_TYPE_OPTIONROM, NULL);

	if (orom == NULL)
		return NULL;

	/* They might have specified a dest address. If so, we can decompress.
	 * If not, there's not much hope of decompressing or relocating the rom.
	 * in the common case, the expansion rom is uncompressed, we
	 * pass 0 in for the dest, and all we have to do is find the rom and
	 * return a pointer to it.
	 */

	/* BUG: the cbfstool is (not yet) including a cbfs_optionrom header */
	src = (uint8_t *)orom; // + sizeof(struct cbfs_optionrom);

	if (! dest)
		return src;

	if (!cbfs_decompress(ntohl(orom->compression),
			     src,
			     dest,
			     ntohl(orom->len)))
		return NULL;

	return dest;
}
/*Loads Stage; reading content that is not compressed
 */
void * cbfs_load_stage(struct cbfs_media *media, const char *name)
{
	struct cbfs_file_handle f;
	struct cbfs_stage stage;
	int c;
	ssize_t value_read;
	void * data;
	ssize_t v_read;
	struct cbfs_media default_media;

	if (media == CBFS_DEFAULT_MEDIA) {
			media = &default_media;
			if (init_default_cbfs_media(media) != 0) {
			ERROR("Failed to initialize default media.\n");
			return NULL;
		}
	}

	c = cbfs_find_file_by_type(media, &f, name, CBFS_TYPE_STAGE);
	if (c < 0) {
		ERROR("Stage not loaded\n");
		return (void *)-1;
	}

	value_read = media->read(media, &stage, f.data_offset, sizeof(stage));
	/* this is a mess. There is no ntohll. */
	/* for now, assume compatible byte order until we solve this. */
	uint32_t entry;
	uint32_t final_size;
	DEBUG("Read complete @offset = %d and length = %d\n", f.data_offset, value_read);
	if (value_read != sizeof(stage))
		return (void *) -1;

	DEBUG("loading stage %s @ 0x%x (%d bytes), entry @ 0x%llx\n",
			name,
			(uint32_t) stage.load, stage.memlen,
			stage.entry);

	if(stage.compression == CBFS_COMPRESS_NONE) //i.e no compression
	{
		//No compression; hence we can directly read
		DEBUG("Read Done\n");
		v_read = media->read(media, (void *) (uintptr_t) stage.load, f.data_offset + sizeof(stage), f.data_len);
		final_size = f.data_len;
	}
	else
	{
		data = media->map(media, f.data_offset + sizeof(stage), f.data_len);
		DEBUG("Map Done\n");
		final_size = cbfs_decompress(stage.compression, data,
				     (void *) (uint32_t) stage.load,
				     stage.len);

		if (!final_size)
			return (void *) -1;
	}

	/* Stages rely the below clearing so that the bss is initialized. */
	memset((void *)((uintptr_t)stage.load + final_size), 0,
	       stage.memlen - final_size);

	DEBUG("stage loaded.\n");

	entry = stage.entry;
	return (void *) entry;
}

/* Simple buffer */

void *cbfs_simple_buffer_map(struct cbfs_simple_buffer *buffer,
			     struct cbfs_media *media,
			     size_t offset, size_t count) {
	void *address = buffer->buffer + buffer->allocated;
	DEBUG("simple_buffer_map(offset=%zd, count=%zd): "
	      "allocated=%zd, size=%zd, last_allocate=%zd\n",
	    offset, count, buffer->allocated, buffer->size,
	    buffer->last_allocate);
	if (buffer->allocated + count >= buffer->size)
		return CBFS_MEDIA_INVALID_MAP_ADDRESS;
	if (media->read(media, address, offset, count) != count) {
		ERROR("simple_buffer: fail to read %zd bytes from 0x%zx\n",
		      count, offset);
		return CBFS_MEDIA_INVALID_MAP_ADDRESS;
	}
	buffer->allocated += count;
	buffer->last_allocate = count;
	return address;
}

void *cbfs_simple_buffer_unmap(struct cbfs_simple_buffer *buffer,
			       const void *address) {
	// TODO Add simple buffer management so we can free more than last
	// allocated one.
	DEBUG("simple_buffer_unmap(address=0x%p): "
	      "allocated=%zd, size=%zd, last_allocate=%zd\n",
	    address, buffer->allocated, buffer->size,
	    buffer->last_allocate);
	if ((buffer->buffer + buffer->allocated - buffer->last_allocate) ==
	    address) {
		buffer->allocated -= buffer->last_allocate;
		buffer->last_allocate = 0;
	}
	return NULL;
}

/**
 * run_address is passed the address of a function taking no parameters and
 * jumps to it, returning the result.
 * @param f the address to call as a function.
 * @return value returned by the function.
 */

int run_address(void *f)
{
	int (*v) (void);
	v = f;
	return v();
}

#endif
