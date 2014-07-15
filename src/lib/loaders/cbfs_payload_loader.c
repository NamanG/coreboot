/*
 * This file is part of the coreboot project.
 *
 * Copyright (C) 2014 Google Inc.
 * Copyright (C) 2014 Naman Govil <namangov@gmail.com>
 *
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
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA
 */

#include <cbfs.h>
#include <payload_loader.h>
#include <cbfs_core.h>

static int cbfs_locate_payload(struct payload *payload)
{
	//void *buffer;
	//size_t size;
	const int type = CBFS_TYPE_PAYLOAD;
	struct cbfs_media default_media, *m;
	struct cbfs_file_handle fh;
	int c;
	m = CBFS_DEFAULT_MEDIA;

	if (m == CBFS_DEFAULT_MEDIA) {
		m = &default_media;
		if (init_default_cbfs_media(m) != 0) {
			//ERROR("Failed to initialize default media\n");
			return -1;
		}
	}

	c = cbfs_find_file(m, &fh, payload->name, type);

	if (c < 0) {
		//ERROR("File not found\n");
		return -1;
	}

	payload->media = m;
	payload->f = fh;
	//payload->backing_store.data = &fh;
	//payload->backing_store.size = fh.data_len;

	return 0;
}

const struct payload_loader_ops cbfs_payload_loader = {
	.name = "CBFS",
	.locate = cbfs_locate_payload,
};
