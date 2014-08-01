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
	const int type = CBFS_TYPE_PAYLOAD;
	struct cbfs_media default_media, *m;

	m = &default_media;
	if (init_default_cbfs_media(m) != 0)
		return -1;

	if (cbfs_find_file_by_type(m, &payload->f, payload->name, type) < 0)
		return -1;

	payload->media = CBFS_DEFAULT_MEDIA;

	return 0;
}

const struct payload_loader_ops cbfs_payload_loader = {
	.name = "CBFS",
	.locate = cbfs_locate_payload,
};
