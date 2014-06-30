/*
 * This file is part of the coreboot project.
 *
 * Copyright (C) 2011 secunet Security Networks AG
 * Copyright (C) 2013 The Chromium OS Authors. All rights reserved.
 * Copyright (C) 2014 Naman Govil <namangov@gmail.com>
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. The name of the author may not be used to endorse or promote products
 *    derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

/* The CBFS core requires a couple of #defines or functions to adapt it to the
 * target environment:
 *
 * CBFS_CORE_WITH_LZMA (must be #define)
 *      if defined, ulzma() must exist for decompression of data streams
 *
 * CBFS_HEADER_ROM_ADDRESS
 *	ROM address (offset) of CBFS header. Underlying CBFS media may interpret
 *	it in other way so we call this "address".
 *
 * ERROR(x...)
 *      print an error message x (in printf format)
 *
 * LOG(x...)
 *      print a message x (in printf format)
 *
 * DEBUG(x...)
 *      print a debug message x (in printf format)
 *
 */

#include <cbfs.h>
#include <string.h>

/* fills in the header structure with a pointer to CBFS master header,
   returns 0 on success and <0 if header not found */
int cbfs_get_header(struct cbfs_media *media, struct cbfs_header *header)
{
	struct cbfs_media default_media;
	ssize_t header_size;

	if (media == CBFS_DEFAULT_MEDIA) {
		media = &default_media;
		if (init_default_cbfs_media(media) != 0) {
			ERROR("Failed to initialize default media.\n");
			return -1;
		}
	}

	media->open(media);
	DEBUG("CBFS_HEADER_ROM_ADDRESS: 0x%x/0x%x\n", CBFS_HEADER_ROM_ADDRESS,
	      CONFIG_ROM_SIZE);
	header_size = media->read(media, (void *)header ,
			CBFS_HEADER_ROM_ADDRESS, sizeof(*header));
	media->close(media);

	header->offset = ntohl(header->offset);
	header->align = ntohl(header->align);
	header->romsize = ntohl(header->romsize);
	header->magic = ntohl(header->magic);
	header->version = ntohl(header->version);
	header->architecture = ntohl(header->architecture);
	header->bootblocksize = ntohl(header->bootblocksize);
	header->pad[1] = ntohl(header->pad[1]);

	if (header_size != sizeof(*header)) {
		ERROR("Failed to load CBFS header from 0x%x\n",
		      CBFS_HEADER_ROM_ADDRESS);
		return -1;
	}
	else if (CBFS_HEADER_MAGIC != header->magic) {
		ERROR("Could not find valid CBFS master header at %x: "
		      "%x vs %x.\n", CBFS_HEADER_ROM_ADDRESS, CBFS_HEADER_MAGIC,
		      header->magic);
		if (header->magic == 0xffffffff) {
			ERROR("Maybe ROM is not mapped properly?\n");
		}
		return -1;
	}
	return 0;
}

/* public API starts here*/
/* This functions finds the absolute data_offset of a file searched for by
   name. Returns 0 on success and -1 on failure
 */
int cbfs_find_file(struct cbfs_media *media, struct cbfs_file_handle *f,
		const char *name)
{
	uint32_t offset, align, romsize,name_len;
	struct cbfs_media default_media;
	ssize_t value_read;
	const char *file_name;
	struct cbfs_header header;

	if (media == CBFS_DEFAULT_MEDIA) {
		media = &default_media;
		if (init_default_cbfs_media(media) != 0) {
			ERROR("Failed to initialize default media.\n");
			return -1;
		}
	}

	if (cbfs_get_header(media, &header))
		return -1;

	// Offset (for source media) of first file.
	offset = header.offset;
	align = header.align;
	romsize = header.romsize;

#if defined(CONFIG_ARCH_X86) && CONFIG_ARCH_X86
	romsize -= header.bootblocksize;
#endif
	DEBUG("CBFS location: 0x%x~0x%x, align: %d\n", offset, romsize, align);
	DEBUG("Looking for '%s' starting from 0x%x.\n", name, offset);
	media->open(media);
	while (offset < romsize)
	{
		value_read = media->read(media, &f->file, offset, sizeof(f->file));
		if(value_read != sizeof(f->file)){
			return -1;
		}
		f->file.len = ntohl(f->file.len);
		f->file.offset = ntohl(f->file.offset);
		f->file.type = ntohl(f->file.type);

		if (memcmp(CBFS_FILE_MAGIC, f->file.magic,
			   sizeof(f->file.magic)) != 0) {
			uint32_t new_align = align;
			if (offset % align)
				new_align += align - (offset % align);
			ERROR("ERROR: No file header found at 0x%x - try next aligned address: 0x%x.\n", offset,offset+new_align);
			offset += new_align;
			continue;
		}

		name_len = f->file.offset - sizeof(f->file);
		DEBUG(" - load entry 0x%x file name (%d bytes)...\n", offset,name_len);
		file_name = (const char *)media->map(media, offset + sizeof(f->file),
				name_len);
		if (file_name == CBFS_MEDIA_INVALID_MAP_ADDRESS) {
			ERROR("ERROR: Failed to get filename: 0x%x.\n", offset);
		} else if (strcmp(file_name, name) == 0) {
				f->data_offset = offset + f->file.offset;
				f->data_len = f->file.len;
				media->unmap(media, file_name);
				DEBUG("Found file:offset = 0x%x, len=%d\n",
						f->data_offset, f->data_len);
				return 0;
		} else {
			DEBUG("unmatched file offset = 0x%x : %s\n", offset, file_name);
			media->unmap(media,file_name);
		}
		// Move to next file.
		offset += f->file.len + f->file.offset;
		if (offset % align)
			offset += align - (offset % align);
		DEBUG("Going for next offset\n");
	}
	media->close(media);
	LOG("Warning: '%s' not found\n",name);
	return -1;
}


/* This functions finds the absolute data_offset of a file searched for by
   name and type using cbfs_find_file(). Returns 0 on success and -1 on failure
 */
int cbfs_find_file_by_type(struct cbfs_media *media, struct cbfs_file_handle *f,
		const char *name, int type)
{

	if (cbfs_find_file(media, f, name) < 0) {
		ERROR("Failed to find file\n");
		return -1;
	}

	if (f->file.type == type) {
		DEBUG("File of matching type has been found\n");
		return 0;
	}
	else
		return -1;
}


/*Returns pointer to file content inside CBFS after verifying type
 */
void *cbfs_get_file_content(struct cbfs_media *media, const char *name,
		int type, size_t *sz)
{
	struct cbfs_file_handle f;
	struct cbfs_media default_media;
	void *content;

	if (sz)
		*sz = 0;

	if (media == CBFS_DEFAULT_MEDIA) {
		media = &default_media;
		if (init_default_cbfs_media(media) != 0) {
			ERROR("Failed to initialize default media.\n");
			return NULL;
		}
	}

	if (cbfs_find_file_by_type(media, &f, name, type) < 0) {
		ERROR("File not found\n");
		return NULL;
	}

	DEBUG("Found file. Will be mapping it now!\n");

	if (sz)
		*sz = f.data_len;

	content = media->map(media, f.data_offset, f.data_len);

	if (content == CBFS_MEDIA_INVALID_MAP_ADDRESS)
		return NULL;
	else
		return content;
}

/* returns pointer to file entry inside the CBFS or NULL
*/
struct cbfs_file *cbfs_get_file(struct cbfs_media *media, const char *name)
{
	struct cbfs_file_handle f;
	struct cbfs_media default_media;
	struct cbfs_file *fileptr;

	if (media == CBFS_DEFAULT_MEDIA) {
		media = &default_media;
		if (init_default_cbfs_media(media) != 0) {
			ERROR("Failed to initialize media\n");
			return NULL;
		}
	}

	if (cbfs_find_file(media, &f, name) < 0) {
		ERROR("Failed to find file\n");
		return NULL;
	}

	fileptr = media->map(media, f.data_offset - f.file.offset, f.data_len + f.file.offset);

	if (fileptr == CBFS_MEDIA_INVALID_MAP_ADDRESS)
		return NULL;
	else
		return fileptr;
}

int cbfs_decompress(int algo, void *src, void *dst, int len)
{
	switch (algo) {
		case CBFS_COMPRESS_NONE:
			/* Reads need to be aligned at 4 bytes to avoid
			   poor flash performance.  */
			while (len && ((u32)src & 3)) {
				*(u8*)dst++ = *(u8*)src++;
				len--;
			}
			memmove(dst, src, len);
			return len;
#ifdef CBFS_CORE_WITH_LZMA
		case CBFS_COMPRESS_LZMA:
			return ulzma(src, dst);
#endif
		default:
			ERROR("tried to decompress %d bytes with algorithm #%x,"
			      "but that algorithm id is unsupported.\n", len,
			      algo);
			return 0;
	}
}

