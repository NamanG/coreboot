/*
 * This file is part of the coreboot project.
 *
 * Copyright (C) 2011 secunet Security Networks AG
 * Copyright (C) 2013 The Chromium OS Authors. All rights reserved.
 * Copyright (C) 2014 Naman Govil <namangov@gmail.com>
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

/* returns a pointer to CBFS master header, or CBFS_HEADER_INVALID_ADDRESS
 *  on failure */
const struct cbfs_header* cbfs_get_header(struct cbfs_media *media)
{
	struct cbfs_header header;
	const struct cbfs_header *h;
	struct cbfs_media default_media;
	ssize_t header_size;
	if (media == CBFS_DEFAULT_MEDIA) {
		media = &default_media;
		if (init_default_cbfs_media(media) != 0) {
			ERROR("Failed to initialize default media.\n");
			return CBFS_HEADER_INVALID_ADDRESS;
		}
	}

	media->open(media);
	DEBUG("CBFS_HEADER_ROM_ADDRESS: 0x%x/0x%x\n", CBFS_HEADER_ROM_ADDRESS,
	      CONFIG_ROM_SIZE);
	header_size = media->read(media, &header, CBFS_HEADER_ROM_ADDRESS, sizeof(header));
	//size of mapping (now read) : 32 bytes
	DEBUG("Size of read done is : %zd bytes\n",header_size);
	media->close(media);

	if (header_size != sizeof(header)) {
		ERROR("Failed to load CBFS header from 0x%x\n",CBFS_HEADER_ROM_ADDRESS);
		return CBFS_HEADER_INVALID_ADDRESS;
	}

	if (CBFS_HEADER_MAGIC != ntohl(header.magic)) {
		ERROR("Could not find valid CBFS master header at %x: "
		      "%x vs %x.\n", CBFS_HEADER_ROM_ADDRESS, CBFS_HEADER_MAGIC,
		      ntohl(header.magic));
		if (header.magic == 0xffffffff) {
			ERROR("Maybe ROM is not mapped properly?\n");
		}
		return CBFS_HEADER_INVALID_ADDRESS;
	}

	h=&header;

	return h;
}

/* public API starts here*/

struct cbfs_file *cbfs_get_file_modified(struct cbfs_media *media, const char *name)
{
	uint32_t offset, align, romsize, name_len;
	struct cbfs_file file, *file_ptr,*file_ptr2;
	struct cbfs_media default_media;
	const struct cbfs_header *header;
	ssize_t value_read;
	const char *file_name;
	
	if (media == CBFS_DEFAULT_MEDIA) {
		media = &default_media;
		if (init_default_cbfs_media(media) != 0) {
			ERROR("Failed to initialize default media.\n");
			return NULL;
		}
	}
	
	if (CBFS_HEADER_INVALID_ADDRESS == (header = cbfs_get_header(media)))
		return NULL; // error

	// Logical offset (for source media) of first file.
	// Now we know where the file lives
	offset = ntohl(header->offset);
	align = ntohl(header->align);
	romsize = ntohl(header->romsize);
//Not needed for ARM based systems, but to make it generic	
#if defined(CONFIG_ARCH_X86) && CONFIG_ARCH_X86
	romsize -= htonl(header->bootblocksize);
#endif
	
	DEBUG("CBFS location: 0x%x~0x%x, align: %d\n", offset, romsize, align);
	DEBUG("Looking for '%s' starting from 0x%x.\n", name, offset);
	media->open(media);
	while (offset < romsize)
	{
		value_read = media->read(media, &file, offset, sizeof(file));

		if(value_read != sizeof(file)){
			return NULL; //error: since read not successful
			break;
		}
		 
		file.len = ntohl(file.len);
		file.type = ntohl(file.type);
		file.offset = ntohl(file.offset);
		file.type = ntohl(file.type);

		if (memcmp(CBFS_FILE_MAGIC, file.magic,
			   sizeof(file.magic)) != 0) {
			uint32_t new_align = align;
			if (offset % align)
				new_align += align - (offset % align);
			offset += new_align;
			continue;
			//continuing with new offset
		}


		if(file.type == CBFS_TYPE_STAGE || file.type == CBFS_TYPE_PAYLOAD){
			DEBUG("Did not do any mapping\n");
			DEBUG("Found file (offset=0x%x, len=%d).\n",offset + file.offset, file.len);
			offset += file.offset + file.len;
			uint32_t new_align1 = align;
			if (offset % align)
				new_align1 += align - (offset % align);
			offset += new_align1;
			file_ptr2=&file;
			return file_ptr2;
		}
		else
		{
			name_len = file.offset - sizeof(file);
			DEBUG(" - load entry 0x%x file name (%d bytes)...\n", offset,
		      	name_len);

			file_name = (const char *)media->map(
					media, offset + sizeof(file), name_len);
			if (file_name == CBFS_MEDIA_INVALID_MAP_ADDRESS) {
				ERROR("ERROR: Failed to get filename: 0x%x.\n", offset);
			} else if (strcmp(file_name, name) == 0) {
				int file_offset = file.offset,
			    	file_len = file.len;
				DEBUG("Found file (offset=0x%x, len=%d).\n",
			    	offset + file_offset, file_len);
				media->unmap(media, file_name);
				file_ptr = media->map(media, offset,
						      file_offset + file_len);
				media->close(media);
				return file_ptr;
			} else {
				DEBUG(" (unmatched file @0x%x: %s)\n", offset,
			      	file_name);
				media->unmap(media, file_name);
			}	
		}

		// Move to next file.
		offset += file.len + file.offset;
		if (offset % align)
			offset += align - (offset % align);
	}
	media->close(media);
	LOG("Warning: '%s' not found\n",name);
	return NULL;
}
			
		

struct cbfs_file *cbfs_get_file(struct cbfs_media *media, const char *name)
{
	const char *file_name;
	uint32_t offset, align, romsize, name_len;
	const struct cbfs_header *header;
	struct cbfs_file file, *file_ptr;
	struct cbfs_media default_media;

	if (media == CBFS_DEFAULT_MEDIA) {
		media = &default_media;
		if (init_default_cbfs_media(media) != 0) {
			ERROR("Failed to initialize default media.\n");
			return NULL;
		}
	}

	if (CBFS_HEADER_INVALID_ADDRESS == (header = cbfs_get_header(media)))
		return NULL;

	// Logical offset (for source media) of first file.
	// Now we know where the file lives
	offset = ntohl(header->offset);
	align = ntohl(header->align);
	romsize = ntohl(header->romsize);

	// TODO Add a "size" in CBFS header for a platform independent way to
	// determine the end of CBFS data.
#if defined(CONFIG_ARCH_X86) && CONFIG_ARCH_X86
	romsize -= htonl(header->bootblocksize);
#endif
	DEBUG("CBFS location: 0x%x~0x%x, align: %d\n", offset, romsize, align);

	DEBUG("Looking for '%s' starting from 0x%x.\n", name, offset);
	media->open(media);
	while (offset < romsize &&
	       media->read(media, &file, offset, sizeof(file)) == sizeof(file)) {
		if (memcmp(CBFS_FILE_MAGIC, file.magic,
			   sizeof(file.magic)) != 0) {
			uint32_t new_align = align;
			if (offset % align)
				new_align += align - (offset % align);
			ERROR("ERROR: No file header found at 0x%x - "
			      "try next aligned address: 0x%x.\n", offset,
			      offset + new_align);
			offset += new_align;
			continue;
		}
		name_len = ntohl(file.offset) - sizeof(file);
		DEBUG(" - load entry 0x%x file name (%d bytes)...\n", offset,
		      name_len);

		// load file name (arbitrary length).
		file_name = (const char *)media->map(
				media, offset + sizeof(file), name_len);
		if (file_name == CBFS_MEDIA_INVALID_MAP_ADDRESS) {
			ERROR("ERROR: Failed to get filename: 0x%x.\n", offset);
		} else if (strcmp(file_name, name) == 0) {
			int file_offset = ntohl(file.offset),
			    file_len = ntohl(file.len);
			DEBUG("Found file (offset=0x%x, len=%d).\n",
			    offset + file_offset, file_len);
			media->unmap(media, file_name);
			file_ptr = media->map(media, offset,
					      file_offset + file_len);
			media->close(media);
			return file_ptr;
		} else {
			DEBUG(" (unmatched file @0x%x: %s)\n", offset,
			      file_name);
			media->unmap(media, file_name);
		}

		// Move to next file.
		offset += ntohl(file.len) + ntohl(file.offset);
		if (offset % align)
			offset += align - (offset % align);
	}
	media->close(media);
	LOG("WARNING: '%s' not found.\n", name);
	return NULL;
}

void *cbfs_get_file_content(struct cbfs_media *media, const char *name,
			    int type, size_t *sz)
{
	struct cbfs_file *file = cbfs_get_file_modified(media, name);

	if (sz)
		*sz = 0;

	if (file == NULL) {
		ERROR("Could not find file '%s'.\n", name);
		return NULL;
	}

	if (file->type != type) {
		ERROR("File '%s' is of type %x, but we requested %x.\n", name,
		      file->type, type);
		return NULL;
	}

	if (sz)
		*sz = file->len;

	return (void *)CBFS_SUBHEADER(file);
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

