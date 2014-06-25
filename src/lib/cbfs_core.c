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
#include <stdlib.h>

/* returns a pointer to CBFS master header, or CBFS_HEADER_INVALID_ADDRESS
 *  on failure*/
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
/* This functions finds the absolute data_offset of a file searched for by name/type
   Returns 0 on success and -1 on failure
 */
int cbfs_find_file(struct cbfs_media *media, struct cbfs_file_handler *f, const char *name, int type)
{
	uint32_t offset, align, romsize,name_len;
	struct cbfs_media default_media;
	const struct cbfs_header *header;
	ssize_t value_read;
	const char *file_name;
	
	if (media == CBFS_DEFAULT_MEDIA) {
		media = &default_media;
		if (init_default_cbfs_media(media) != 0) {
			ERROR("Failed to initialize default media.\n");
			return -1;
		}
	}
	
	if (CBFS_HEADER_INVALID_ADDRESS == (header = cbfs_get_header(media)))
		return -1; // error

	// Logical offset (for source media) of first file.
	// Now we know where the file lives
	offset = ntohl(header->offset);
	align = ntohl(header->align);
	romsize = ntohl(header->romsize);

#if defined(CONFIG_ARCH_X86) && CONFIG_ARCH_X86
	romsize -= htonl(header->bootblocksize);
#endif
	int catch;	
	DEBUG("CBFS location: 0x%x~0x%x, align: %d\n", offset, romsize, align);
	DEBUG("Looking for '%s' starting from 0x%x.\n", name, offset);
	media->open(media);
	while (offset < romsize)
	{
		value_read = media->read(media, &f->file, offset, sizeof(f->file));
		if(value_read != sizeof(f->file)){
			return -1; //error: since read not successful
			break;
		}
		//make all ntohl() at once place to avoid any gibberish later
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
			//continuing with new offset
		}

		f->found = -1;
		if(f->file.type == type){
			
			name_len = f->file.offset - sizeof(f->file);
			DEBUG(" - load entry 0x%x file name (%d bytes)...\n", offset,name_len);
			// load file name (arbitrary length).
			file_name = (const char *)media->map(media, offset + sizeof(f->file), name_len);
			//this mapping done to verify name of file
			if (file_name == CBFS_MEDIA_INVALID_MAP_ADDRESS) {
				ERROR("ERROR: Failed to get filename: 0x%x.\n", offset);
			} else if (strcmp(file_name, name) == 0) {
					f->found = 0;
					f->data_offset = offset + f->file.offset; 
					f->data_len = f->file.len;
					media->unmap(media, file_name);
					DEBUG("Found file:offset = 0x%x, len=%d\n", f->data_offset, f->data_len);
					catch = f->found;
					return catch;
			} else {
				DEBUG("unmatched file offset = 0x%x : %s\n", offset, file_name);
				media->unmap(media,file_name);
			}
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

/*Returns pointer to file content inside CBFS after verifying type
 */
void *cbfs_get_file_content(struct cbfs_media *media, const char *name, int type, size_t *sz)
{
	struct cbfs_file_handler f;
	int c;
	struct cbfs_media default_media;

	if (media == CBFS_DEFAULT_MEDIA) {
		media = &default_media;
		if (init_default_cbfs_media(media) != 0) {
			ERROR("Failed to initialize default media.\n");
			return NULL;
		}
	}
	c = cbfs_find_file(media, &f, name, type);
	if (c == 0){
	DEBUG("Found file. Will be mapping it now!\n");
	if (sz)
		*sz = 0;

	if (f.file.type != type) {
		ERROR("File '%s' is of type %x, but we requested %x.\n", name, f.file.type, type);
		return NULL;
	}

	if (sz)
		*sz = f.data_len;
	return media->map(media, f.data_offset, f.data_len + f.file.offset);
	}
	else {
		DEBUG("condition not successful\n");
		ERROR("File Not Found\n");
		return NULL;
	}
}


/*void cbfs_get_data(struct cbfs_media *media, const char *name, int type)
{
	struct cbfs_file_handler f;
	ssize_t value_read;
	int c;
	c = cbfs_find_file(media, &f, name, type);
	if (c == 0){
		DEBUG("File has been found and can be read\n");
		uint32_t loop_offset = f.data_offset + f.file.offset;
		uint32_t loop_align = f.align;

		while (f.data_len > 0){
		
			struct cbfs_file file;
			value_read = media->read(media, &file, loop_offset , sizeof(file));
			loop_offset += file.len + file.offset; 
			if (loop_offset % loop_align)
				loop_offset += loop_align = (loop_offset % loop_align);
			f.data_len -= sizeof(file); 
		}
	}
	else {
		ERROR("File not found\n");
	}
		
}
*/	

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
			      "but that algorithm id is unsupporteid.\n", len,
			      algo);
			return 0;
	}
}

