// SPDX-License-Identifier: BSD-2-Clause-Patent
/*
 * pe-relocate.c - our PE relocation/loading (but not verification) code
 * Copyright Peter Jones <pjones@redhat.com>
 */

#include "shim.h"
#include <Library/BaseCryptLib.h>

struct shim_section_cache_entry {
	EFI_HANDLE parent_image_handle;
	UINT8 section_name[9];
	UINTN size;
	/*
	 * Since this is all internal and there's no API access to it, this is
	 * currently always sha256 and can be updated as needed.
	 */
	UINT8 digest[32];
};

static struct shim_section_cache_entry *section_cache = NULL;
static UINTN num_section_cache_entries = 0;

/*
 * Perform basic bounds checking of the intra-image pointers
 */
void *
ImageAddress (void *image, uint64_t size, uint64_t address)
{
	uintptr_t img_addr;

	/* ensure our local pointer isn't bigger than our size */
	if (address >= size)
		return NULL;

	/* Insure our math won't overflow */
	img_addr = (uintptr_t)image;
	if (checked_add(img_addr, address, &img_addr))
		return NULL;

	/* return the absolute pointer */
	return (void *)img_addr;
}

/*
 * Perform the actual relocation
 */
EFI_STATUS
relocate_coff (PE_COFF_LOADER_IMAGE_CONTEXT *context,
	       EFI_IMAGE_SECTION_HEADER *Section,
	       void *orig, void *data)
{
	EFI_IMAGE_BASE_RELOCATION *RelocBase, *RelocBaseEnd;
	UINT64 Adjust;
	UINT16 *Reloc, *RelocEnd;
	char *Fixup, *FixupBase;
	UINT16 *Fixup16;
	UINT32 *Fixup32;
	UINT64 *Fixup64;
	int size = context->ImageSize;
	void *ImageEnd = (char *)orig + size;
	int n = 0;

	/* Alright, so here's how this works:
	 *
	 * context->RelocDir gives us two things:
	 * - the VA the table of base relocation blocks are (maybe) to be
	 *   mapped at (RelocDir->VirtualAddress)
	 * - the virtual size (RelocDir->Size)
	 *
	 * The .reloc section (Section here) gives us some other things:
	 * - the name! kind of. (Section->Name)
	 * - the virtual size (Section->VirtualSize), which should be the same
	 *   as RelocDir->Size
	 * - the virtual address (Section->VirtualAddress)
	 * - the file section size (Section->SizeOfRawData), which is
	 *   a multiple of OptHdr->FileAlignment.  Only useful for image
	 *   validation, not really useful for iteration bounds.
	 * - the file address (Section->PointerToRawData)
	 * - a bunch of stuff we don't use that's 0 in our binaries usually
	 * - Flags (Section->Characteristics)
	 *
	 * and then the thing that's actually at the file address is an array
	 * of EFI_IMAGE_BASE_RELOCATION structs with some values packed behind
	 * them.  The SizeOfBlock field of this structure includes the
	 * structure itself, and adding it to that structure's address will
	 * yield the next entry in the array.
	 */
	RelocBase = ImageAddress(orig, size, Section->PointerToRawData);
	/* RelocBaseEnd here is the address of the first entry /past/ the
	 * table.  */
	RelocBaseEnd = ImageAddress(orig, size, Section->PointerToRawData +
						context->RelocDir->Size - 1);

	if (!RelocBase && !RelocBaseEnd)
		return EFI_SUCCESS;

	if (!RelocBase || !RelocBaseEnd) {
		perror(L"Reloc table overflows binary\n");
		return EFI_UNSUPPORTED;
	}

	Adjust = (UINTN)data - context->ImageAddress;

	if (Adjust == 0)
		return EFI_SUCCESS;

	while (RelocBase < RelocBaseEnd) {
		Reloc = (UINT16 *) ((char *) RelocBase + sizeof (EFI_IMAGE_BASE_RELOCATION));

		if (RelocBase->SizeOfBlock == 0) {
			perror(L"Reloc %d block size 0 is invalid\n", n);
			return EFI_UNSUPPORTED;
		} else if (RelocBase->SizeOfBlock > context->RelocDir->Size) {
			perror(L"Reloc %d block size %d greater than reloc dir"
					"size %d, which is invalid\n", n,
					RelocBase->SizeOfBlock,
					context->RelocDir->Size);
			return EFI_UNSUPPORTED;
		}

		RelocEnd = (UINT16 *) ((char *) RelocBase + RelocBase->SizeOfBlock);
		if ((void *)RelocEnd < orig || (void *)RelocEnd > ImageEnd) {
			perror(L"Reloc %d entry overflows binary\n", n);
			return EFI_UNSUPPORTED;
		}

		FixupBase = ImageAddress(data, size, RelocBase->VirtualAddress);
		if (!FixupBase) {
			perror(L"Reloc %d Invalid fixupbase\n", n);
			return EFI_UNSUPPORTED;
		}

		while (Reloc < RelocEnd) {
			Fixup = FixupBase + (*Reloc & 0xFFF);
			switch ((*Reloc) >> 12) {
			case EFI_IMAGE_REL_BASED_ABSOLUTE:
				break;

			case EFI_IMAGE_REL_BASED_HIGH:
				Fixup16   = (UINT16 *) Fixup;
				*Fixup16 = (UINT16) (*Fixup16 + ((UINT16) ((UINT32) Adjust >> 16)));
				break;

			case EFI_IMAGE_REL_BASED_LOW:
				Fixup16   = (UINT16 *) Fixup;
				*Fixup16  = (UINT16) (*Fixup16 + (UINT16) Adjust);
				break;

			case EFI_IMAGE_REL_BASED_HIGHLOW:
				Fixup32   = (UINT32 *) Fixup;
				*Fixup32  = *Fixup32 + (UINT32) Adjust;
				break;

			case EFI_IMAGE_REL_BASED_DIR64:
				Fixup64 = (UINT64 *) Fixup;
				*Fixup64 = *Fixup64 + (UINT64) Adjust;
				break;

			default:
				perror(L"Reloc %d Unknown relocation\n", n);
				return EFI_UNSUPPORTED;
			}
			Reloc += 1;
		}
		RelocBase = (EFI_IMAGE_BASE_RELOCATION *) RelocEnd;
		n++;
	}

	return EFI_SUCCESS;
}

static EFI_STATUS
_do_sha256_sum(void *addr, UINTN size, UINT8 *digest)
{
	unsigned int sha256ctxsize;
	void *sha256ctx = NULL;

	sha256ctxsize = Sha256GetContextSize();
	sha256ctx = AllocateZeroPool(sha256ctxsize);
	if (sha256ctx == NULL)
		return EFI_OUT_OF_RESOURCES;

	if (!Sha256Init(sha256ctx))
		return EFI_OUT_OF_RESOURCES;

	if (!Sha256Update(sha256ctx, addr, size))
		return EFI_OUT_OF_RESOURCES;

	if (!Sha256Final(sha256ctx, digest))
		return EFI_OUT_OF_RESOURCES;

	FreePool(sha256ctx);
	return EFI_SUCCESS;
}

static EFI_STATUS
cache_section(EFI_HANDLE parent_image_handle, UINT8 section_name[8],
	      void *addr, UINTN size)
{
	struct shim_section_cache_entry *new_section_cache = NULL;
	struct shim_section_cache_entry *entry = NULL;
	size_t oscsz = num_section_cache_entries * sizeof (*new_section_cache);
	size_t nscsz = oscsz + sizeof (*new_section_cache);
	EFI_STATUS efi_status;

	new_section_cache = AllocateZeroPool(nscsz);
	if (!new_section_cache)
		return EFI_OUT_OF_RESOURCES;

	if (section_cache) {
		CopyMem(new_section_cache, section_cache, oscsz);
		FreePool(section_cache);
	}
	section_cache = new_section_cache;
	entry = &section_cache[num_section_cache_entries];

	entry->parent_image_handle = parent_image_handle;
	CopyMem(entry->section_name, section_name, sizeof(entry->section_name)-1);
	entry->size = size;

	efi_status = _do_sha256_sum(addr, size, entry->digest);
	if (EFI_ERROR(efi_status)) {
		ZeroMem(entry, sizeof (*entry));
		return efi_status;
	}
	num_section_cache_entries += 1;
	return EFI_SUCCESS;
}

EFI_STATUS
validate_cached_section(EFI_HANDLE parent_image_handle,
			void *addr, UINTN size)
{
	struct shim_section_cache_entry *section = NULL;
	EFI_STATUS efi_status;

	for (UINTN i = 0; i < num_section_cache_entries; i++) {
		struct shim_section_cache_entry *this_entry = &section_cache[i];
		UINT8 digest[32];

		dprint(L"Handles: 0x%016llx 0x%016llx section: '%a'\n",
		       (unsigned long long)(uintptr_t)this_entry->parent_image_handle,
		       (unsigned long long)(uintptr_t)parent_image_handle,
		       this_entry->section_name);

		if (this_entry->size != size)
			continue;
		if (this_entry->parent_image_handle != parent_image_handle)
			continue;

		ZeroMem(digest, sizeof(digest));

		efi_status = _do_sha256_sum(addr, size, digest);
		if (EFI_ERROR(efi_status))
			return efi_status;

		if (CompareMem(digest, this_entry->digest, sizeof(digest)) != 0)
			continue;

		section = this_entry;
		break;
	}
	if (section == NULL)
		return EFI_NOT_FOUND;

	return EFI_SUCCESS;
}

void
flush_cached_sections(EFI_HANDLE parent_image_handle)
{
	UINTN reduction = 0;
	for (UINTN i = 0; i < num_section_cache_entries; i++) {
		struct shim_section_cache_entry *this_entry = &section_cache[i];

		if (this_entry->parent_image_handle != parent_image_handle)
			continue;

		reduction += 1;
		CopyMem(&this_entry[1], &this_entry[0], sizeof(*this_entry) * (num_section_cache_entries - i - 1));
	}

	ZeroMem(&section_cache[num_section_cache_entries - reduction],
		sizeof(section_cache[0]) * reduction);

	num_section_cache_entries -= reduction;
}

EFI_STATUS
get_section_vma (UINTN section_num,
		 char *buffer, size_t bufsz UNUSED,
		 PE_COFF_LOADER_IMAGE_CONTEXT *context,
		 char **basep, size_t *sizep,
		 EFI_IMAGE_SECTION_HEADER **sectionp)
{
	EFI_IMAGE_SECTION_HEADER *sections = context->FirstSection;
	EFI_IMAGE_SECTION_HEADER *section;
	char *base = NULL, *end = NULL;

	if (section_num >= context->NumberOfSections)
		return EFI_NOT_FOUND;

	if (context->FirstSection == NULL) {
		perror(L"Invalid section %d requested\n", section_num);
		return EFI_UNSUPPORTED;
	}

	section = &sections[section_num];

	base = ImageAddress (buffer, context->ImageSize, section->VirtualAddress);
	end = ImageAddress (buffer, context->ImageSize,
			    section->VirtualAddress + section->Misc.VirtualSize - 1);

	if (!(section->Characteristics & EFI_IMAGE_SCN_MEM_DISCARDABLE)) {
		if (!base) {
			perror(L"Section %d has invalid base address\n", section_num);
			return EFI_UNSUPPORTED;
		}
		if (!end) {
			perror(L"Section %d has zero size\n", section_num);
			return EFI_UNSUPPORTED;
		}
	}

	if (!(section->Characteristics & EFI_IMAGE_SCN_CNT_UNINITIALIZED_DATA) &&
	    (section->VirtualAddress < context->SizeOfHeaders ||
	     section->PointerToRawData < context->SizeOfHeaders)) {
		perror(L"Section %d is inside image headers\n", section_num);
		return EFI_UNSUPPORTED;
	}

	if (end < base) {
		perror(L"Section %d has negative size\n", section_num);
		return EFI_UNSUPPORTED;
	}

	*basep = base;
	*sizep = end - base;
	*sectionp = section;
	return EFI_SUCCESS;
}

EFI_STATUS
get_section_vma_by_name (char *name, size_t namesz,
			 char *buffer, size_t bufsz,
			 PE_COFF_LOADER_IMAGE_CONTEXT *context,
			 char **basep, size_t *sizep,
			 EFI_IMAGE_SECTION_HEADER **sectionp)
{
	UINTN i;
	char namebuf[9];

	if (!name || namesz == 0 || !buffer || bufsz < namesz || !context
	    || !basep || !sizep || !sectionp)
		return EFI_INVALID_PARAMETER;

	/*
	 * This code currently is only used for ".reloc\0\0" and
	 * ".sbat\0\0\0", and it doesn't know how to look up longer section
	 * names.
	 */
	if (namesz > 8)
		return EFI_UNSUPPORTED;

	SetMem(namebuf, sizeof(namebuf), 0);
	CopyMem(namebuf, name, MIN(namesz, 8));

	/*
	 * Copy the executable's sections to their desired offsets
	 */
	for (i = 0; i < context->NumberOfSections; i++) {
		EFI_STATUS status;
		EFI_IMAGE_SECTION_HEADER *section = NULL;
		char *base = NULL;
		size_t size = 0;

		status = get_section_vma(i, buffer, bufsz, context, &base, &size, &section);
		if (!EFI_ERROR(status)) {
			if (CompareMem(section->Name, namebuf, 8) == 0) {
				*basep = base;
				*sizep = size;
				*sectionp = section;
				return EFI_SUCCESS;
			}
			continue;
		}

		switch(status) {
		case EFI_NOT_FOUND:
			break;
		}
	}

	return EFI_NOT_FOUND;
}

#define check_size_line(data, datasize_in, hashbase, hashsize, l) ({	\
	if ((unsigned long)hashbase >					\
			(unsigned long)data + datasize_in) {		\
		efi_status = EFI_INVALID_PARAMETER;			\
		perror(L"shim.c:%d Invalid hash base 0x%016x\n", l,	\
			hashbase);					\
		goto done;						\
	}								\
	if ((unsigned long)hashbase + hashsize >			\
			(unsigned long)data + datasize_in) {		\
		efi_status = EFI_INVALID_PARAMETER;			\
		perror(L"shim.c:%d Invalid hash size 0x%016x\n", l,	\
			hashsize);					\
		goto done;						\
	}								\
})
#define check_size(d, ds, h, hs) check_size_line(d, ds, h, hs, __LINE__)

EFI_STATUS
generate_hash(char *data, unsigned int datasize,
	      PE_COFF_LOADER_IMAGE_CONTEXT *context, UINT8 *sha256hash,
	      UINT8 *sha1hash)
{
	unsigned int sha256ctxsize, sha1ctxsize;
	void *sha256ctx = NULL, *sha1ctx = NULL;
	char *hashbase;
	unsigned int hashsize;
	unsigned int SumOfBytesHashed, SumOfSectionBytes;
	unsigned int index, pos;
	EFI_IMAGE_SECTION_HEADER *Section;
	EFI_IMAGE_SECTION_HEADER *SectionHeader = NULL;
	EFI_STATUS efi_status = EFI_SUCCESS;
	EFI_IMAGE_DOS_HEADER *DosHdr = (void *)data;
	unsigned int PEHdr_offset = 0;

	if (datasize <= sizeof (*DosHdr) ||
	    DosHdr->e_magic != EFI_IMAGE_DOS_SIGNATURE) {
		perror(L"Invalid signature\n");
		return EFI_INVALID_PARAMETER;
	}
	PEHdr_offset = DosHdr->e_lfanew;

	sha256ctxsize = Sha256GetContextSize();
	sha256ctx = AllocatePool(sha256ctxsize);

	sha1ctxsize = Sha1GetContextSize();
	sha1ctx = AllocatePool(sha1ctxsize);

	if (!sha256ctx || !sha1ctx) {
		perror(L"Unable to allocate memory for hash context\n");
		return EFI_OUT_OF_RESOURCES;
	}

	if (!Sha256Init(sha256ctx) || !Sha1Init(sha1ctx)) {
		perror(L"Unable to initialise hash\n");
		efi_status = EFI_OUT_OF_RESOURCES;
		goto done;
	}

	/* Hash start to checksum */
	hashbase = data;
	hashsize = (char *)&context->PEHdr->Pe32.OptionalHeader.CheckSum -
		hashbase;
	check_size(data, datasize, hashbase, hashsize);

	if (!(Sha256Update(sha256ctx, hashbase, hashsize)) ||
	    !(Sha1Update(sha1ctx, hashbase, hashsize))) {
		perror(L"Unable to generate hash\n");
		efi_status = EFI_OUT_OF_RESOURCES;
		goto done;
	}

	/* Hash post-checksum to start of certificate table */
	hashbase = (char *)&context->PEHdr->Pe32.OptionalHeader.CheckSum +
		sizeof (int);
	hashsize = (char *)context->SecDir - hashbase;
	check_size(data, datasize, hashbase, hashsize);

	if (!(Sha256Update(sha256ctx, hashbase, hashsize)) ||
	    !(Sha1Update(sha1ctx, hashbase, hashsize))) {
		perror(L"Unable to generate hash\n");
		efi_status = EFI_OUT_OF_RESOURCES;
		goto done;
	}

	/* Hash end of certificate table to end of image header */
	EFI_IMAGE_DATA_DIRECTORY *dd = context->SecDir + 1;
	hashbase = (char *)dd;
	hashsize = context->SizeOfHeaders - (unsigned long)((char *)dd - data);
	if (hashsize > datasize) {
		perror(L"Data Directory size %d is invalid\n", hashsize);
		efi_status = EFI_INVALID_PARAMETER;
		goto done;
	}
	check_size(data, datasize, hashbase, hashsize);

	if (!(Sha256Update(sha256ctx, hashbase, hashsize)) ||
	    !(Sha1Update(sha1ctx, hashbase, hashsize))) {
		perror(L"Unable to generate hash\n");
		efi_status = EFI_OUT_OF_RESOURCES;
		goto done;
	}

	/* Sort sections */
	SumOfBytesHashed = context->SizeOfHeaders;

	/*
	 * XXX Do we need this here, or is it already done in all cases?
	 */
	if (context->NumberOfSections == 0 ||
	    context->FirstSection == NULL) {
		uint16_t opthdrsz;
		uint64_t addr;
		uint16_t nsections;
		EFI_IMAGE_SECTION_HEADER *section0, *sectionN;

		nsections = context->PEHdr->Pe32.FileHeader.NumberOfSections;
		opthdrsz = context->PEHdr->Pe32.FileHeader.SizeOfOptionalHeader;

		/* Validate section0 is within image */
		addr = PEHdr_offset + sizeof(UINT32)
			+ sizeof(EFI_IMAGE_FILE_HEADER)
			+ opthdrsz;
		section0 = ImageAddress(data, datasize, addr);
		if (!section0) {
			perror(L"Malformed file header.\n");
			perror(L"Image address for Section Header 0 is 0x%016llx\n",
			       addr);
			perror(L"File size is 0x%016llx\n", datasize);
			efi_status = EFI_INVALID_PARAMETER;
			goto done;
		}

		/* Validate sectionN is within image */
		addr += (uint64_t)(intptr_t)&section0[nsections-1] -
			(uint64_t)(intptr_t)section0;
		sectionN = ImageAddress(data, datasize, addr);
		if (!sectionN) {
			perror(L"Malformed file header.\n");
			perror(L"Image address for Section Header %d is 0x%016llx\n",
			       nsections - 1, addr);
			perror(L"File size is 0x%016llx\n", datasize);
			efi_status = EFI_INVALID_PARAMETER;
			goto done;
		}

		context->NumberOfSections = nsections;
		context->FirstSection = section0;
	}

	/*
	 * Allocate a new section table so we can sort them without
	 * modifying the image.
	 */
	SectionHeader = AllocateZeroPool (sizeof (EFI_IMAGE_SECTION_HEADER)
					  * context->NumberOfSections);
	if (SectionHeader == NULL) {
		perror(L"Unable to allocate section header\n");
		efi_status = EFI_OUT_OF_RESOURCES;
		goto done;
	}

	/*
	 * Validate section locations and sizes, and sort the table into
	 * our newly allocated header table
	 */
	SumOfSectionBytes = 0;
	Section = context->FirstSection;
	for (index = 0; index < context->NumberOfSections; index++) {
		EFI_IMAGE_SECTION_HEADER *SectionPtr;
		char *base;
		size_t size;

		efi_status = get_section_vma(index, data, datasize, context,
					     &base, &size, &SectionPtr);
		if (efi_status == EFI_NOT_FOUND)
			break;
		if (EFI_ERROR(efi_status)) {
			perror(L"Malformed section header\n");
			goto done;
		}

		/* Validate section size is within image. */
		if (SectionPtr->SizeOfRawData >
		    datasize - SumOfBytesHashed - SumOfSectionBytes) {
			perror(L"Malformed section %d size\n", index);
			efi_status = EFI_INVALID_PARAMETER;
			goto done;
		}
		SumOfSectionBytes += SectionPtr->SizeOfRawData;

		pos = index;
		while ((pos > 0) && (Section->PointerToRawData < SectionHeader[pos - 1].PointerToRawData)) {
			CopyMem (&SectionHeader[pos], &SectionHeader[pos - 1], sizeof (EFI_IMAGE_SECTION_HEADER));
			pos--;
		}
		CopyMem (&SectionHeader[pos], Section, sizeof (EFI_IMAGE_SECTION_HEADER));
		Section += 1;

	}

	/* Hash the sections */
	for (index = 0; index < context->NumberOfSections; index++) {
		Section = &SectionHeader[index];
		if (Section->SizeOfRawData == 0) {
			continue;
		}

		hashbase  = ImageAddress(data, datasize,
					 Section->PointerToRawData);
		if (!hashbase) {
			perror(L"Malformed section header\n");
			efi_status = EFI_INVALID_PARAMETER;
			goto done;
		}

		/* Verify hashsize within image. */
		if (Section->SizeOfRawData >
		    datasize - Section->PointerToRawData) {
			perror(L"Malformed section raw size %d\n", index);
			efi_status = EFI_INVALID_PARAMETER;
			goto done;
		}
		hashsize  = (unsigned int) Section->SizeOfRawData;
		check_size(data, datasize, hashbase, hashsize);

		if (!(Sha256Update(sha256ctx, hashbase, hashsize)) ||
		    !(Sha1Update(sha1ctx, hashbase, hashsize))) {
			perror(L"Unable to generate hash\n");
			efi_status = EFI_OUT_OF_RESOURCES;
			goto done;
		}
		SumOfBytesHashed += Section->SizeOfRawData;
	}

	/* Hash all remaining data up to SecDir if SecDir->Size is not 0 */
	if (datasize > SumOfBytesHashed && context->SecDir->Size) {
		hashbase = data + SumOfBytesHashed;
		hashsize = datasize - context->SecDir->Size - SumOfBytesHashed;

		if ((datasize - SumOfBytesHashed < context->SecDir->Size) ||
		    (SumOfBytesHashed + hashsize != context->SecDir->VirtualAddress)) {
			perror(L"Malformed binary after Attribute Certificate Table\n");
			console_print(L"datasize: %u SumOfBytesHashed: %u SecDir->Size: %lu\n",
				      datasize, SumOfBytesHashed, context->SecDir->Size);
			console_print(L"hashsize: %u SecDir->VirtualAddress: 0x%08lx\n",
				      hashsize, context->SecDir->VirtualAddress);
			efi_status = EFI_INVALID_PARAMETER;
			goto done;
		}
		check_size(data, datasize, hashbase, hashsize);

		if (!(Sha256Update(sha256ctx, hashbase, hashsize)) ||
		    !(Sha1Update(sha1ctx, hashbase, hashsize))) {
			perror(L"Unable to generate hash\n");
			efi_status = EFI_OUT_OF_RESOURCES;
			goto done;
		}

		SumOfBytesHashed += hashsize;
	}

	/* Hash all remaining data. If SecDir->Size is > 0 this code should not
	 * be entered.  If it is, there are still things to hash.  For a file
	 * without a SecDir, we need to hash what remains. */
	if (datasize > SumOfBytesHashed + context->SecDir->Size) {
		char padbuf[8];
		ZeroMem(padbuf, 8);

		hashbase = data + SumOfBytesHashed;
		hashsize = datasize - SumOfBytesHashed;

		check_size(data, datasize, hashbase, hashsize);

		if (!(Sha256Update(sha256ctx, hashbase, hashsize)) ||
		    !(Sha1Update(sha1ctx, hashbase, hashsize))) {
			perror(L"Unable to generate hash\n");
			efi_status = EFI_OUT_OF_RESOURCES;
			goto done;
		}

		SumOfBytesHashed += hashsize;
		hashsize = ALIGN_VALUE(SumOfBytesHashed, 8) - SumOfBytesHashed;

		if (hashsize) {
			if (!(Sha256Update(sha256ctx, padbuf, hashsize)) ||
			    !(Sha1Update(sha1ctx, padbuf, hashsize))) {
				perror(L"Unable to generate hash\n");
				efi_status = EFI_OUT_OF_RESOURCES;
				goto done;
			}
		}
	}

	if (!(Sha256Final(sha256ctx, sha256hash)) ||
	    !(Sha1Final(sha1ctx, sha1hash))) {
		perror(L"Unable to finalise hash\n");
		efi_status = EFI_OUT_OF_RESOURCES;
		goto done;
	}

	dprint(L"sha1 authenticode hash:\n");
	dhexdumpat(sha1hash, SHA1_DIGEST_SIZE, 0);
	dprint(L"sha256 authenticode hash:\n");
	dhexdumpat(sha256hash, SHA256_DIGEST_SIZE, 0);

done:
	if (SectionHeader)
		FreePool(SectionHeader);
	if (sha1ctx)
		FreePool(sha1ctx);
	if (sha256ctx)
		FreePool(sha256ctx);

	return efi_status;
}

EFI_STATUS
verify_sbat_section(char *SBATBase, size_t SBATSize)
{
	unsigned int i;
	EFI_STATUS efi_status;
	size_t n;
	struct sbat_section_entry **entries = NULL;
	char *sbat_data;
	size_t sbat_size;

	if (list_empty(&sbat_var))
		return EFI_SUCCESS;

	if (SBATBase == NULL || SBATSize == 0) {
		dprint(L"No .sbat section data\n");
		/*
		 * SBAT is mandatory for binaries loaded by shim, but optional
		 * for binaries loaded outside of shim but verified via the
		 * protocol.
		 */
		return in_protocol ? EFI_SUCCESS : EFI_SECURITY_VIOLATION;
	}

	if (checked_add(SBATSize, 1, &sbat_size)) {
		dprint(L"SBATSize + 1 would overflow\n");
		return EFI_SECURITY_VIOLATION;
	}

	sbat_data = AllocatePool(sbat_size);
	if (!sbat_data) {
		console_print(L"Failed to allocate .sbat section buffer\n");
		return EFI_OUT_OF_RESOURCES;
	}
	CopyMem(sbat_data, SBATBase, SBATSize);
	sbat_data[SBATSize] = '\0';

	efi_status = parse_sbat_section(sbat_data, sbat_size, &n, &entries);
	if (EFI_ERROR(efi_status)) {
		perror(L"Could not parse .sbat section data: %r\n", efi_status);
		goto err;
	}

	dprint(L"SBAT section data\n");
        for (i = 0; i < n; i++) {
		dprint(L"%a, %a, %a, %a, %a, %a\n",
		       entries[i]->component_name,
		       entries[i]->component_generation,
		       entries[i]->vendor_name,
		       entries[i]->vendor_package_name,
		       entries[i]->vendor_version,
		       entries[i]->vendor_url);
	}

	efi_status = verify_sbat(n, entries);
	cleanup_sbat_section_entries(n, entries);

err:
	FreePool(sbat_data);

	return efi_status;
}

EFI_STATUS verify_image(void *data, unsigned int datasize,
			EFI_LOADED_IMAGE *li,
			PE_COFF_LOADER_IMAGE_CONTEXT *context)
{
	EFI_STATUS efi_status;
	UINT8 sha1hash[SHA1_DIGEST_SIZE];
	UINT8 sha256hash[SHA256_DIGEST_SIZE];

	/*
	 * The binary header contains relevant context and section pointers
	 */
	efi_status = read_header(data, datasize, context, true);
	if (EFI_ERROR(efi_status)) {
		perror(L"Failed to read header: %r\n", efi_status);
		return efi_status;
	}

	/*
	 * Perform the image verification before we start copying data around
	 * in order to load it.
	 */
	if (secure_mode()) {
		efi_status = verify_buffer(data, datasize,
					   context, sha256hash, sha1hash,
					   false);
		if (EFI_ERROR(efi_status)) {
			if (verbose)
				console_print(L"Verification failed: %r\n", efi_status);
			else
				console_error(L"Verification failed", efi_status);
			return efi_status;
		} else if (verbose)
			console_print(L"Verification succeeded\n");
	}

	/*
	 * Calculate the hash for the TPM measurement.
	 * XXX: We're computing these twice in secure boot mode when the
	 *  buffers already contain the previously computed hashes. Also,
	 *  this is only useful for the TPM1.2 case. We should try to fix
	 *  this in a follow-up.
	 */
	efi_status = generate_hash(data, datasize, context, sha256hash,
				   sha1hash);
	if (EFI_ERROR(efi_status))
		return efi_status;

	/* Measure the binary into the TPM */
#ifdef REQUIRE_TPM
	efi_status =
#endif
	tpm_log_pe((EFI_PHYSICAL_ADDRESS)(UINTN)data, datasize,
		   (EFI_PHYSICAL_ADDRESS)(UINTN)context->ImageAddress,
		   li->FilePath, sha1hash, 4);
#ifdef REQUIRE_TPM
	if (efi_status != EFI_SUCCESS) {
		return efi_status;
	}
#endif

	return EFI_SUCCESS;
}

/*
 * Once the image has been loaded it needs to be validated and relocated
 */
EFI_STATUS
handle_image (void *data, unsigned int datasize,
	      EFI_LOADED_IMAGE *li, EFI_HANDLE image_handle,
	      EFI_IMAGE_ENTRY_POINT *entry_point,
	      EFI_PHYSICAL_ADDRESS *alloc_address,
	      UINTN *alloc_pages, unsigned int *alloc_alignment,
	      bool parent_verified)
{
	EFI_STATUS efi_status;
	char *buffer;
	int i;
	EFI_IMAGE_SECTION_HEADER *Section;
	char *base, *end;
	UINT32 size;
	PE_COFF_LOADER_IMAGE_CONTEXT context;
	unsigned int alloc_size;
	int found_entry_point = 0;
	UINT8 sha1hash[SHA1_DIGEST_SIZE];
	UINT8 sha256hash[SHA256_DIGEST_SIZE];

	/*
	 * The binary header contains relevant context and section pointers
	 */
	efi_status = read_header(data, datasize, &context, true);
	if (EFI_ERROR(efi_status)) {
		perror(L"Failed to read header: %r\n", efi_status);
		return efi_status;
	}

	/*
	 * Perform the image verification before we start copying data around
	 * in order to load it.
	 */
	if (secure_mode ()) {
		efi_status = verify_buffer(data, datasize, &context, sha256hash,
					   sha1hash, parent_verified);

		if (EFI_ERROR(efi_status)) {
			if (verbose || in_protocol)
				console_print(L"Verification failed: %r\n", efi_status);
			else
				console_error(L"Verification failed", efi_status);
			return efi_status;
		} else {
			if (verbose)
				console_print(L"Verification succeeded\n");
		}
	}

	/*
	 * We had originally thought about making this much more granular
	 * and logging the child section hashes in the event log, but the
	 * EFI APIs give us extend-without-logging but not
	 * logging-without-extending, so there's no point.
	 */
	if (!parent_verified) {
		/*
		 * Calculate the hash for the TPM measurement.
		 * XXX: We're computing these twice in secure boot mode when the
		 *  buffers already contain the previously computed hashes. Also,
		 *  this is only useful for the TPM1.2 case. We should try to fix
		 *  this in a follow-up.
		 */
		efi_status = generate_hash(data, datasize, &context, sha256hash,
					   sha1hash);
		if (EFI_ERROR(efi_status))
			return efi_status;

		/* Measure the binary into the TPM */
#ifdef REQUIRE_TPM
		efi_status =
#endif
		tpm_log_pe((EFI_PHYSICAL_ADDRESS)(UINTN)data, datasize,
			   (EFI_PHYSICAL_ADDRESS)(UINTN)context.ImageAddress,
			   li->FilePath, sha1hash, 4);
#ifdef REQUIRE_TPM
		if (efi_status != EFI_SUCCESS) {
			return efi_status;
		}
#endif
	}

	/* The spec says, uselessly, of SectionAlignment:
	 * =====
	 * The alignment (in bytes) of sections when they are loaded into
	 * memory. It must be greater than or equal to FileAlignment. The
	 * default is the page size for the architecture.
	 * =====
	 * Which doesn't tell you whose responsibility it is to enforce the
	 * "default", or when.  It implies that the value in the field must
	 * be > FileAlignment (also poorly defined), but it appears visual
	 * studio will happily write 512 for FileAlignment (its default) and
	 * 0 for SectionAlignment, intending to imply PAGE_SIZE.
	 *
	 * We only support one page size, so if it's zero, nerf it to 4096.
	 */
	*alloc_alignment = context.SectionAlignment;
	if (!*alloc_alignment)
		*alloc_alignment = 4096;

	alloc_size = ALIGN_VALUE(context.ImageSize + context.SectionAlignment,
				 PAGE_SIZE);
	*alloc_pages = alloc_size / PAGE_SIZE;

	efi_status = BS->AllocatePages(AllocateAnyPages, EfiLoaderCode,
				       *alloc_pages, alloc_address);
	if (EFI_ERROR(efi_status)) {
		perror(L"Failed to allocate image buffer\n");
		return EFI_OUT_OF_RESOURCES;
	}

	buffer = (void *)ALIGN_VALUE((unsigned long)*alloc_address, *alloc_alignment);
	dprint(L"Loading 0x%llx bytes at 0x%llx\n",
	       (unsigned long long)context.ImageSize,
	       (unsigned long long)(uintptr_t)buffer);
	update_mem_attrs((uintptr_t)buffer, alloc_size, MEM_ATTR_R|MEM_ATTR_W,
			 MEM_ATTR_X);

	CopyMem(buffer, data, context.SizeOfHeaders);

	/* Flush the instruction cache for the region holding the image */
	cache_invalidate(buffer, buffer + context.ImageSize);

	*entry_point = ImageAddress(buffer, context.ImageSize, context.EntryPoint);
	if (!*entry_point) {
		perror(L"Entry point is invalid\n");
		BS->FreePages(*alloc_address, *alloc_pages);
		return EFI_UNSUPPORTED;
	}

	char *RelocBase, *RelocBaseEnd;
	/*
	 * These are relative virtual addresses, so we have to check them
	 * against the image size, not the data size.
	 */
	RelocBase = ImageAddress(buffer, context.ImageSize,
				 context.RelocDir->VirtualAddress);
	/*
	 * RelocBaseEnd here is the address of the last byte of the table
	 */
	RelocBaseEnd = ImageAddress(buffer, context.ImageSize,
				    context.RelocDir->VirtualAddress +
				    context.RelocDir->Size - 1);

	EFI_IMAGE_SECTION_HEADER *RelocSection = NULL;

	/*
	 * Copy the executable's sections to their desired offsets
	 */
	Section = context.FirstSection;
	for (i = 0; i < context.NumberOfSections; i++, Section++) {
		/* Don't try to copy discardable sections with zero size */
		if ((Section->Characteristics & EFI_IMAGE_SCN_MEM_DISCARDABLE) &&
		    !Section->Misc.VirtualSize)
			continue;

		/*
		 * Skip sections that aren't marked readable.
		 */
		if (!(Section->Characteristics & EFI_IMAGE_SCN_MEM_READ))
			continue;

		if (!(Section->Characteristics & EFI_IMAGE_SCN_MEM_DISCARDABLE) &&
		    (Section->Characteristics & EFI_IMAGE_SCN_MEM_WRITE) &&
		    (Section->Characteristics & EFI_IMAGE_SCN_MEM_EXECUTE) &&
		    (mok_policy & MOK_POLICY_REQUIRE_NX)) {
			perror(L"Section %d is writable and executable\n", i);
			BS->FreePages(*alloc_address, *alloc_pages);
			return EFI_UNSUPPORTED;
		}

		base = ImageAddress (buffer, context.ImageSize,
				     Section->VirtualAddress);
		end = ImageAddress (buffer, context.ImageSize,
				    Section->VirtualAddress
				     + Section->Misc.VirtualSize - 1);

		if (end < base) {
			perror(L"Section %d has negative size\n", i);
			BS->FreePages(*alloc_address, *alloc_pages);
			return EFI_UNSUPPORTED;
		}

		if (Section->VirtualAddress <= context.EntryPoint &&
		    (Section->VirtualAddress + Section->Misc.VirtualSize - 1)
		    > context.EntryPoint)
			found_entry_point++;

		/* We do want to process .reloc, but it's often marked
		 * discardable, so we don't want to memcpy it. */
		if (CompareMem(Section->Name, ".reloc\0\0", 8) == 0) {
			if (RelocSection) {
				perror(L"Image has multiple relocation sections\n");
				BS->FreePages(*alloc_address, *alloc_pages);
				return EFI_UNSUPPORTED;
			}
			/* If it has nonzero sizes, and our bounds check
			 * made sense, and the VA and size match RelocDir's
			 * versions, then we believe in this section table. */
			if (Section->SizeOfRawData &&
					Section->Misc.VirtualSize &&
					base && end &&
					RelocBase == base &&
					RelocBaseEnd <= end) {
				RelocSection = Section;
			} else {
				perror(L"Relocation section is invalid \n");
				BS->FreePages(*alloc_address, *alloc_pages);
				return EFI_UNSUPPORTED;
			}
		}

		if (Section->Characteristics & EFI_IMAGE_SCN_MEM_DISCARDABLE) {
			continue;
		}

		if (!base) {
			perror(L"Section %d has invalid base address\n", i);
			BS->FreePages(*alloc_address, *alloc_pages);
			return EFI_UNSUPPORTED;
		}
		if (!end) {
			perror(L"Section %d has zero size\n", i);
			BS->FreePages(*alloc_address, *alloc_pages);
			return EFI_UNSUPPORTED;
		}

		if (!(Section->Characteristics & EFI_IMAGE_SCN_CNT_UNINITIALIZED_DATA) &&
		    (Section->VirtualAddress < context.SizeOfHeaders ||
		     Section->PointerToRawData < context.SizeOfHeaders)) {
			perror(L"Section %d is inside image headers\n", i);
			BS->FreePages(*alloc_address, *alloc_pages);
			return EFI_UNSUPPORTED;
		}

		if (Section->Characteristics & EFI_IMAGE_SCN_CNT_UNINITIALIZED_DATA) {
			ZeroMem(base, Section->Misc.VirtualSize);
		} else {
			if (Section->PointerToRawData < context.SizeOfHeaders) {
				perror(L"Section %d is inside image headers\n", i);
				BS->FreePages(*alloc_address, *alloc_pages);
				return EFI_UNSUPPORTED;
			}

			size = Section->Misc.VirtualSize;
			if (size > Section->SizeOfRawData)
				size = Section->SizeOfRawData;

			if (size > 0)
				CopyMem(base, data + Section->PointerToRawData, size);

			if (size < Section->Misc.VirtualSize)
				ZeroMem(base + size, Section->Misc.VirtualSize - size);
		}
	}

	if (context.NumberOfRvaAndSizes <= EFI_IMAGE_DIRECTORY_ENTRY_BASERELOC) {
		perror(L"Image has no relocation entry\n");
		BS->FreePages(*alloc_address, *alloc_pages);
		return EFI_UNSUPPORTED;
	}

	if (context.RelocDir->Size && RelocSection) {
		/*
		 * Run the relocation fixups
		 */
		efi_status = relocate_coff(&context, RelocSection, data,
					   buffer);

		if (EFI_ERROR(efi_status)) {
			perror(L"Relocation failed: %r\n", efi_status);
			BS->FreePages(*alloc_address, *alloc_pages);
			return efi_status;
		}
	}

	/*
	 * Now set the page permissions appropriately and cache appropriate
	 * section sizes, and digests.
	 */
	Section = context.FirstSection;
	for (i = 0; i < context.NumberOfSections; i++, Section++) {
		uint64_t set_attrs = MEM_ATTR_R;
		uint64_t clear_attrs = MEM_ATTR_W|MEM_ATTR_X;
		uintptr_t addr;
		uint64_t raw_length;
		uint64_t length;

		/*
		 * Skip discardable sections with zero size
		 */
		if ((Section->Characteristics & EFI_IMAGE_SCN_MEM_DISCARDABLE) &&
		    !Section->Misc.VirtualSize)
			continue;

		/*
		 * Skip sections that aren't marked readable.
		 */
		if (!(Section->Characteristics & EFI_IMAGE_SCN_MEM_READ))
			continue;

		base = ImageAddress (buffer, context.ImageSize,
				     Section->VirtualAddress);
		end = ImageAddress (buffer, context.ImageSize,
				    Section->VirtualAddress
				     + Section->Misc.VirtualSize - 1);

		addr = (uintptr_t)base;
		// Align the length up to PAGE_SIZE. This is required because
		// platforms generally set memory attributes at page
		// granularity, but the section length (unlike the section
		// address) is not required to be aligned.
		raw_length = (uintptr_t)end - (uintptr_t)base + 1;
		length = ALIGN_VALUE(raw_length, PAGE_SIZE);

		if (Section->Characteristics & EFI_IMAGE_SCN_MEM_WRITE) {
			set_attrs |= MEM_ATTR_W;
			clear_attrs &= ~MEM_ATTR_W;
		}
		if (Section->Characteristics & EFI_IMAGE_SCN_MEM_EXECUTE) {
			set_attrs |= MEM_ATTR_X;
			clear_attrs &= ~MEM_ATTR_X;
		}
		update_mem_attrs(addr, length, set_attrs, clear_attrs);

		/*
		 * We only cache CODE and INITIALIZED data sections that
		 * are marked readable.  Also, don't cache sections on the
		 * second level deep...
		 */
		if ((Section->Characteristics & EFI_IMAGE_SCN_CNT_CODE ||
		     Section->Characteristics & EFI_IMAGE_SCN_CNT_INITIALIZED_DATA) &&
		    Section->Characteristics & EFI_IMAGE_SCN_MEM_READ &&
		    !parent_verified) {
			efi_status = cache_section(image_handle, Section->Name, base, raw_length);
			if (EFI_ERROR(efi_status)) {
				perror(L"Failed to cache section details\n");
				BS->FreePages(*alloc_address, *alloc_pages);
				return efi_status;
			}
			dprint(L"Cached section %d (%a) at 0x%016llx, size 0x%016llx\n",
			       i, Section->Name,
			       (unsigned long long)(uintptr_t)base,
			       (unsigned long long)raw_length);
		}
	}

	/*
	 * grub needs to know its location and size in memory, so fix up
	 * the loaded image protocol values
	 */
	li->ImageBase = buffer;
	li->ImageSize = context.ImageSize;

	/* Pass the load options to the second stage loader */
	li->LoadOptions = load_options;
	li->LoadOptionsSize = load_options_size;

	if (!found_entry_point) {
		perror(L"Entry point is not within sections\n");
		flush_cached_sections(image_handle);
		BS->FreePages(*alloc_address, *alloc_pages);
		return EFI_UNSUPPORTED;
	}
	if (found_entry_point > 1) {
		perror(L"%d sections contain entry point\n", found_entry_point);
		flush_cached_sections(image_handle);
		BS->FreePages(*alloc_address, *alloc_pages);
		return EFI_UNSUPPORTED;
	}

	return EFI_SUCCESS;
}

/* here's a chart:
 *		i686	x86_64	aarch64
 *  64-on-64:	nyet	yes	yes
 *  64-on-32:	nyet	yes	nyet
 *  32-on-32:	yes	yes	no
 */
static int
allow_64_bit(void)
{
#if defined(__x86_64__) || defined(__aarch64__)
	return 1;
#elif defined(__i386__) || defined(__i686__)
	// Right now blindly assuming the kernel will correctly detect this
	//  and /halt the system/ if you're not really on a 64-bit cpu 
	if (in_protocol)
		return 1;
	return 0;
#elif defined (__riscv) && __riscv_xlen == 64
	return 1;
#else 
	// assuming everything else is 32-bit... 
	return 0;
#endif
}

static int
allow_32_bit(void)
{
#if defined(__x86_64__)
#if defined(ALLOW_32BIT_KERNEL_ON_X64)
	if (in_protocol)
		return 1;
	return 0;
#else
	return 0;
#endif
#elif defined(__i386__) || defined(__i686__)
	return 1;
#elif defined(__aarch64__)
	return 0;
#elif defined (__riscv) && __riscv_xlen == 64
	return 0;
#else /* assuming everything else is 32-bit... */
	return 1;
#endif
}

static int
image_is_64_bit(EFI_IMAGE_OPTIONAL_HEADER_UNION *PEHdr)
{
	/* .Magic is the same offset in all cases */
	if (PEHdr->Pe32.OptionalHeader.Magic
			== EFI_IMAGE_NT_OPTIONAL_HDR64_MAGIC)
		return 1;
	return 0;
}

static const UINT16 machine_type =
#if defined(__x86_64__)
	IMAGE_FILE_MACHINE_X64;
#elif defined(__aarch64__)
	IMAGE_FILE_MACHINE_ARM64;
#elif defined(__arm__)
	IMAGE_FILE_MACHINE_ARMTHUMB_MIXED;
#elif defined(__i386__) || defined(__i486__) || defined(__i686__)
	IMAGE_FILE_MACHINE_I386;
#elif defined(__ia64__)
	IMAGE_FILE_MACHINE_IA64;
#elif defined(__riscv) && __riscv_xlen == 64
	IMAGE_FILE_MACHINE_RISCV64;
#else
#error this architecture is not supported by shim
#endif

static int
image_is_loadable(EFI_IMAGE_OPTIONAL_HEADER_UNION *PEHdr)
{
	/* If the machine type doesn't match the binary, bail, unless
	 * we're in an allowed 64-on-32 scenario */
	if (PEHdr->Pe32.FileHeader.Machine != machine_type) {
		if (!(machine_type == IMAGE_FILE_MACHINE_I386 &&
		      PEHdr->Pe32.FileHeader.Machine == IMAGE_FILE_MACHINE_X64 &&
		      allow_64_bit())) {
			return 0;
		}
	}

	/* If it's not a header type we recognize at all, bail */
	switch (PEHdr->Pe32Plus.OptionalHeader.Magic) {
	case EFI_IMAGE_NT_OPTIONAL_HDR64_MAGIC:
	case EFI_IMAGE_NT_OPTIONAL_HDR32_MAGIC:
		break;
	default:
		return 0;
	}

	/* and now just check for general 64-vs-32 compatibility */
	if (image_is_64_bit(PEHdr)) {
		if (allow_64_bit())
			return 1;
	} else {
		if (allow_32_bit())
			return 1;
	}
	return 0;
}

/*
 * Read the binary header and grab appropriate information from it
 */
EFI_STATUS
read_header(void *data, unsigned int datasize,
	    PE_COFF_LOADER_IMAGE_CONTEXT *context,
	    bool check_secdir)
{
	EFI_IMAGE_DOS_HEADER *DosHdr = data;
	EFI_IMAGE_OPTIONAL_HEADER_UNION *PEHdr = data;
	unsigned long HeaderWithoutDataDir, SectionHeaderOffset, OptHeaderSize;
	unsigned long FileAlignment = 0;
	size_t dos_sz = 0;
	size_t tmpsz0, tmpsz1;

	/*
	 * It has to be big enough to hold the DOS header; right now we
	 * don't support images without it.
	 */
	if (datasize < sizeof (*DosHdr)) {
		perror(L"Invalid image\n");
		return EFI_UNSUPPORTED;
	}

	/*
	 * It must have a valid DOS header
	 */
	if (DosHdr->e_magic == EFI_IMAGE_DOS_SIGNATURE) {
		if (DosHdr->e_lfanew < sizeof (*DosHdr) ||
		    DosHdr->e_lfanew > datasize - 4) {
			perror(L"Invalid image\n");
			return EFI_UNSUPPORTED;
		}

		dos_sz = DosHdr->e_lfanew;
		PEHdr = (EFI_IMAGE_OPTIONAL_HEADER_UNION *)((char *)data + DosHdr->e_lfanew);
	}

	/*
	 * Has to be big enough to hold a PE header
	 */
	if (datasize - dos_sz < sizeof (PEHdr->Pe32)) {
		perror(L"Invalid image\n");
		return EFI_UNSUPPORTED;
	}

	/*
	 * If it's 64-bit, it has to hold the PE32+ header
	 */
	if (image_is_64_bit(PEHdr) &&
	    (datasize - dos_sz < sizeof (PEHdr->Pe32Plus))) {
		perror(L"Invalid image\n");
		return EFI_UNSUPPORTED;
	}

	if (!image_is_loadable(PEHdr)) {
		perror(L"Platform does not support this image\n");
		return EFI_UNSUPPORTED;
	}

	if (image_is_64_bit(PEHdr)) {
		context->NumberOfRvaAndSizes = PEHdr->Pe32Plus.OptionalHeader.NumberOfRvaAndSizes;
		context->SizeOfHeaders = PEHdr->Pe32Plus.OptionalHeader.SizeOfHeaders;
		context->ImageSize = PEHdr->Pe32Plus.OptionalHeader.SizeOfImage;
		context->SectionAlignment = PEHdr->Pe32Plus.OptionalHeader.SectionAlignment;
		FileAlignment = PEHdr->Pe32Plus.OptionalHeader.FileAlignment;
		OptHeaderSize = sizeof(EFI_IMAGE_OPTIONAL_HEADER64);
	} else {
		context->NumberOfRvaAndSizes = PEHdr->Pe32.OptionalHeader.NumberOfRvaAndSizes;
		context->SizeOfHeaders = PEHdr->Pe32.OptionalHeader.SizeOfHeaders;
		context->ImageSize = (UINT64)PEHdr->Pe32.OptionalHeader.SizeOfImage;
		context->SectionAlignment = PEHdr->Pe32.OptionalHeader.SectionAlignment;
		FileAlignment = PEHdr->Pe32.OptionalHeader.FileAlignment;
		OptHeaderSize = sizeof(EFI_IMAGE_OPTIONAL_HEADER32);
	}

	/*
	 * Set up our file alignment and section alignment expectations to
	 * be mostly sane.
	 *
	 * This probably should have a check for /power/ of two not just
	 * multiple, but in practice it hasn't been an issue.
	 */
	if (FileAlignment % 2 != 0) {
		perror(L"File Alignment is invalid (%d)\n", FileAlignment);
		return EFI_UNSUPPORTED;
	}
	if (FileAlignment == 0)
		FileAlignment = 0x200;
	if (context->SectionAlignment == 0)
		context->SectionAlignment = PAGE_SIZE;
	if (context->SectionAlignment < FileAlignment)
		context->SectionAlignment = FileAlignment;

	context->NumberOfSections = PEHdr->Pe32.FileHeader.NumberOfSections;

	/*
	 * Check and make sure the space for data directory entries is as
	 * large as we expect.
	 *
	 * In truth we could set this number smaller if we needed to -
	 * currently it's 16 but we only care about #4 and #5 (the fifth
	 * and sixth ones) - but it hasn't been a problem.  If it's too
	 * weird we'll fail trying to allocate it.
	 */
	if (EFI_IMAGE_NUMBER_OF_DIRECTORY_ENTRIES < context->NumberOfRvaAndSizes) {
		perror(L"Image header too large\n");
		return EFI_UNSUPPORTED;
	}

	/*
	 * Check that the OptionalHeaderSize and the end of the Data
	 * Directory match up sanely
	 */
	if (checked_mul(sizeof(EFI_IMAGE_DATA_DIRECTORY), EFI_IMAGE_NUMBER_OF_DIRECTORY_ENTRIES, &tmpsz0) ||
	    checked_sub(OptHeaderSize, tmpsz0, &HeaderWithoutDataDir) ||
	    checked_sub((size_t)PEHdr->Pe32.FileHeader.SizeOfOptionalHeader, HeaderWithoutDataDir, &tmpsz0) ||
	    checked_mul((size_t)context->NumberOfRvaAndSizes, sizeof (EFI_IMAGE_DATA_DIRECTORY), &tmpsz1) ||
	    (tmpsz0 != tmpsz1)) {
		perror(L"Image header overflows data directory\n");
		return EFI_UNSUPPORTED;
	}

	/*
	 * Check that the SectionHeaderOffset field is within the image.
	 */
	if (checked_add((size_t)DosHdr->e_lfanew, sizeof(UINT32), &tmpsz0) ||
	    checked_add(tmpsz0, sizeof(EFI_IMAGE_FILE_HEADER), &tmpsz0) ||
	    checked_add(tmpsz0, PEHdr->Pe32.FileHeader.SizeOfOptionalHeader, &SectionHeaderOffset)) {
		perror(L"Image sections overflow image size\n");
		return EFI_UNSUPPORTED;
	}

	/*
	 * Check that the sections headers themselves are within the image
	 */
	if (checked_sub((size_t)context->ImageSize, SectionHeaderOffset, &tmpsz0) ||
	    (tmpsz0 / EFI_IMAGE_SIZEOF_SECTION_HEADER <= context->NumberOfSections)) {
		perror(L"Image sections overflow image size\n");
		return EFI_UNSUPPORTED;
	}

	/*
	 * Check that the section headers fit within the total headers
	 */
	if (checked_sub((size_t)context->SizeOfHeaders, SectionHeaderOffset, &tmpsz0) ||
	    (tmpsz0 / EFI_IMAGE_SIZEOF_SECTION_HEADER < (UINT32)context->NumberOfSections)) {
		perror(L"Image sections overflow section headers\n");
		return EFI_UNSUPPORTED;
	}

	/*
	 * Check that the section headers are actually within the data
	 * we've read.  Might be duplicative of the ImageSize one, but it
	 * won't hurt.
	 */
	if (checked_mul((size_t)context->NumberOfSections, sizeof(EFI_IMAGE_SECTION_HEADER), &tmpsz0) ||
	    checked_add(tmpsz0, SectionHeaderOffset, &tmpsz0) ||
	    (tmpsz0 > datasize)) {
		perror(L"Image sections overflow section headers\n");
		return EFI_UNSUPPORTED;
	}

	/*
	 * Check that the optional header fits in the image.
	 */
	if (checked_sub((size_t)(uintptr_t)PEHdr, (size_t)(uintptr_t)data, &tmpsz0) ||
	    checked_add(tmpsz0, sizeof(EFI_IMAGE_OPTIONAL_HEADER_UNION), &tmpsz0) ||
	    (tmpsz0 > datasize)) {
		perror(L"Invalid image\n");
		return EFI_UNSUPPORTED;
	}

	/*
	 * Check that this claims to be a PE binary
	 */
	if (PEHdr->Te.Signature != EFI_IMAGE_NT_SIGNATURE) {
		perror(L"Unsupported image type\n");
		return EFI_UNSUPPORTED;
	}

	/*
	 * Check that relocations aren't stripped, because that won't work.
	 */
	if (PEHdr->Pe32.FileHeader.Characteristics & EFI_IMAGE_FILE_RELOCS_STRIPPED) {
		perror(L"Unsupported image - Relocations have been stripped\n");
		return EFI_UNSUPPORTED;
	}

	context->PEHdr = PEHdr;

	if (image_is_64_bit(PEHdr)) {
		context->ImageAddress = PEHdr->Pe32Plus.OptionalHeader.ImageBase;
		context->EntryPoint = PEHdr->Pe32Plus.OptionalHeader.AddressOfEntryPoint;
		context->RelocDir = &PEHdr->Pe32Plus.OptionalHeader.DataDirectory[EFI_IMAGE_DIRECTORY_ENTRY_BASERELOC];
		context->SecDir = &PEHdr->Pe32Plus.OptionalHeader.DataDirectory[EFI_IMAGE_DIRECTORY_ENTRY_SECURITY];
		context->DllCharacteristics = PEHdr->Pe32Plus.OptionalHeader.DllCharacteristics;
	} else {
		context->ImageAddress = PEHdr->Pe32.OptionalHeader.ImageBase;
		context->EntryPoint = PEHdr->Pe32.OptionalHeader.AddressOfEntryPoint;
		context->RelocDir = &PEHdr->Pe32.OptionalHeader.DataDirectory[EFI_IMAGE_DIRECTORY_ENTRY_BASERELOC];
		context->SecDir = &PEHdr->Pe32.OptionalHeader.DataDirectory[EFI_IMAGE_DIRECTORY_ENTRY_SECURITY];
		context->DllCharacteristics = PEHdr->Pe32.OptionalHeader.DllCharacteristics;
	}

	/*
	 * If NX_COMPAT is required, check that it's set.
	 */
	if ((mok_policy & MOK_POLICY_REQUIRE_NX) &&
	    !(context->DllCharacteristics & EFI_IMAGE_DLLCHARACTERISTICS_NX_COMPAT)) {
		perror(L"Policy requires NX, but image does not support NX\n");
		return EFI_UNSUPPORTED;
        }

	/*
	 * Check that the file header fits within the image.
	 */
	if (checked_add((size_t)(uintptr_t)PEHdr, PEHdr->Pe32.FileHeader.SizeOfOptionalHeader, &tmpsz0) ||
	    checked_add(tmpsz0, sizeof(UINT32), &tmpsz0) ||
	    checked_add(tmpsz0, sizeof(EFI_IMAGE_FILE_HEADER), &tmpsz0)) {
		perror(L"Invalid image\n");
		return EFI_UNSUPPORTED;
	}

	/*
	 * Check that the first section header is within the image data
	 */
	context->FirstSection = (EFI_IMAGE_SECTION_HEADER *)(uintptr_t)tmpsz0;
	if ((uint64_t)(uintptr_t)(context->FirstSection)
	    > (uint64_t)(uintptr_t)data + datasize) {
		perror(L"Invalid image\n");
		return EFI_UNSUPPORTED;
	}

	/*
	 * Check that the headers fit within the image.
	 */
	if (context->ImageSize < context->SizeOfHeaders) {
		perror(L"Invalid image\n");
		return EFI_UNSUPPORTED;
	}

	/*
	 * check that the data directory fits within the image.
	 */
	if (checked_sub((size_t)(uintptr_t)context->SecDir, (size_t)(uintptr_t)data, &tmpsz0) ||
	    (tmpsz0 > datasize - sizeof(EFI_IMAGE_DATA_DIRECTORY))) {
		perror(L"Invalid image\n");
		return EFI_UNSUPPORTED;
	}

	/*
	 * Check that the certificate table is within the binary -
	 * "VirtualAddress" is a misnomer here, it's a relative offset to
	 * the image's load address, so compared to datasize it should be
	 * absolute.
	 */
	if (check_secdir &&
	    (context->SecDir->VirtualAddress > datasize ||
	     (context->SecDir->VirtualAddress == datasize &&
	      context->SecDir->Size > 0))) {
		dprint(L"context->SecDir->VirtualAddress:0x%llx context->SecDir->Size:0x%llx datasize:0x%llx\n",
		       context->SecDir->VirtualAddress, context->SecDir->Size, datasize);
		perror(L"Malformed security header\n");
		return EFI_INVALID_PARAMETER;
	}
	return EFI_SUCCESS;
}

void
get_shim_nx_capability(EFI_HANDLE image_handle)
{
	EFI_LOADED_IMAGE_PROTOCOL*li = NULL;
	EFI_STATUS efi_status;
	PE_COFF_LOADER_IMAGE_CONTEXT context;

	efi_status = BS->HandleProtocol(image_handle, &gEfiLoadedImageProtocolGuid, (void **)&li);
	if (EFI_ERROR(efi_status) || !li) {
		dprint(L"Could not get loaded image protocol: %r\n", efi_status);
		return;
	}

	ZeroMem(&context, sizeof(context));
	efi_status = read_header(li->ImageBase, li->ImageSize, &context, false);
	if (EFI_ERROR(efi_status)) {
		dprint(L"Couldn't parse image header: %r\n", efi_status);
		return;
	}

	dprint(L"DllCharacteristics:0x%lx\n", context.DllCharacteristics);
	if (context.DllCharacteristics & EFI_IMAGE_DLLCHARACTERISTICS_NX_COMPAT) {
		dprint(L"Setting HSI from %a to %a\n",
		       decode_hsi_bits(hsi_status),
		       decode_hsi_bits(hsi_status | SHIM_HSI_STATUS_NX));
		hsi_status |= SHIM_HSI_STATUS_NX;
	}
}

static inline bool
hsi_nx_is_enforced(void)
{
	return !((hsi_status & SHIM_HSI_STATUS_HEAPX) ||
		 (hsi_status & SHIM_HSI_STATUS_STACKX) ||
		 (hsi_status & SHIM_HSI_STATUS_ROW));
}

static inline bool
hsi_api_is_present(void)
{
	return (hsi_status & SHIM_HSI_STATUS_HASMAP) ||
		((hsi_status & SHIM_HSI_STATUS_HASDSTGMSD &&
		  hsi_status & SHIM_HSI_STATUS_HASDSTSMSA));
}

void
set_shim_nx_policy(void)
{
	if ((hsi_status & SHIM_HSI_STATUS_NX) &&
	    hsi_nx_is_enforced() &&
	    hsi_api_is_present())
	{
		mok_policy |= MOK_POLICY_REQUIRE_NX;
		dprint("Enforcing NX policy for all images\n");
	}
}

// vim:fenc=utf-8:tw=75:noet
