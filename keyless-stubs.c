#include "shim.h"

/* SBAT globals and helpers expected by pe.c */
list_t sbat_var;

EFI_STATUS verify_sbat(size_t n UNUSED,
		       struct sbat_section_entry **entries UNUSED)
{
	return EFI_SUCCESS;
}

void cleanup_sbat_section_entries(size_t n UNUSED,
				  struct sbat_section_entry **entries UNUSED)
{
}

/* Secure boot and verification hooks expected by pe.c */
BOOLEAN secure_mode(void)
{
	return FALSE; /* keep verification path disabled for this tool */
}

EFI_STATUS verify_buffer(char *data UNUSED, int datasize UNUSED,
			 PE_COFF_LOADER_IMAGE_CONTEXT *context UNUSED,
			 UINT8 *sha256hash UNUSED, UINT8 *sha1hash UNUSED)
{
	return EFI_SUCCESS;
}

/* Load options expected by pe.c */
VOID *load_options = NULL;
UINT32 load_options_size = 0;

/* TPM logging expected by pe.c (match include/tpm.h signature) */
EFI_STATUS tpm_log_pe(EFI_PHYSICAL_ADDRESS buf UNUSED, UINTN size UNUSED,
		      EFI_PHYSICAL_ADDRESS entrypoint UNUSED,
		      EFI_DEVICE_PATH *FilePath UNUSED,
		      UINT8 *sha1hash UNUSED, UINT8 pcrIndex UNUSED)
{
	return EFI_SUCCESS;
}


EFI_STATUS parse_sbat_section(char *sbat_data UNUSED, size_t sbat_size UNUSED,
			      size_t *n UNUSED,
			      struct sbat_section_entry ***entries UNUSED)
{
	if (n)
		*n = 0;
	if (entries)
		*entries = NULL;
	return EFI_SUCCESS;
}