// SPDX-License-Identifier: BSD-2-Clause-Patent

#include <efi.h>

#include "version.h"

CHAR8 shim_version[] __attribute__((section (".data.ident"))) =
	"UEFI SHIM\n"
	"$Version: 15.5 $\n"
	"$BuildMachine: Linux x86_64 x86_64 x86_64 GNU/Linux $\n"
	"$Commit: master $\n";
