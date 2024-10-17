/** @file
  Boot service StandaloneMm BIOS ID library implementation.

  These functions in this file can be called during DXE and cannot be called during runtime
  or in SMM which should use a RT or SMM library.


Copyright (c) 2023, Intel Corporation. All rights reserved.<BR>
SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#include <PiMm.h>
#include <Library/HobLib.h>
#include <Library/BaseMemoryLib.h>
#include <Library/DebugLib.h>
#include <Library/BiosIdLib.h>

#include <Guid/BiosId.h>

/**
  This function returns BIOS ID by searching HOB.
  It also debug print the BIOS ID found.

  @param[out] BiosIdImage   The BIOS ID got from HOB or FV. It is optional,
                            no BIOS ID will be returned if it is NULL as input.

  @retval EFI_SUCCESS               BIOS ID has been got successfully.
  @retval EFI_NOT_FOUND             BIOS ID image is not found, and no parameter will be modified.

**/
EFI_STATUS
EFIAPI
GetBiosId (
  OUT BIOS_ID_IMAGE  *BiosIdImage OPTIONAL
  )
{
  BIOS_ID_IMAGE  TempBiosIdImage;
  VOID           *Address;
  UINTN          Size;

  Address = NULL;
  Size    = 0;

  if (BiosIdImage == NULL) {
    //
    // It is NULL as input, so no BIOS ID will be returned.
    // Use temp buffer to hold the BIOS ID.
    //
    BiosIdImage = &TempBiosIdImage;
  }

  Address = GetFirstGuidHob (&gBiosIdGuid);
  if (Address != NULL) {
    Size = sizeof (BIOS_ID_IMAGE);
    CopyMem ((VOID *)BiosIdImage, GET_GUID_HOB_DATA (Address), Size);

    DEBUG ((DEBUG_INFO, "StandaloneMm get BIOS ID from HOB successfully\n"));
    DEBUG ((DEBUG_INFO, "BIOS ID: %s\n", (CHAR16 *)(&(BiosIdImage->BiosIdString))));
    return EFI_SUCCESS;
  }

  DEBUG ((DEBUG_ERROR, "StandaloneMm get BIOS ID failed: %r\n", EFI_NOT_FOUND));
  return EFI_NOT_FOUND;
}
