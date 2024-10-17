/** @file
  Boot service common BIOS ID library implementation.

  These functions in this file can be called during DXE and cannot be called during runtime
  or in SMM which should use a RT or SMM library.


Copyright (c) 2023, Intel Corporation. All rights reserved.<BR>
SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#include <PiDxe.h>
#include <Library/BaseMemoryLib.h>
#include <Library/BiosIdLib.h>
#include <Guid/BiosId.h>

/**
  This function returns the BIOS Version & Release Date and Time by getting and converting BIOS ID.

  @param[out] BiosVersion       The Bios Version out of the conversion.
  @param[out] BiosReleaseDate   The Bios Release Date out of the conversion.
  @param[out] BiosReleaseTime   The Bios Release Time out of the conversion.

  @retval EFI_SUCCESS               BIOS Version & Release Date and Time have been got successfully.
  @retval EFI_NOT_FOUND             BIOS ID image is not found, and no parameter will be modified.
  @retval EFI_INVALID_PARAMETER     All the parameters are NULL.

**/
EFI_STATUS
EFIAPI
GetBiosVersionDateTime (
  OUT CHAR16  *BiosVersion OPTIONAL,
  OUT CHAR16  *BiosReleaseDate OPTIONAL,
  OUT CHAR16  *BiosReleaseTime OPTIONAL
  )
{
  EFI_STATUS     Status;
  BIOS_ID_IMAGE  BiosIdImage;

  if ((BiosVersion == NULL) && (BiosReleaseDate == NULL) && (BiosReleaseTime == NULL)) {
    return EFI_INVALID_PARAMETER;
  }

  Status = GetBiosId (&BiosIdImage);
  if (EFI_ERROR (Status)) {
    return EFI_NOT_FOUND;
  }

  if (BiosVersion != NULL) {
    //
    // Fill the BiosVersion data from the BIOS ID.
    //
    CopyMem (BiosVersion, &(BiosIdImage.BiosIdString), sizeof (BIOS_ID_STRING));
  }

  if (BiosReleaseDate != NULL) {
    //
    // Fill the build timestamp date from the BIOS ID in the "MM/DD/YY" format.
    //
    BiosReleaseDate[0] = BiosIdImage.BiosIdString.TimeStamp[2];
    BiosReleaseDate[1] = BiosIdImage.BiosIdString.TimeStamp[3];
    BiosReleaseDate[2] = (CHAR16)((UINT8)('/'));

    BiosReleaseDate[3] = BiosIdImage.BiosIdString.TimeStamp[4];
    BiosReleaseDate[4] = BiosIdImage.BiosIdString.TimeStamp[5];
    BiosReleaseDate[5] = (CHAR16)((UINT8)('/'));

    //
    // Add 20 for SMBIOS table
    // Current Linux kernel will misjudge 09 as year 0, so using 2009 for SMBIOS table
    //
    BiosReleaseDate[6] = '2';
    BiosReleaseDate[7] = '0';
    BiosReleaseDate[8] = BiosIdImage.BiosIdString.TimeStamp[0];
    BiosReleaseDate[9] = BiosIdImage.BiosIdString.TimeStamp[1];

    BiosReleaseDate[10] = (CHAR16)((UINT8)('\0'));
  }

  if (BiosReleaseTime != NULL) {
    //
    // Fill the build timestamp time from the BIOS ID in the "HH:MM" format.
    //
    BiosReleaseTime[0] = BiosIdImage.BiosIdString.TimeStamp[6];
    BiosReleaseTime[1] = BiosIdImage.BiosIdString.TimeStamp[7];
    BiosReleaseTime[2] = (CHAR16)((UINT8)(':'));

    BiosReleaseTime[3] = BiosIdImage.BiosIdString.TimeStamp[8];
    BiosReleaseTime[4] = BiosIdImage.BiosIdString.TimeStamp[9];

    BiosReleaseTime[5] = (CHAR16)((UINT8)('\0'));
  }

  return EFI_SUCCESS;
}
