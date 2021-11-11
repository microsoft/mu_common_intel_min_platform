/** @file

  Platform configuration check library NULL implementation for TestPointCheckLib

  Copyright (c) Microsoft Corporation. All rights reserved
 **/

#include <Uefi.h>
#include <Library/DebugLib.h>
#include <Library/UefiLib.h>
#include <Library/BaseLib.h>
#include <Library/PrintLib.h>
#include <Library/PlatformConfigCheckLib.h>

/**
  This function dumps platform level information at Exit Boot Services.

  @retval     EFI_SUCCESS  Function has completed successfully.
              Other        Function error indicates failure.
**/
EFI_STATUS
EFIAPI
PlatformConfigDumpExitBootServices (
  VOID
  )
{
  return EFI_SUCCESS;
}
