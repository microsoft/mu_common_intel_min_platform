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
  This function peforms platform level checks at Exit Boot Services.

  @retval     EFI_SUCCESS  Function has completed successfully.
              Other        Function error indicates failure.
**/
EFI_STATUS
EFIAPI
PlatformConfigCheckExitBootServices (
  VOID
  )
{
  return EFI_SUCCESS;
}
