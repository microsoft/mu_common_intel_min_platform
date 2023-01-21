/** @file
  Pei library function to reset the system from FSP wrapper.

Copyright (c) 2017, Intel Corporation. All rights reserved.<BR>
SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#include <PiPei.h>
#include <Library/PeiServicesTablePointerLib.h>
#include <Library/BaseMemoryLib.h>
#include <Library/DebugLib.h>
#include <FspEas.h>
/**
  Perform platform related reset in FSP wrapper.

  @param[in] ResetType  The type of reset the platform has to perform.

  @return Will reset the system based on Reset status provided.
**/
VOID
EFIAPI
CallFspWrapperResetSystem (
  EFI_STATUS    ResetType
  )
{
  EFI_RESET_TYPE             EfiResetType;

  switch (ResetType) {
    case FSP_STATUS_RESET_REQUIRED_COLD:
      EfiResetType = EfiResetCold;
      break;
    case FSP_STATUS_RESET_REQUIRED_WARM:
      EfiResetType = EfiResetWarm;
      break;
    default:
      DEBUG ((DEBUG_ERROR, "UnSupported reset type requested. Initiating cold reset\n"));
      EfiResetType = EfiResetCold;
  }
  (*GetPeiServicesTablePointer ())->ResetSystem2 (EfiResetType, EFI_SUCCESS, 0, NULL);
  CpuDeadLoop ();
}
