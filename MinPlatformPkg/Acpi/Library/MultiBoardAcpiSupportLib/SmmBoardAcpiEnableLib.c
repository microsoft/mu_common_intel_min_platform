/** @file

Copyright (c) 2017, Intel Corporation. All rights reserved.<BR>
Copyright (c) Microsoft Corporation.<BR>
SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#include <Library/BoardAcpiTableLib.h>
#include <Library/MultiBoardAcpiSupportLib.h>
#include <Library/DebugLib.h>
#include <Library/MmServicesTableLib.h>

EFI_STATUS
EFIAPI
BoardEnableAcpi (
  IN BOOLEAN  EnableSci
  )
{
  BOARD_ACPI_ENABLE_FUNC     *BoardAcpiEnableFunc;
  EFI_STATUS                 Status;

  Status = gMmst->MmLocateProtocol (
                    &gBoardAcpiEnableGuid,
                    NULL,
                    (VOID **)&BoardAcpiEnableFunc
                    );
  if (!EFI_ERROR(Status)) {
    if (BoardAcpiEnableFunc->BoardEnableAcpi != NULL) {
      return BoardAcpiEnableFunc->BoardEnableAcpi (EnableSci);
    }
  }
  return EFI_SUCCESS;
}

EFI_STATUS
EFIAPI
BoardDisableAcpi (
  IN BOOLEAN  DisableSci
  )
{
  BOARD_ACPI_ENABLE_FUNC     *BoardAcpiEnableFunc;
  EFI_STATUS                 Status;

  Status = gMmst->MmLocateProtocol (
                    &gBoardAcpiEnableGuid,
                    NULL,
                    (VOID **)&BoardAcpiEnableFunc
                    );
  if (!EFI_ERROR(Status)) {
    if (BoardAcpiEnableFunc->BoardDisableAcpi != NULL) {
      return BoardAcpiEnableFunc->BoardDisableAcpi (DisableSci);
    }
  }
  return EFI_SUCCESS;
}

