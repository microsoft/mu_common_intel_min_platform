/** @file

Copyright (c) 2017, Intel Corporation. All rights reserved.<BR>
SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#include <Library/BoardAcpiEnableLib.h>
#include <Library/MultiBoardAcpiSupportLib.h>
#include <Library/DebugLib.h>
#include <Library/MmServicesTableLib.h>

EFI_STATUS
EFIAPI
RegisterBoardAcpiEnableFunc (
  IN BOARD_ACPI_ENABLE_FUNC  *BoardAcpiEnableFunc
  )
{
  EFI_HANDLE  Handle;
  EFI_STATUS  Status;

  Handle = NULL;
  Status = gMmst->MmInstallProtocolInterface (
                    &Handle,
                    &gBoardAcpiEnableGuid,
                    EFI_NATIVE_INTERFACE,
                    BoardAcpiEnableFunc
                    );
  ASSERT_EFI_ERROR(Status);

  return EFI_SUCCESS;
}
