/** @file

Copyright (c) 2017, Intel Corporation. All rights reserved.<BR>
This program and the accompanying materials are licensed and made available under
the terms and conditions of the BSD License that accompanies this distribution.
The full text of the license may be found at
http://opensource.org/licenses/bsd-license.php.

THE PROGRAM IS DISTRIBUTED UNDER THE BSD LICENSE ON AN "AS IS" BASIS,
WITHOUT WARRANTIES OR REPRESENTATIONS OF ANY KIND, EITHER EXPRESS OR IMPLIED.

**/

#include <Library/BoardInitLib.h>
#include <Library/MultiBoardInitSupportLib.h>
#include <Library/PcdLib.h>
#include <Library/DebugLib.h>
#include <Library/UefiBootServicesTableLib.h>

EFI_STATUS
EFIAPI
BoardInitAfterPciEnumeration (
  VOID
  )
{
  BOARD_NOTIFICATION_INIT_FUNC    *BoardNotificationInit;
  EFI_STATUS                      Status;

  Status = gBS->LocateProtocol (
                  &gBoardNotificationInitGuid,
                  NULL,
                  (VOID **)&BoardNotificationInit
                  );
  if (!EFI_ERROR(Status)) {
    if (BoardNotificationInit->BoardInitAfterPciEnumeration != NULL) {
      return BoardNotificationInit->BoardInitAfterPciEnumeration ();
    }
  }
  return EFI_SUCCESS;
}

EFI_STATUS
EFIAPI
BoardInitReadyToBoot (
  VOID
  )
{
  BOARD_NOTIFICATION_INIT_FUNC    *BoardNotificationInit;
  EFI_STATUS                      Status;

  Status = gBS->LocateProtocol (
                  &gBoardNotificationInitGuid,
                  NULL,
                  (VOID **)&BoardNotificationInit
                  );
  if (!EFI_ERROR(Status)) {
    if (BoardNotificationInit->BoardInitReadyToBoot != NULL) {
      return BoardNotificationInit->BoardInitReadyToBoot ();
    }
  }
  return EFI_SUCCESS;
}

EFI_STATUS
EFIAPI
BoardInitEndOfFirmware (
  VOID
  )
{
  BOARD_NOTIFICATION_INIT_FUNC    *BoardNotificationInit;
  EFI_STATUS                      Status;

  Status = gBS->LocateProtocol (
                  &gBoardNotificationInitGuid,
                  NULL,
                  (VOID **)&BoardNotificationInit
                  );
  if (!EFI_ERROR(Status)) {
    if (BoardNotificationInit->BoardInitEndOfFirmware != NULL) {
      return BoardNotificationInit->BoardInitEndOfFirmware ();
    }
  }
  return EFI_SUCCESS;
}
