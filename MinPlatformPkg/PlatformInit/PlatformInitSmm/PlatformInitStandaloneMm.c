/** @file
  This driver will register two callbacks to call fsp's notifies.

  Copyright (c) 2014 - 2016, Intel Corporation. All rights reserved.<BR>
  Copyright (c) Microsoft Corporation.
  SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#include "EventNotify.h"
#include <PiMm.h>

#include <Protocol/MmReadyToLock.h>
#include <Protocol/MmEndOfDxe.h>
#include <Protocol/SmmReadyToBoot.h>
#include <Protocol/SmmExitBootServices.h>

#include <Library/StandaloneMmDriverEntryPoint.h>
#include <Library/MmServicesTableLib.h>
#include <Library/DebugLib.h>
#include <Library/BaseMemoryLib.h>
#include <Library/BoardInitLib.h>
#include <Library/TestPointCheckLib.h>
#include <Library/PerformanceLib.h>
#include <Library/HobLib.h>

EFI_STATUS
EFIAPI
StandaloneMmReadyToBootEventNotify (
  IN CONST EFI_GUID  *Protocol,
  IN VOID            *Interface,
  IN EFI_HANDLE      Handle
  );

EFI_STATUS
EFIAPI
StandaloneMmReadyToLockEventNotify (
  IN CONST EFI_GUID  *Protocol,
  IN VOID            *Interface,
  IN EFI_HANDLE      Handle
  );

/**
  Standalone MM Ready To Lock event notification handler.

  @param[in] Protocol   Points to the protocol's unique identifier.
  @param[in] Interface  Points to the interface instance.
  @param[in] Handle     The handle on which the interface was installed.

  @retval EFI_SUCCESS   Notification handler runs successfully.
**/
EFI_STATUS
EFIAPI
MmReadyToLockEventNotify (
  IN CONST EFI_GUID  *Protocol,
  IN VOID            *Interface,
  IN EFI_HANDLE      Handle
  )
{
  EFI_STATUS Status;

  Status = StandaloneMmReadyToLockEventNotify (Protocol, Interface, Handle);
  return Status;
}

/**
  Standalone MM Ready To Boot event notification handler.

  @param[in] Protocol   Points to the protocol's unique identifier.
  @param[in] Interface  Points to the interface instance.
  @param[in] Handle     The handle on which the interface was installed.

  @retval EFI_SUCCESS   Notification handler runs successfully.
**/
EFI_STATUS
EFIAPI
MmReadyToBootEventNotify (
  IN CONST EFI_GUID  *Protocol,
  IN VOID            *Interface,
  IN EFI_HANDLE      Handle
  )
{
  EFI_STATUS Status;

  Status = StandaloneMmReadyToBootEventNotify (Protocol, Interface, Handle);
  return Status;
}

/**
  Standalone MM Ready To Lock event notification handler.

  @param[in] Protocol   Points to the protocol's unique identifier.
  @param[in] Interface  Points to the interface instance.
  @param[in] Handle     The handle on which the interface was installed.

  @retval EFI_SUCCESS   Notification handler runs successfully.
**/
EFI_STATUS
EFIAPI
StandaloneMmReadyToLockEventNotify (
  IN CONST EFI_GUID  *Protocol,
  IN VOID            *Interface,
  IN EFI_HANDLE      Handle
  )
{
  TestPointMmReadyToLockSecureMmCommunicationBuffer ();
  return EFI_SUCCESS;
}

/**
  Standalone MM Ready To Boot event notification handler.

  @param[in] Protocol   Points to the protocol's unique identifier.
  @param[in] Interface  Points to the interface instance.
  @param[in] Handle     The handle on which the interface was installed.

  @retval EFI_SUCCESS   Notification handler runs successfully.
**/
EFI_STATUS
EFIAPI
StandaloneMmReadyToBootEventNotify (
  IN CONST EFI_GUID  *Protocol,
  IN VOID            *Interface,
  IN EFI_HANDLE      Handle
  )
{
  TestPointStandaloneMmReadyToBootStandaloneMmPageProtection ();
  return EFI_SUCCESS;
}

/**
  Initialize  Standalone MM Platform.

  @param[in] ImageHandle       Image handle of this driver.
  @param[in] MmSystemTable     Global system service table.

  @retval EFI_SUCCESS           Initialization complete.
  @exception EFI_UNSUPPORTED       The chipset is unsupported by this driver.
  @retval EFI_OUT_OF_RESOURCES  Do not have enough resources to initialize the driver.
  @retval EFI_DEVICE_ERROR      Device error, driver exits abnormally.
**/
EFI_STATUS
EFIAPI
PlatformInitStandaloneMmEntryPoint (
  IN EFI_HANDLE           ImageHandle,
  IN EFI_MM_SYSTEM_TABLE  *MmSystemTable
  )
{
  PlatformInitMmEntryPoint ();

  // Always succeeds
  return EFI_SUCCESS;
}
