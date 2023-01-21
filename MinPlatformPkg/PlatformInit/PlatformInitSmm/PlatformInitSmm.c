/** @file
  This driver will register callbacks for various testpoint tests that use
  Traditional MM functionality.

  Copyright (c) 2014 - 2016, Intel Corporation. All rights reserved.<BR>
  Copyright (c) Microsoft Corporation.
  SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#include "EventNotify.h"
#include <PiSmm.h>

#include <Protocol/SmmReadyToLock.h>
#include <Protocol/SmmEndOfDxe.h>
#include <Protocol/SmmReadyToBoot.h>
#include <Protocol/SmmExitBootServices.h>

#include <Library/UefiDriverEntryPoint.h>
#include <Library/SmmServicesTableLib.h>
#include <Library/DebugLib.h>
#include <Library/BaseMemoryLib.h>
#include <Library/BoardInitLib.h>
#include <Library/TestPointCheckLib.h>
#include <Library/PerformanceLib.h>
#include <Library/HobLib.h>

/**
  Traditional MM Ready To Lock event notification handler.

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
  TestPointMmReadyToLockMmMemoryAttributeTableFunctional ();
  TestPointMmReadyToLockSecureMmCommunicationBuffer ();
  return EFI_SUCCESS;
}

/**
  Traditional MM Ready To Boot event notification handler.

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
  TestPointMmReadyToBootMmPageProtection ();
  return EFI_SUCCESS;
}

/**
  Initialize  SMM Platform.

  @param[in] ImageHandle       Image handle of this driver.
  @param[in] SystemTable       Global system service table.

  @retval EFI_SUCCESS          Always returns success.
**/
EFI_STATUS
EFIAPI
PlatformInitSmmEntryPoint (
  IN EFI_HANDLE       ImageHandle,
  IN EFI_SYSTEM_TABLE *SystemTable
  )
{
  PlatformInitMmEntryPoint ();

  // Always succeeds
  return EFI_SUCCESS;
}
