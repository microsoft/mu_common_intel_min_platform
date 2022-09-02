/** @file
  This driver will register four callbacks to run different testpoint tests.
  This is a common file between traditional and standalone MM that is a wrapper
  for different callbacks.

  Copyright (c) 2014 - 2016, Intel Corporation. All rights reserved.<BR>
  Copyright (c) Microsoft Corporation.
  SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#include <PiMm.h>

#include "EventNotify.h"
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

/**
  MM End Of Dxe event notification handler.

  @param[in] Protocol   Points to the protocol's unique identifier.
  @param[in] Interface  Points to the interface instance.
  @param[in] Handle     The handle on which the interface was installed.

  @retval EFI_SUCCESS   Notification handler runs successfully.
**/
EFI_STATUS
EFIAPI
MmEndOfDxeEventNotify (
  IN CONST EFI_GUID  *Protocol,
  IN VOID            *Interface,
  IN EFI_HANDLE      Handle
  )
{
  TestPointMmEndOfDxeSmrrFunctional ();
  return EFI_SUCCESS;
}

/**
  MM Exit Boot Services event notification handler.

  @param[in] Protocol   Points to the protocol's unique identifier.
  @param[in] Interface  Points to the interface instance.
  @param[in] Handle     The handle on which the interface was installed.

  @retval EFI_SUCCESS   Notification handler runs successfully.
**/
EFI_STATUS
EFIAPI
MmExitBootServicesEventNotify (
  IN CONST EFI_GUID  *Protocol,
  IN VOID            *Interface,
  IN EFI_HANDLE      Handle
  )
{
  TestPointMmExitBootServices ();
  return EFI_SUCCESS;
}

/**
  Initialize Shared MM Platform.

  @retval EFI_SUCCESS           Initialization complete.
**/
EFI_STATUS
EFIAPI
PlatformInitMmEntryPoint (
  VOID
  )
{
  EFI_STATUS  Status;
  VOID        *MmEndOfDxeRegistration;
  VOID        *MmReadyToLockRegistration;
  VOID        *MmReadyToBootRegistration;
  VOID        *MmExitBootServicesRegistration;

  Status = gMmst->MmRegisterProtocolNotify (
                    &gEfiMmEndOfDxeProtocolGuid,
                    MmEndOfDxeEventNotify,
                    &MmEndOfDxeRegistration
                    );
  ASSERT_EFI_ERROR (Status);

  Status = gMmst->MmRegisterProtocolNotify (
                    &gEfiMmReadyToLockProtocolGuid,
                    MmReadyToLockEventNotify,
                    &MmReadyToLockRegistration
                    );
  ASSERT_EFI_ERROR (Status);

  Status = gMmst->MmRegisterProtocolNotify (
                    &gEdkiiSmmReadyToBootProtocolGuid,
                    MmReadyToBootEventNotify,
                    &MmReadyToBootRegistration
                    );
  ASSERT_EFI_ERROR (Status);

  Status = gMmst->MmRegisterProtocolNotify (
                    &gEdkiiSmmExitBootServicesProtocolGuid,
                    MmExitBootServicesEventNotify,
                    &MmExitBootServicesRegistration
                    );
  ASSERT_EFI_ERROR (Status);

  return EFI_SUCCESS;
}
