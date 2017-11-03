/** @file
  This driver will register two callbacks to call fsp's notifies.

  Copyright (c) 2014 - 2016, Intel Corporation. All rights reserved.<BR>
  This program and the accompanying materials
  are licensed and made available under the terms and conditions of the BSD License
  which accompanies this distribution.  The full text of the license may be found at
  http://opensource.org/licenses/bsd-license.php.

  THE PROGRAM IS DISTRIBUTED UNDER THE BSD LICENSE ON AN "AS IS" BASIS,
  WITHOUT WARRANTIES OR REPRESENTATIONS OF ANY KIND, EITHER EXPRESS OR IMPLIED.

**/

#include <PiDxe.h>

#include <Protocol/PciEnumerationComplete.h>

#include <Library/UefiDriverEntryPoint.h>
#include <Library/UefiBootServicesTableLib.h>
#include <Library/DebugLib.h>
#include <Library/BaseMemoryLib.h>
#include <Library/UefiLib.h>
#include <Library/BoardInitLib.h>
#include <Library/TestPointCheckLib.h>
#include <Library/PerformanceLib.h>
#include <Library/HobLib.h>
#include <Protocol/ReportStatusCodeHandler.h>

EFI_STATUS
PlatformInitUnRegisterRscHandler (
  VOID
  );

EFI_EVENT                   mRscNotifyEvent = NULL;
EFI_RSC_HANDLER_PROTOCOL    *mRscHandlerProtocol = NULL;

/**
  PciEnumerationComplete Protocol notification event handler.

  @param[in] Event    Event whose notification function is being invoked.
  @param[in] Context  Pointer to the notification function's context.
**/
VOID
EFIAPI
OnPciEnumerationComplete (
  IN EFI_EVENT  Event,
  IN VOID       *Context
  )
{
  EFI_STATUS          Status;
  VOID                *Interface;

  //
  // Try to locate it because gEfiPciEnumerationCompleteProtocolGuid will trigger it once when registration.
  // Just return if it is not found.
  //
  Status = gBS->LocateProtocol (
                  &gEfiPciEnumerationCompleteProtocolGuid,
                  NULL,
                  &Interface
                  );
  if (EFI_ERROR (Status)) {
    return ;
  }

  Status = BoardInitAfterPciEnumeration ();
  ASSERT_EFI_ERROR(Status);

  TestPointPciEnumerationDonePciBusMasterDisabled ();

  TestPointPciEnumerationDonePciResourceAllocated ();
}

/**
  This stage is notified when system exists platform manufacture authentication.

  @param  Event         Event whose notification function is being invoked.
  @param  Context       Pointer to the notification function's context, which is
                        always zero in current implementation.

**/
VOID
EFIAPI
OnEndOfDxe (
  IN EFI_EVENT  Event,
  IN VOID       *Context
  )
{
  gBS->CloseEvent (Event);

  TestPointEndOfDxeNoThirdPartyPciOptionRom ();
  
  TestPointEndOfDxeDmarTableFuntional ();
}

/**
  SmmReadyToLock Protocol notification event handler.

  @param[in] Event    Event whose notification function is being invoked.
  @param[in] Context  Pointer to the notification function's context.
**/
VOID
EFIAPI
OnDxeSmmReadyToLock (
  IN EFI_EVENT  Event,
  IN VOID       *Context
  )
{
  EFI_STATUS          Status;
  VOID                *Interface;

  //
  // Try to locate it because gEfiPciEnumerationCompleteProtocolGuid will trigger it once when registration.
  // Just return if it is not found.
  //
  Status = gBS->LocateProtocol (
                  &gEfiDxeSmmReadyToLockProtocolGuid,
                  NULL,
                  &Interface
                  );
  if (EFI_ERROR (Status)) {
    return ;
  }

  TestPointDxeSmmReadyToLockSmramAligned ();

  TestPointDxeSmmReadyToLockWsmtTableFuntional ();
}

/**
  Notification function of EVT_GROUP_READY_TO_BOOT event group.

  This is a notification function registered on EVT_GROUP_READY_TO_BOOT event group.
  When the Boot Manager is about to load and execute a boot option, it reclaims variable
  storage if free size is below the threshold.

  @param[in] Event        Event whose notification function is being invoked.
  @param[in] Context      Pointer to the notification function's context.

**/
VOID
EFIAPI
OnReadyToBoot (
  IN EFI_EVENT  Event,
  IN VOID       *Context
  )
{
  EFI_STATUS                        Status;

  gBS->CloseEvent (Event);

  Status = BoardInitReadyToBoot ();
  ASSERT_EFI_ERROR(Status);

  TestPointDxeSmmReadyToBootSmmPageProtection ();
}

/**
  This stage is notified just before the firmware/Preboot environment transfers
  management of all system resources to the OS or next level execution environment.

  @param  Event         Event whose notification function is being invoked.
  @param  Context       Pointer to the notification function's context, which is
                        always zero in current implementation.

**/
VOID
EFIAPI
OnEndOfFirmware (
  IN EFI_EVENT  Event,
  IN VOID       *Context
  )
{
  EFI_STATUS                        Status;

  gBS->CloseEvent (Event);
  
  PlatformInitUnRegisterRscHandler ();

  Status = BoardInitEndOfFirmware ();
  ASSERT_EFI_ERROR(Status);

  TestPointExitBootServices ();
}

/**
  Main entry for the FSP DXE module.

  This routine registers two callbacks to call fsp's notifies.

  @param[in] ImageHandle    The firmware allocated handle for the EFI image.
  @param[in] SystemTable    A pointer to the EFI System Table.

  @retval EFI_SUCCESS       The entry point is executed successfully.
  @retval other             Some error occurs when executing this entry point.

**/
EFI_STATUS
BoardNotificationInitEntryPoint (
  VOID
  )
{
  EFI_STATUS Status;
  EFI_EVENT  ReadyToBootEvent;
  VOID       *Registration;
  EFI_EVENT  ProtocolNotifyEvent;
  EFI_EVENT  ExitBootServicesEvent;
  EFI_EVENT  EndOfDxeEvent;
  VOID       *SmmReadyToLockRegistration;
  EFI_EVENT  SmmReadyToLockEvent;

  ProtocolNotifyEvent = EfiCreateProtocolNotifyEvent (
                          &gEfiPciEnumerationCompleteProtocolGuid,
                          TPL_CALLBACK,
                          OnPciEnumerationComplete,
                          NULL,
                          &Registration
                          );
  ASSERT (ProtocolNotifyEvent != NULL);
  
  Status = gBS->CreateEventEx (
                  EVT_NOTIFY_SIGNAL,
                  TPL_CALLBACK,
                  OnEndOfDxe,
                  NULL,
                  &gEfiEndOfDxeEventGroupGuid,
                  &EndOfDxeEvent
                  );
  ASSERT_EFI_ERROR (Status);
  
  SmmReadyToLockEvent = EfiCreateProtocolNotifyEvent  (
                          &gEfiDxeSmmReadyToLockProtocolGuid,
                          TPL_CALLBACK,
                          OnDxeSmmReadyToLock,
                          NULL,
                          &SmmReadyToLockRegistration
                          );

  Status = EfiCreateEventReadyToBootEx (
             TPL_CALLBACK,
             OnReadyToBoot,
             NULL,
             &ReadyToBootEvent
             );
  ASSERT_EFI_ERROR (Status);
  
  Status = gBS->CreateEventEx (
                  EVT_NOTIFY_SIGNAL,
                  TPL_CALLBACK,
                  OnEndOfFirmware,
                  NULL,
                  &gEfiEventExitBootServicesGuid,
                  &ExitBootServicesEvent
                  );
  ASSERT_EFI_ERROR (Status);

  return EFI_SUCCESS;
}

/**
  Report status code listener
  for OsLoaderLoadImageStart and OsLoaderStartImageStart.

  @param[in]  CodeType            Indicates the type of status code being reported.
  @param[in]  Value               Describes the current status of a hardware or software entity.
                                  This included information about the class and subclass that is used to
                                  classify the entity as well as an operation.
  @param[in]  Instance            The enumeration of a hardware or software entity within
                                  the system. Valid instance numbers start with 1.
  @param[in]  CallerId            This optional parameter may be used to identify the caller.
                                  This parameter allows the status code driver to apply different rules to
                                  different callers.
  @param[in]  Data                This optional parameter may be used to pass additional data.

  @retval EFI_SUCCESS             Status code is what we expected.
  @retval EFI_UNSUPPORTED         Status code not supported.

**/
EFI_STATUS
EFIAPI
PlatformInitStatusCodeListener (
  IN EFI_STATUS_CODE_TYPE     CodeType,
  IN EFI_STATUS_CODE_VALUE    Value,
  IN UINT32                   Instance,
  IN EFI_GUID                 *CallerId,
  IN EFI_STATUS_CODE_DATA     *Data
  )
{
  EFI_STATUS  Status;
  STATIC BOOLEAN     Tested = FALSE;

  //
  // Check whether status code is what we are interested in.
  //
  if ((CodeType & EFI_STATUS_CODE_TYPE_MASK) != EFI_PROGRESS_CODE) {
    return EFI_UNSUPPORTED;
  }

  Status = EFI_SUCCESS;
  if (Value == (EFI_SOFTWARE_DXE_BS_DRIVER | EFI_SW_DXE_BS_PC_READY_TO_BOOT_EVENT)) {
    if (!Tested) {
      TestPointReadyToBootAcpiTableFuntional ();
      TestPointReadyToBootMemoryTypeInformationFunctional ();
      TestPointReadyToBootUefiMemoryAttributeTableFunctional ();
      TestPointReadyToBootUefiBootVariableFunctional ();
      TestPointReadyToBootUefiConsoleVariableFunctional ();
      TestPointReadyToBootHstiTableFunctional ();
      TestPointReadyToBootSmiHandlerInstrument ();

      TestPointReadyToBootUefiSecureBootEnabled ();
      TestPointReadyToBootPiSignedFvBootEnabled ();
      TestPointReadyToBootTcgTrustedBootEnabled ();
      TestPointReadyToBootTcgMorEnabled ();
      TestPointReadyToBootEsrtTableFunctional ();
      Tested = TRUE;
    }
  } else if (Value == PcdGet32 (PcdProgressCodeOsLoaderLoad)) {
  } else if (Value == PcdGet32 (PcdProgressCodeOsLoaderStart)) {
  } else if (Value == (EFI_SOFTWARE_EFI_BOOT_SERVICE | EFI_SW_BS_PC_EXIT_BOOT_SERVICES)) {
    PlatformInitUnRegisterRscHandler ();
  } else if (Value == (EFI_SOFTWARE_DXE_BS_DRIVER | EFI_SW_DXE_BS_PC_LEGACY_BOOT_EVENT)) {
  } else {
    //
    // Ignore else progress code.
    //
    Status = EFI_UNSUPPORTED;
  }

  return Status;
}

/**
  RscHandler Protocol notification event handler.

  @param[in] Event    Event whose notification function is being invoked.
  @param[in] Context  Pointer to the notification function's context.
**/
VOID
EFIAPI
OnRscHandlerInstalled (
  IN EFI_EVENT  Event,
  IN VOID       *Context
  )
{
  EFI_STATUS          Status;
  
  Status = gBS->LocateProtocol (
                  &gEfiRscHandlerProtocolGuid,
                  NULL,
                  &mRscHandlerProtocol
                  );
  if (EFI_ERROR (Status)) {
    return ;
  }
  
  //
  // Register report status code listener for OS Loader load and start.
  //
  Status = mRscHandlerProtocol->Register (PlatformInitStatusCodeListener, TPL_HIGH_LEVEL);
  ASSERT_EFI_ERROR (Status);

  gBS->CloseEvent (mRscNotifyEvent);
  mRscNotifyEvent = NULL;
}

EFI_STATUS
PlatformInitRegisterRscHandler (
  VOID
  )
{
  VOID       *Registration;

  mRscNotifyEvent = EfiCreateProtocolNotifyEvent (
                      &gEfiRscHandlerProtocolGuid,
                      TPL_CALLBACK,
                      OnRscHandlerInstalled,
                      NULL,
                      &Registration
                      );
  ASSERT (mRscNotifyEvent != NULL);
  
  return EFI_SUCCESS;
}

EFI_STATUS
PlatformInitUnRegisterRscHandler (
  VOID
  )
{
  if (mRscHandlerProtocol != NULL) {
    mRscHandlerProtocol->Unregister (PlatformInitStatusCodeListener);
    mRscHandlerProtocol = NULL;
  }
  if (mRscNotifyEvent != NULL) {
    gBS->CloseEvent (mRscNotifyEvent);
    mRscNotifyEvent = NULL;
  }
  return EFI_SUCCESS;
}

/**
  Initialize  DXE Platform.

  @param[in] ImageHandle       Image handle of this driver.
  @param[in] SystemTable       Global system service table.

  @retval EFI_SUCCESS           Initialization complete.
  @exception EFI_UNSUPPORTED       The chipset is unsupported by this driver.
  @retval EFI_OUT_OF_RESOURCES  Do not have enough resources to initialize the driver.
  @retval EFI_DEVICE_ERROR      Device error, driver exits abnormally.
**/
EFI_STATUS
EFIAPI
PlatformInitDxeEntryPoint (
  IN EFI_HANDLE       ImageHandle,
  IN EFI_SYSTEM_TABLE *SystemTable
  )
{
  PlatformInitRegisterRscHandler ();
  BoardNotificationInitEntryPoint ();

  return EFI_SUCCESS;
}