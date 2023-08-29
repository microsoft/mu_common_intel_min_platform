/** @file

  Copyright (c) 2017, Intel Corporation. All rights reserved.<BR>
  Copyright (c) Microsoft Corporation.
  SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#include <PiDxe.h>
#include <Library/BaseLib.h>
#include <Library/BaseMemoryLib.h>
#include <Library/MemoryAllocationLib.h>
#include <Library/UefiBootServicesTableLib.h>
#include <Library/DebugLib.h>
#include <Library/UefiLib.h>
#include <Library/HobLib.h>
#include <Library/TestPointLib.h>
#include <Library/MmUnblockMemoryLib.h>
#include <Protocol/AdapterInformation.h>
#include <Protocol/MmCommunication.h>
#include <Guid/PiSmmCommunicationRegionTable.h>

UINTN  mMmTestPointDatabaseSize;
VOID   *mMmTestPointDatabase;
VOID   *mMmCommBuffer;

VOID
PublishPeiTestPoint (
  VOID
  )
{
  EFI_PEI_HOB_POINTERS              Hob;
  ADAPTER_INFO_PLATFORM_TEST_POINT  *TestPoint;
  UINTN                             TestPointSize;

  DEBUG ((DEBUG_INFO, "PublishPeiTestPoint\n"));

  Hob.Raw = GetHobList ();
  while (TRUE) {
    Hob.Raw = GetNextGuidHob (&gAdapterInfoPlatformTestPointGuid, Hob.Raw);
    if (Hob.Raw == NULL) {
      return ;
    }
    TestPoint = GET_GUID_HOB_DATA (Hob);
    TestPointSize = GET_GUID_HOB_DATA_SIZE (Hob);

    TestPointLibSetTable (TestPoint, TestPointSize);

    Hob.Raw = GET_NEXT_HOB (Hob);
    if (Hob.Raw == NULL) {
      return ;
    }
  }
}

VOID
TestPointStubForPei (
  VOID
  )
{
  PublishPeiTestPoint ();
}

VOID
GetTestPointDataMm (
  VOID
  )
{
  EFI_STATUS                                          Status;
  UINTN                                               CommSize;
  UINT8                                               *CommBuffer;
  EFI_MM_COMMUNICATE_HEADER                          *CommHeader;
  MMI_HANDLER_TEST_POINT_PARAMETER_GET_INFO           *CommGetInfo;
  MMI_HANDLER_TEST_POINT_PARAMETER_GET_DATA_BY_OFFSET *CommGetData;
  EFI_MM_COMMUNICATION_PROTOCOL                      *MmCommunication;
  UINTN                                               MinimalSizeNeeded;
  EDKII_PI_SMM_COMMUNICATION_REGION_TABLE             *PiSmmCommunicationRegionTable;
  UINT32                                              Index;
  EFI_MEMORY_DESCRIPTOR                               *Entry;
  UINTN                                               Size;
  UINTN                                               Offset;

  Status = gBS->LocateProtocol(&gEfiMmCommunicationProtocolGuid, NULL, (VOID **)&MmCommunication);
  if (EFI_ERROR(Status)) {
    DEBUG ((DEBUG_INFO, "MmiHandlerTestPoint: Locate MmCommunication protocol - %r\n", Status));
    return ;
  }

  MinimalSizeNeeded = EFI_PAGE_SIZE;

  Status = EfiGetSystemConfigurationTable(
             &gEdkiiPiSmmCommunicationRegionTableGuid,
             (VOID **)&PiSmmCommunicationRegionTable
             );
  if (EFI_ERROR(Status)) {
    DEBUG ((DEBUG_INFO, "MmiHandlerTestPoint: Get PiSmmCommunicationRegionTable - %r\n", Status));
    return ;
  }
  ASSERT(PiSmmCommunicationRegionTable != NULL);
  Entry = (EFI_MEMORY_DESCRIPTOR *)(PiSmmCommunicationRegionTable + 1);
  Size = 0;
  for (Index = 0; Index < PiSmmCommunicationRegionTable->NumberOfEntries; Index++) {
    if (Entry->Type == EfiConventionalMemory) {
      Size = EFI_PAGES_TO_SIZE((UINTN)Entry->NumberOfPages);
      if (Size >= MinimalSizeNeeded) {
        break;
      }
    }
    Entry = (EFI_MEMORY_DESCRIPTOR *)((UINT8 *)Entry + PiSmmCommunicationRegionTable->DescriptorSize);
  }
  ASSERT(Index < PiSmmCommunicationRegionTable->NumberOfEntries);
  CommBuffer = (UINT8 *)(UINTN)Entry->PhysicalStart;

  //
  // Get Size
  //
  CommHeader = (EFI_MM_COMMUNICATE_HEADER *)&CommBuffer[0];
  CopyMem(&CommHeader->HeaderGuid, &gAdapterInfoPlatformTestPointGuid, sizeof(gAdapterInfoPlatformTestPointGuid));
  CommHeader->MessageLength = sizeof(MMI_HANDLER_TEST_POINT_PARAMETER_GET_INFO);

  CommGetInfo = (MMI_HANDLER_TEST_POINT_PARAMETER_GET_INFO *)&CommBuffer[OFFSET_OF(EFI_MM_COMMUNICATE_HEADER, Data)];
  CommGetInfo->Header.Command = MMI_HANDLER_TEST_POINT_COMMAND_GET_INFO;
  CommGetInfo->Header.DataLength = sizeof(*CommGetInfo);
  CommGetInfo->Header.ReturnStatus = (UINT64)-1;
  CommGetInfo->DataSize = 0;

  CommSize = OFFSET_OF (EFI_MM_COMMUNICATE_HEADER, Data) + (UINTN)CommHeader->MessageLength;

  Status = MmCommunication->Communicate(MmCommunication, CommBuffer, &CommSize);
  if (EFI_ERROR(Status)) {
    DEBUG ((DEBUG_INFO, "MmiHandlerTestPoint: MmCommunication - %r\n", Status));
    return ;
  }

  if (CommGetInfo->Header.ReturnStatus != 0) {
    DEBUG ((DEBUG_INFO, "MmiHandlerTestPoint: GetInfo - 0x%0x\n", CommGetInfo->Header.ReturnStatus));
    return ;
  }

  mMmTestPointDatabaseSize = (UINTN)CommGetInfo->DataSize;

  //
  // Get Data
  //
  mMmTestPointDatabase = AllocateZeroPool(mMmTestPointDatabaseSize);
  if (mMmTestPointDatabase == NULL) {
    Status = EFI_OUT_OF_RESOURCES;
    DEBUG ((DEBUG_INFO, "MmiHandlerTestPoint: AllocateZeroPool (0x%x) for dump buffer - %r\n", mMmTestPointDatabaseSize, Status));
    return ;
  }

  CommHeader = (EFI_MM_COMMUNICATE_HEADER *)&CommBuffer[0];
  CopyMem(&CommHeader->HeaderGuid, &gAdapterInfoPlatformTestPointGuid, sizeof(gAdapterInfoPlatformTestPointGuid));
  CommHeader->MessageLength = sizeof(MMI_HANDLER_TEST_POINT_PARAMETER_GET_DATA_BY_OFFSET);

  CommGetData = (MMI_HANDLER_TEST_POINT_PARAMETER_GET_DATA_BY_OFFSET *)&CommBuffer[OFFSET_OF(EFI_MM_COMMUNICATE_HEADER, Data)];
  CommGetData->Header.Command = MMI_HANDLER_TEST_POINT_COMMAND_GET_DATA_BY_OFFSET;
  CommGetData->Header.DataLength = sizeof(*CommGetData);
  CommGetData->Header.ReturnStatus = (UINT64)-1;

  CommSize = OFFSET_OF (EFI_MM_COMMUNICATE_HEADER, Data) + (UINTN)CommHeader->MessageLength;
  Size -= CommSize;

  CommGetData->DataBuffer = (PHYSICAL_ADDRESS)(UINTN)mMmCommBuffer;
  CommGetData->DataOffset = 0;
  while (CommGetData->DataOffset < mMmTestPointDatabaseSize) {
    Offset = (UINTN)CommGetData->DataOffset;
    if (Size <= (mMmTestPointDatabaseSize - CommGetData->DataOffset)) {
      CommGetData->DataSize = (UINT64)Size;
    } else {
      CommGetData->DataSize = (UINT64)(mMmTestPointDatabaseSize - CommGetData->DataOffset);
    }
    Status = MmCommunication->Communicate(MmCommunication, CommBuffer, &CommSize);
    ASSERT_EFI_ERROR(Status);

    if (CommGetData->Header.ReturnStatus != 0) {
      FreePool(mMmTestPointDatabase);
      mMmTestPointDatabase = NULL;
      DEBUG ((DEBUG_INFO, "MmiHandlerTestPoint: GetData - 0x%x\n", CommGetData->Header.ReturnStatus));
      return ;
    }
    CopyMem((UINT8 *)mMmTestPointDatabase + Offset, (VOID *)(UINTN)CommGetData->DataBuffer, (UINTN)CommGetData->DataSize);
  }

  DEBUG ((DEBUG_INFO, "MmTestPointDatabaseSize - 0x%x\n", mMmTestPointDatabaseSize));

  return ;
}

UINTN
GetTestPointInfoSize (
  IN ADAPTER_INFO_PLATFORM_TEST_POINT  *TestPoint,
  IN UINTN                             MaxSize
  )
{
  CHAR16  *ErrorString;
  UINTN   ErrorStringLength;
  UINTN   ErrorStringMaxSize;
  CHAR16  ErrorChar;

  ErrorString = (CHAR16 *)((UINTN)TestPoint + sizeof(ADAPTER_INFO_PLATFORM_TEST_POINT) + TEST_POINT_FEATURES_ITEM_NUMBER * TestPoint->FeaturesSize);

  ErrorStringMaxSize = MaxSize - sizeof(ADAPTER_INFO_PLATFORM_TEST_POINT) - TestPoint->FeaturesSize * TEST_POINT_FEATURES_ITEM_NUMBER;
  //
  // ErrorString might not be CHAR16 aligned.
  //
  CopyMem (&ErrorChar, ErrorString, sizeof(ErrorChar));
  for (ErrorStringLength = 0; (ErrorChar != 0) && (ErrorStringLength < (ErrorStringMaxSize/2)); ErrorStringLength++) {
    ErrorString++;
    CopyMem (&ErrorChar, ErrorString, sizeof(ErrorChar));
  }

  return sizeof(ADAPTER_INFO_PLATFORM_TEST_POINT) + TEST_POINT_FEATURES_ITEM_NUMBER * TestPoint->FeaturesSize + (ErrorStringLength + 1) * sizeof(CHAR16);
}

VOID
PublishMmTestPoint (
  VOID
  )
{
  ADAPTER_INFO_PLATFORM_TEST_POINT  *TestPoint;
  UINTN                             TestPointSize;

  DEBUG ((DEBUG_INFO, "PublishMmTestPoint\n"));

  GetTestPointDataMm ();

  if (mMmTestPointDatabaseSize == 0) {
    return ;
  }
  if (mMmTestPointDatabase == NULL) {
    return ;
  }

  TestPoint = mMmTestPointDatabase;
  while ((UINTN)TestPoint < (UINTN)mMmTestPointDatabase + mMmTestPointDatabaseSize) {
    TestPointSize = GetTestPointInfoSize (TestPoint, (UINTN)mMmTestPointDatabase + mMmTestPointDatabaseSize - (UINTN)TestPoint);

    TestPointLibSetTable (TestPoint, TestPointSize);

    TestPoint = (ADAPTER_INFO_PLATFORM_TEST_POINT *)((UINTN)TestPoint + TestPointSize);
  }
}

/**
  Notification function of END_OF_DXE event group.

  This is a notification function registered on END_OF_DXE event group.
  When End of DXE is signalled we get the size of the PiSmmCommunicationRegionTable
  to allocate a runtime buffer used for communicating the MM Testpoint results.
  This requires the allocated pages to be unblocked for MM which must occur before
  ReadyToLock.

  @param[in] Event        Event whose notification function is being invoked.
  @param[in] Context      Pointer to the notification function's context.

**/
VOID
EFIAPI
OnEndOfDxe (
  IN EFI_EVENT  Event,
  IN VOID       *Context
  )
{
  EFI_STATUS                                          Status;
  UINTN                                               CommSize;
  EFI_MM_COMMUNICATION_PROTOCOL                      *MmCommunication;
  UINTN                                               MinimalSizeNeeded;
  EDKII_PI_SMM_COMMUNICATION_REGION_TABLE             *PiSmmCommunicationRegionTable;
  UINT32                                              Index;
  EFI_MEMORY_DESCRIPTOR                               *Entry;
  UINTN                                               Size;

  Status = gBS->LocateProtocol(&gEfiMmCommunicationProtocolGuid, NULL, (VOID **)&MmCommunication);
  if (EFI_ERROR(Status)) {
    DEBUG ((DEBUG_ERROR, "MmiHandlerTestPoint: Locate MmCommunication protocol - %r\n", Status));
    return ;
  }

  MinimalSizeNeeded = EFI_PAGE_SIZE;

  Status = EfiGetSystemConfigurationTable(
             &gEdkiiPiSmmCommunicationRegionTableGuid,
             (VOID **)&PiSmmCommunicationRegionTable
             );
  if (EFI_ERROR(Status)) {
    DEBUG ((DEBUG_ERROR, "MmiHandlerTestPoint: Get PiSmmCommunicationRegionTable - %r\n", Status));
    return ;
  }
  if (PiSmmCommunicationRegionTable == NULL) {
    DEBUG ((DEBUG_ERROR, "Failed to get the PiSmmCommunicationRegionTable.\n"));
    ASSERT(PiSmmCommunicationRegionTable != NULL);
    return ;
  }
  Entry = (EFI_MEMORY_DESCRIPTOR *)(PiSmmCommunicationRegionTable + 1);
  Size = 0;
  for (Index = 0; Index < PiSmmCommunicationRegionTable->NumberOfEntries; Index++) {
    if (Entry->Type == EfiConventionalMemory) {
      Size = EFI_PAGES_TO_SIZE((UINTN)Entry->NumberOfPages);
      if (Size >= MinimalSizeNeeded) {
        break;
      }
    }
    Entry = (EFI_MEMORY_DESCRIPTOR *)((UINT8 *)Entry + PiSmmCommunicationRegionTable->DescriptorSize);
  }
  ASSERT(Index < PiSmmCommunicationRegionTable->NumberOfEntries);
  if (Size < MinimalSizeNeeded) {
    DEBUG ((DEBUG_ERROR, "Failed to find any entries in the PiSmmCommunicationRegionTable.\n"));
    return ;
  }

  CommSize = OFFSET_OF (EFI_MM_COMMUNICATE_HEADER, Data) + sizeof(MMI_HANDLER_TEST_POINT_PARAMETER_GET_DATA_BY_OFFSET);

  Size -= CommSize;
  mMmCommBuffer = AllocateRuntimeZeroPool(Size);

  //
  // Request to unblock the newly allocated cache region to be accessible from inside MM
  //
  Status = MmUnblockMemoryRequest (
             (EFI_PHYSICAL_ADDRESS) ALIGN_VALUE ((UINTN)mMmCommBuffer - EFI_PAGE_SIZE + 1, EFI_PAGE_SIZE),
             EFI_SIZE_TO_PAGES (Size)
             );
  if ((Status != EFI_UNSUPPORTED) && EFI_ERROR (Status)) {
    DEBUG ((DEBUG_ERROR, "Failed to unblock memory!\n"));
    return;
  }
}


/**
  Notification function of END_OF_DXE event group.
  This is required to unblock pages before ReadyToLock occurs

**/
VOID
TestPointUnblockCall (
  VOID
  )
{
  EFI_STATUS Status;
  EFI_EVENT  EndOfDxeEvent;

  Status = gBS->CreateEventEx (
                  EVT_NOTIFY_SIGNAL,
                  TPL_CALLBACK,
                  OnEndOfDxe,
                  NULL,
                  &gEfiEndOfDxeEventGroupGuid,
                  &EndOfDxeEvent
                  );

  ASSERT_EFI_ERROR (Status);
}

/**
  Notification function of EVT_GROUP_READY_TO_BOOT event group.
  It runs after most ReadyToBoot event signaled.

  This is a notification function registered on EVT_GROUP_READY_TO_BOOT event group.
  When the Boot Manager is about to load and execute a boot option, it reclaims variable
  storage if free size is below the threshold.

  @param[in] Event        Event whose notification function is being invoked.
  @param[in] Context      Pointer to the notification function's context.

**/
VOID
EFIAPI
OnReadyToBootLater (
  IN EFI_EVENT  Event,
  IN VOID       *Context
  )
{
  gBS->CloseEvent (Event);

  PublishMmTestPoint ();
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
  EFI_EVENT                         ReadyToBootLaterEvent;

  gBS->CloseEvent (Event);

  Status = gBS->CreateEvent (
                  EVT_NOTIFY_SIGNAL,
                  TPL_CALLBACK,
                  OnReadyToBootLater,
                  NULL,
                  &ReadyToBootLaterEvent
                  );
  ASSERT_EFI_ERROR (Status);

  gBS->SignalEvent (ReadyToBootLaterEvent);
}

VOID
TestPointStubForMm (
  VOID
  )
{
  EFI_STATUS Status;
  EFI_EVENT  ReadyToBootEvent;

  Status = EfiCreateEventReadyToBootEx (
             TPL_CALLBACK,
             OnReadyToBoot,
             NULL,
             &ReadyToBootEvent
             );
  ASSERT_EFI_ERROR (Status);
}

/**
  Initialize TestPointStub.

  @param[in] ImageHandle       Image handle of this driver.
  @param[in] SystemTable       Global system service table.

  @retval EFI_SUCCESS           Initialization complete.
  @exception EFI_UNSUPPORTED       The chipset is unsupported by this driver.
  @retval EFI_OUT_OF_RESOURCES  Do not have enough resources to initialize the driver.
  @retval EFI_DEVICE_ERROR      Device error, driver exits abnormally.
**/
EFI_STATUS
EFIAPI
TestPointStubDxeMmEntryPoint (
  IN EFI_HANDLE       ImageHandle,
  IN EFI_SYSTEM_TABLE *SystemTable
  )
{
  TestPointStubForPei ();
  TestPointStubForMm ();
  TestPointUnblockCall ();

  return EFI_SUCCESS;
}
