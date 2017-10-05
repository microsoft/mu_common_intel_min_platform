/** @file

  Copyright (c) 2017, Intel Corporation. All rights reserved.<BR>
  This program and the accompanying materials
  are licensed and made available under the terms and conditions of the BSD License
  which accompanies this distribution.  The full text of the license may be found at
  http://opensource.org/licenses/bsd-license.php.

  THE PROGRAM IS DISTRIBUTED UNDER THE BSD LICENSE ON AN "AS IS" BASIS,
  WITHOUT WARRANTIES OR REPRESENTATIONS OF ANY KIND, EITHER EXPRESS OR IMPLIED.

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
#include <Protocol/AdapterInformation.h>
#include <Protocol/SmmCommunication.h>
#include <Guid/PiSmmCommunicationRegionTable.h>
#include <Protocol/ReportStatusCodeHandler.h>

EFI_STATUS
TestPointStubUnRegisterRscHandler (
  VOID
  );

UINTN  mSmmTestPointDatabaseSize;
VOID   *mSmmTestPointDatabase;

EFI_EVENT                   mRscNotifyEvent = NULL;
EFI_RSC_HANDLER_PROTOCOL    *mRscHandlerProtocol = NULL;

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
GetTestPointDataSmm (
  VOID
  )
{
  EFI_STATUS                                          Status;
  UINTN                                               CommSize;
  UINT8                                               *CommBuffer;
  EFI_SMM_COMMUNICATE_HEADER                          *CommHeader;
  SMI_HANDLER_TEST_POINT_PARAMETER_GET_INFO           *CommGetInfo;
  SMI_HANDLER_TEST_POINT_PARAMETER_GET_DATA_BY_OFFSET *CommGetData;
  EFI_SMM_COMMUNICATION_PROTOCOL                      *SmmCommunication;
  UINTN                                               MinimalSizeNeeded;
  EDKII_PI_SMM_COMMUNICATION_REGION_TABLE             *PiSmmCommunicationRegionTable;
  UINT32                                              Index;
  EFI_MEMORY_DESCRIPTOR                               *Entry;
  VOID                                                *Buffer;
  UINTN                                               Size;
  UINTN                                               Offset;

  Status = gBS->LocateProtocol(&gEfiSmmCommunicationProtocolGuid, NULL, (VOID **)&SmmCommunication);
  if (EFI_ERROR(Status)) {
    DEBUG ((DEBUG_INFO, "SmiHandlerTestPoint: Locate SmmCommunication protocol - %r\n", Status));
    return ;
  }

  MinimalSizeNeeded = EFI_PAGE_SIZE;

  Status = EfiGetSystemConfigurationTable(
             &gEdkiiPiSmmCommunicationRegionTableGuid,
             (VOID **)&PiSmmCommunicationRegionTable
             );
  if (EFI_ERROR(Status)) {
    DEBUG ((DEBUG_INFO, "SmiHandlerTestPoint: Get PiSmmCommunicationRegionTable - %r\n", Status));
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
  CommHeader = (EFI_SMM_COMMUNICATE_HEADER *)&CommBuffer[0];
  CopyMem(&CommHeader->HeaderGuid, &gAdapterInfoPlatformTestPointGuid, sizeof(gAdapterInfoPlatformTestPointGuid));
  CommHeader->MessageLength = sizeof(SMI_HANDLER_TEST_POINT_PARAMETER_GET_INFO);

  CommGetInfo = (SMI_HANDLER_TEST_POINT_PARAMETER_GET_INFO *)&CommBuffer[OFFSET_OF(EFI_SMM_COMMUNICATE_HEADER, Data)];
  CommGetInfo->Header.Command = SMI_HANDLER_TEST_POINT_COMMAND_GET_INFO;
  CommGetInfo->Header.DataLength = sizeof(*CommGetInfo);
  CommGetInfo->Header.ReturnStatus = (UINT64)-1;
  CommGetInfo->DataSize = 0;

  CommSize = sizeof(EFI_GUID) + sizeof(UINTN) + CommHeader->MessageLength;
  Status = SmmCommunication->Communicate(SmmCommunication, CommBuffer, &CommSize);
  if (EFI_ERROR(Status)) {
    DEBUG ((DEBUG_INFO, "SmiHandlerTestPoint: SmmCommunication - %r\n", Status));
    return ;
  }

  if (CommGetInfo->Header.ReturnStatus != 0) {
    DEBUG ((DEBUG_INFO, "SmiHandlerTestPoint: GetInfo - 0x%0x\n", CommGetInfo->Header.ReturnStatus));
    return ;
  }

  mSmmTestPointDatabaseSize = (UINTN)CommGetInfo->DataSize;

  //
  // Get Data
  //
  mSmmTestPointDatabase = AllocateZeroPool(mSmmTestPointDatabaseSize);
  if (mSmmTestPointDatabase == NULL) {
    Status = EFI_OUT_OF_RESOURCES;
    DEBUG ((DEBUG_INFO, "SmiHandlerTestPoint: AllocateZeroPool (0x%x) for dump buffer - %r\n", mSmmTestPointDatabaseSize, Status));
    return ;
  }

  CommHeader = (EFI_SMM_COMMUNICATE_HEADER *)&CommBuffer[0];
  CopyMem(&CommHeader->HeaderGuid, &gAdapterInfoPlatformTestPointGuid, sizeof(gAdapterInfoPlatformTestPointGuid));
  CommHeader->MessageLength = sizeof(SMI_HANDLER_TEST_POINT_PARAMETER_GET_DATA_BY_OFFSET);

  CommGetData = (SMI_HANDLER_TEST_POINT_PARAMETER_GET_DATA_BY_OFFSET *)&CommBuffer[OFFSET_OF(EFI_SMM_COMMUNICATE_HEADER, Data)];
  CommGetData->Header.Command = SMI_HANDLER_TEST_POINT_COMMAND_GET_DATA_BY_OFFSET;
  CommGetData->Header.DataLength = sizeof(*CommGetData);
  CommGetData->Header.ReturnStatus = (UINT64)-1;

  CommSize = sizeof(EFI_GUID) + sizeof(UINTN) + CommHeader->MessageLength;
  Buffer = (UINT8 *)CommHeader + CommSize;
  Size -= CommSize;

  CommGetData->DataBuffer = (PHYSICAL_ADDRESS)(UINTN)Buffer;
  CommGetData->DataOffset = 0;
  while (CommGetData->DataOffset < mSmmTestPointDatabaseSize) {
    Offset = (UINTN)CommGetData->DataOffset;
    if (Size <= (mSmmTestPointDatabaseSize - CommGetData->DataOffset)) {
      CommGetData->DataSize = (UINT64)Size;
    } else {
      CommGetData->DataSize = (UINT64)(mSmmTestPointDatabaseSize - CommGetData->DataOffset);
    }
    Status = SmmCommunication->Communicate(SmmCommunication, CommBuffer, &CommSize);
    ASSERT_EFI_ERROR(Status);

    if (CommGetData->Header.ReturnStatus != 0) {
      FreePool(mSmmTestPointDatabase);
      mSmmTestPointDatabase = NULL;
      DEBUG ((DEBUG_INFO, "SmiHandlerTestPoint: GetData - 0x%x\n", CommGetData->Header.ReturnStatus));
      return ;
    }
    CopyMem((UINT8 *)mSmmTestPointDatabase + Offset, (VOID *)(UINTN)CommGetData->DataBuffer, (UINTN)CommGetData->DataSize);
  }

  DEBUG ((DEBUG_INFO, "SmmTestPointDatabaseSize - 0x%x\n", mSmmTestPointDatabaseSize));

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
PublishSmmTestPoint (
  VOID
  )
{
  ADAPTER_INFO_PLATFORM_TEST_POINT  *TestPoint;
  UINTN                             TestPointSize;

  DEBUG ((DEBUG_INFO, "PublishSmmTestPoint\n"));

  GetTestPointDataSmm ();

  if (mSmmTestPointDatabaseSize == 0) {
    return ;
  }
  if (mSmmTestPointDatabase == NULL) {
    return ;
  }

  TestPoint = mSmmTestPointDatabase;
  while ((UINTN)TestPoint < (UINTN)mSmmTestPointDatabase + mSmmTestPointDatabaseSize) {
    TestPointSize = GetTestPointInfoSize (TestPoint, (UINTN)mSmmTestPointDatabase + mSmmTestPointDatabaseSize - (UINTN)TestPoint);
    
    TestPointLibSetTable (TestPoint, TestPointSize);

    TestPoint = (ADAPTER_INFO_PLATFORM_TEST_POINT *)((UINTN)TestPoint + TestPointSize);
  }
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
TestPointStubStatusCodeListener (
  IN EFI_STATUS_CODE_TYPE     CodeType,
  IN EFI_STATUS_CODE_VALUE    Value,
  IN UINT32                   Instance,
  IN EFI_GUID                 *CallerId,
  IN EFI_STATUS_CODE_DATA     *Data
  )
{
  EFI_STATUS  Status;
  STATIC BOOLEAN     Published = FALSE;

  //
  // Check whether status code is what we are interested in.
  //
  if ((CodeType & EFI_STATUS_CODE_TYPE_MASK) != EFI_PROGRESS_CODE) {
    return EFI_UNSUPPORTED;
  }

  Status = EFI_SUCCESS;
  if (Value == (EFI_SOFTWARE_DXE_BS_DRIVER | EFI_SW_DXE_BS_PC_READY_TO_BOOT_EVENT)) {
    if (!Published) {
      PublishSmmTestPoint ();
      Published = TRUE;
    }
  } else if (Value == PcdGet32 (PcdProgressCodeOsLoaderLoad)) {
  } else if (Value == PcdGet32 (PcdProgressCodeOsLoaderStart)) {
  } else if (Value == (EFI_SOFTWARE_EFI_BOOT_SERVICE | EFI_SW_BS_PC_EXIT_BOOT_SERVICES)) {
    TestPointStubUnRegisterRscHandler ();
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
  Status = mRscHandlerProtocol->Register (TestPointStubStatusCodeListener, TPL_HIGH_LEVEL);
  ASSERT_EFI_ERROR (Status);

  gBS->CloseEvent (mRscNotifyEvent);
  mRscNotifyEvent = NULL;
}

EFI_STATUS
TestPointStubRegisterRscHandler (
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
TestPointStubUnRegisterRscHandler (
  VOID
  )
{
  if (mRscHandlerProtocol != NULL) {
    mRscHandlerProtocol->Unregister (TestPointStubStatusCodeListener);
    mRscHandlerProtocol = NULL;
  }
  if (mRscNotifyEvent != NULL) {
    gBS->CloseEvent (mRscNotifyEvent);
    mRscNotifyEvent = NULL;
  }
  return EFI_SUCCESS;
}

VOID
TestPointStubForSmm (
  VOID
  )
{
  TestPointStubRegisterRscHandler ();
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
TestPointStubDxeEntryPoint (
  IN EFI_HANDLE       ImageHandle,
  IN EFI_SYSTEM_TABLE *SystemTable
  )
{
  TestPointStubForPei ();
  TestPointStubForSmm ();

  return EFI_SUCCESS;
}