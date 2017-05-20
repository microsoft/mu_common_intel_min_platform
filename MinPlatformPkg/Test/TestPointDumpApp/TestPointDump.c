/** @file

Copyright (c) 2017, Intel Corporation. All rights reserved.<BR>
This program and the accompanying materials
are licensed and made available under the terms and conditions of the BSD License
which accompanies this distribution.  The full text of the license may be found at
http://opensource.org/licenses/bsd-license.php

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

VOID
DumpTestPoint (
  IN VOID                     *TestPointData
  )
{
  ADAPTER_INFO_PLATFORM_TEST_POINT *TestPoint;
  UINT8                            *Features;
  CHAR16                           *ErrorString;
  UINTN                            Index;
  CHAR16                           ErrorChar;

  TestPoint = TestPointData;
  Print (L"TestPoint\n");
  Print (L"  Version                     - 0x%08x\n", TestPoint->Version);
  Print (L"  Role                        - 0x%08x\n", TestPoint->Role);
  Print (L"  ImplementationID            - %S\n", TestPoint->ImplementationID);
  Print (L"  FeaturesSize                - 0x%08x\n", TestPoint->FeaturesSize);

  Features = (UINT8 *)(TestPoint + 1);
  Print (L"  FeaturesRequired    - ");
  for (Index = 0; Index < TestPoint->FeaturesSize; Index++) {
    Print (L"%02x ", Features[Index]);
  }
  Print (L"\n");

  Features = (UINT8 *)(Features + TestPoint->FeaturesSize);
  Print (L"  FeaturesImplemented - ");
  for (Index = 0; Index < TestPoint->FeaturesSize; Index++) {
    Print (L"%02x ", Features[Index]);
  }
  Print (L"\n");

  Features = (UINT8 *)(Features + TestPoint->FeaturesSize);
  Print (L"  FeaturesVerified    - ");
  for (Index = 0; Index < TestPoint->FeaturesSize; Index++) {
    Print (L"%02x ", Features[Index]);
  }
  Print (L"\n");

  ErrorString = (CHAR16 *)(Features + TestPoint->FeaturesSize);
  Print (L"  ErrorString                 - \"");
  CopyMem (&ErrorChar, ErrorString, sizeof(ErrorChar));
  for (; ErrorChar != 0;) {
    if (ErrorChar == L'\r') {
      Print (L"\\r");
    } else if (ErrorChar == L'\n') {
      Print (L"\\n");
    } else {
      Print (L"%c", ErrorChar);
    }
    ErrorString++;
    CopyMem (&ErrorChar, ErrorString, sizeof(ErrorChar));
  }
  Print (L"\"\n");
}

VOID
DumpTestPointDataPei (
  IN UINT32                   Role OPTIONAL,
  IN CHAR16                   *ImplementationID OPTIONAL
  )
{
  EFI_PEI_HOB_POINTERS              Hob;
  ADAPTER_INFO_PLATFORM_TEST_POINT  *TestPoint;

  Hob.Raw = GetHobList ();
  while (TRUE) {
    Hob.Raw = GetNextGuidHob (&gAdapterInfoPlatformTestPointGuid, Hob.Raw);
    if (Hob.Raw == NULL) {
      return ;
    }
    TestPoint = GET_GUID_HOB_DATA (Hob);

    if ((Role == 0) ||
        ((TestPoint->Role == Role) && 
         ((ImplementationID == NULL) || (StrCmp (ImplementationID, TestPoint->ImplementationID) == 0)))) {
      DumpTestPoint (TestPoint);
    }
    Hob.Raw = GET_NEXT_HOB (Hob);
    if (Hob.Raw == NULL) {
      return ;
    }
  }
}

VOID
DumpTestPointDataDxe (
  IN UINT32                   Role OPTIONAL,
  IN CHAR16                   *ImplementationID OPTIONAL
  )
{
  EFI_STATUS                        Status;
  EFI_ADAPTER_INFORMATION_PROTOCOL  *Aip;
  UINTN                             NoHandles;
  EFI_HANDLE                        *Handles;
  UINTN                             Index;
  EFI_GUID                          *InfoTypesBuffer;
  UINTN                             InfoTypesBufferCount;
  UINTN                             InfoTypesIndex;
  EFI_ADAPTER_INFORMATION_PROTOCOL  *AipCandidate;
  VOID                              *InformationBlock;
  UINTN                             InformationBlockSize;
  ADAPTER_INFO_PLATFORM_TEST_POINT  *TestPoint;

  Status = gBS->LocateHandleBuffer (
                  ByProtocol,
                  &gEfiAdapterInformationProtocolGuid,
                  NULL,
                  &NoHandles,
                  &Handles
                  );
  if (EFI_ERROR (Status)) {
    return ;
  }

  TestPoint = NULL;
  Aip = NULL;
  InformationBlock = NULL;
  InformationBlockSize = 0;
  for (Index = 0; Index < NoHandles; Index++) {
    Status = gBS->HandleProtocol (
                    Handles[Index],
                    &gEfiAdapterInformationProtocolGuid,
                    (VOID **)&Aip
                    );
    if (EFI_ERROR (Status)) {
      continue;
    }

    //
    // Check AIP
    //
    Status = Aip->GetSupportedTypes (
                    Aip,
                    &InfoTypesBuffer,
                    &InfoTypesBufferCount
                    );
    if (EFI_ERROR (Status)) {
      continue;
    }

    AipCandidate = NULL;
    for (InfoTypesIndex = 0; InfoTypesIndex < InfoTypesBufferCount; InfoTypesIndex++) {
      if (CompareGuid (&InfoTypesBuffer[InfoTypesIndex], &gAdapterInfoPlatformTestPointGuid)) {
        AipCandidate = Aip;
        break;
      }
    }
    FreePool (InfoTypesBuffer);

    if (AipCandidate == NULL) {
      continue;
    }

    //
    // Check Role
    //
    Aip = AipCandidate;
    Status = Aip->GetInformation (
                    Aip,
                    &gAdapterInfoPlatformTestPointGuid,
                    &InformationBlock,
                    &InformationBlockSize
                    );
    if (EFI_ERROR (Status)) {
      continue;
    }

    TestPoint = InformationBlock;

    if ((Role == 0) ||
        ((TestPoint->Role == Role) && 
         ((ImplementationID == NULL) || (StrCmp (ImplementationID, TestPoint->ImplementationID) == 0)))) {
      DumpTestPoint (TestPoint);
    }
    FreePool (InformationBlock);
  }
  FreePool (Handles);
}

UINTN  mSmmTestPointDatabaseSize;
VOID   *mSmmTestPointDatabase;

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
    Print(L"SmiHandlerTestPoint: Locate SmmCommunication protocol - %r\n", Status);
    return ;
  }

  MinimalSizeNeeded = EFI_PAGE_SIZE;

  Status = EfiGetSystemConfigurationTable(
             &gEdkiiPiSmmCommunicationRegionTableGuid,
             (VOID **)&PiSmmCommunicationRegionTable
             );
  if (EFI_ERROR(Status)) {
    Print(L"SmiHandlerTestPoint: Get PiSmmCommunicationRegionTable - %r\n", Status);
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
    Print(L"SmiHandlerTestPoint: SmmCommunication - %r\n", Status);
    return ;
  }

  if (CommGetInfo->Header.ReturnStatus != 0) {
    Print(L"SmiHandlerTestPoint: GetInfo - 0x%0x\n", CommGetInfo->Header.ReturnStatus);
    return ;
  }

  mSmmTestPointDatabaseSize = (UINTN)CommGetInfo->DataSize;

  //
  // Get Data
  //
  mSmmTestPointDatabase = AllocateZeroPool(mSmmTestPointDatabaseSize);
  if (mSmmTestPointDatabase == NULL) {
    Status = EFI_OUT_OF_RESOURCES;
    Print(L"SmiHandlerTestPoint: AllocateZeroPool (0x%x) for dump buffer - %r\n", mSmmTestPointDatabaseSize, Status);
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
      Print(L"SmiHandlerTestPoint: GetData - 0x%x\n", CommGetData->Header.ReturnStatus);
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

  ErrorString = (CHAR16 *)((UINTN)TestPoint + sizeof(ADAPTER_INFO_PLATFORM_TEST_POINT) + 3 * TestPoint->FeaturesSize);

  ErrorStringMaxSize = MaxSize - sizeof(ADAPTER_INFO_PLATFORM_TEST_POINT) - TestPoint->FeaturesSize * 3;
  //
  // ErrorString might not be CHAR16 aligned.
  //
  CopyMem (&ErrorChar, ErrorString, sizeof(ErrorChar));
  for (ErrorStringLength = 0; (ErrorChar != 0) && (ErrorStringLength < (ErrorStringMaxSize/2)); ErrorStringLength++) {
    ErrorString++;
    CopyMem (&ErrorChar, ErrorString, sizeof(ErrorChar));
  }

  return sizeof(ADAPTER_INFO_PLATFORM_TEST_POINT) + 3 * TestPoint->FeaturesSize + (ErrorStringLength + 1) * sizeof(CHAR16);
}

VOID
DumpTestPointDataSmm (
  IN UINT32                   Role OPTIONAL,
  IN CHAR16                   *ImplementationID OPTIONAL
  )
{
  ADAPTER_INFO_PLATFORM_TEST_POINT  *TestPoint;
  UINTN                             Size;

  GetTestPointDataSmm ();

  if (mSmmTestPointDatabaseSize == 0) {
    return ;
  }
  if (mSmmTestPointDatabase == NULL) {
    return ;
  }

  TestPoint = mSmmTestPointDatabase;
  while ((UINTN)TestPoint < (UINTN)mSmmTestPointDatabase + mSmmTestPointDatabaseSize) {
    if ((Role == 0) ||
        ((TestPoint->Role == Role) && 
         ((ImplementationID == NULL) || (StrCmp (ImplementationID, TestPoint->ImplementationID) == 0)))) {
      DumpTestPoint (TestPoint);
    }

    //
    // Next
    //
    Size = GetTestPointInfoSize (TestPoint, (UINTN)mSmmTestPointDatabase + mSmmTestPointDatabaseSize - (UINTN)TestPoint);
    TestPoint = (ADAPTER_INFO_PLATFORM_TEST_POINT *)((UINTN)TestPoint + Size);
  }
}

EFI_STATUS
EFIAPI
TestPointDumpAppEntrypoint (
  IN EFI_HANDLE           ImageHandle,
  IN EFI_SYSTEM_TABLE     *SystemTable
  )
{
  Print(L"TestPoint PEI:\n");
  DumpTestPointDataPei (0, NULL);
  Print(L"TestPoint DXE:\n");
  DumpTestPointDataDxe (0, NULL);
  Print(L"TestPoint SMM:\n");
  DumpTestPointDataSmm (0, NULL);

  return EFI_SUCCESS;
}
