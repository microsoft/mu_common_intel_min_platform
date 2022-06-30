/** @file

  Copyright (c) 2017, Intel Corporation. All rights reserved.<BR>
  SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#include "StandaloneMmTestPoint.h"

EFI_STATUS
GetAllStandaloneMmTestPointData (
  IN OUT UINTN  *DataSize,
  IN OUT VOID   *Data
  )
{
  EFI_STATUS                        Status;
  EFI_ADAPTER_INFORMATION_PROTOCOL  *Aip;
  UINTN                             NoHandles;
  EFI_HANDLE                        *Handles;
  UINTN                             HandleBufSize;
  UINTN                             Index;
  EFI_GUID                          *InfoTypesBuffer;
  UINTN                             InfoTypesBufferCount;
  UINTN                             InfoTypesIndex;
  EFI_ADAPTER_INFORMATION_PROTOCOL  *AipCandidate;
  VOID                              *InformationBlock;
  UINTN                             InformationBlockSize;
  UINTN                             TotalSize;
  EFI_STATUS                        RetStatus;

  TotalSize = 0;

  Handles = NULL;
  HandleBufSize = 0;
  Status = gMmst->MmLocateHandle (
                    ByProtocol,
                    &gEfiAdapterInformationProtocolGuid,
                    NULL,
                    &HandleBufSize,
                    Handles
                    );
  if (Status != EFI_BUFFER_TOO_SMALL) {
    RetStatus = EFI_NOT_FOUND;
    goto Done ;
  }
  Handles = AllocateZeroPool (HandleBufSize);
  if (Handles == NULL) {
    RetStatus = EFI_OUT_OF_RESOURCES;
    goto Done ;
  }
  Status = gMmst->MmLocateHandle (
                    ByProtocol,
                    &gEfiAdapterInformationProtocolGuid,
                    NULL,
                    &HandleBufSize,
                    Handles
                    );
  if (EFI_ERROR (Status)) {
    RetStatus = Status;
    goto Done ;
  }
  NoHandles = HandleBufSize / sizeof(EFI_HANDLE);

  RetStatus = EFI_SUCCESS;

  Aip = NULL;
  InformationBlock = NULL;
  InformationBlockSize = 0;
  for (Index = 0; Index < NoHandles; Index++) {
    Status = gMmst->MmHandleProtocol (
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

    if ((Data != NULL) && (TotalSize + InformationBlockSize <= *DataSize)) {
      CopyMem ((UINT8 *)Data + TotalSize, InformationBlock, InformationBlockSize);
    } else {
      RetStatus = EFI_BUFFER_TOO_SMALL;
    }
    TotalSize += InformationBlockSize;

    FreePool (InformationBlock);
  }

Done:

  *DataSize = TotalSize;

  if (Handles != NULL) {
    FreePool (Handles);
  }

  return RetStatus;
}

/**
  StandaloneMm test point SMI handler to get info.

  @param SmiHandlerTestPointParameterGetInfo The parameter of StandaloneMm test point SMI handler get info.

**/
VOID
StandaloneMmTestPointSmiHandlerGetInfo (
  IN SMI_HANDLER_TEST_POINT_PARAMETER_GET_INFO   *SmiHandlerTestPointParameterGetInfo
  )
{
  UINTN       DataSize;
  EFI_STATUS  Status;
  
  DataSize = 0;
  Status = GetAllStandaloneMmTestPointData (&DataSize, NULL);
  if (Status == EFI_BUFFER_TOO_SMALL) {
    SmiHandlerTestPointParameterGetInfo->DataSize = DataSize;
    SmiHandlerTestPointParameterGetInfo->Header.ReturnStatus = 0;
  } else {
    SmiHandlerTestPointParameterGetInfo->DataSize = 0;
    SmiHandlerTestPointParameterGetInfo->Header.ReturnStatus = (UINT64)(INT64)(INTN)EFI_NOT_FOUND;
  }
}

/**
  Copy StandaloneMm Test Point data.

  @param DataBuffer  The buffer to hold StandaloneMm Test Point data.
  @param DataSize    On input, data buffer size.
                     On output, actual data buffer size copied.
  @param DataOffset  On input, data buffer offset to copy.
                     On output, next time data buffer offset to copy.

**/
VOID
SmiHandlerTestPointCopyData (
  IN VOID       *InputData,
  IN UINTN      InputDataSize,
  OUT VOID      *DataBuffer,
  IN OUT UINT64 *DataSize,
  IN OUT UINT64 *DataOffset
  )
{
  if (*DataOffset >= InputDataSize) {
    *DataOffset = InputDataSize;
    return;
  }
  if (InputDataSize - *DataOffset < *DataSize) {
    *DataSize = InputDataSize - *DataOffset;
  }

  CopyMem(
    DataBuffer,
    (UINT8 *)InputData + *DataOffset,
    (UINTN)*DataSize
    );
  *DataOffset = *DataOffset + *DataSize;
}

/**
  StandaloneMm test point SMI handler to get data by offset.

  @param SmiHandlerTestPointParameterGetDataByOffset   The parameter of StandaloneMm test point SMI handler get data by offset.

**/
VOID
StandaloneMmTestPointSmiHandlerGetDataByOffset (
  IN SMI_HANDLER_TEST_POINT_PARAMETER_GET_DATA_BY_OFFSET     *SmiHandlerTestPointParameterGetDataByOffset
  )
{
  SMI_HANDLER_TEST_POINT_PARAMETER_GET_DATA_BY_OFFSET    SmiHandlerTestPointGetDataByOffset;
  VOID                                                   *Data;
  UINTN                                                  DataSize;
  EFI_STATUS                                             Status;

  Data = NULL;

  CopyMem (
    &SmiHandlerTestPointGetDataByOffset,
    SmiHandlerTestPointParameterGetDataByOffset,
    sizeof(SmiHandlerTestPointGetDataByOffset)
    );

  //
  // Sanity check
  //
  if (!MmCommBufferValid((UINTN)SmiHandlerTestPointGetDataByOffset.DataBuffer, (UINTN)SmiHandlerTestPointGetDataByOffset.DataSize)) {
    DEBUG((DEBUG_ERROR, "StandaloneMmTestPointSmiHandlerGetDataByOffset: StandaloneMmTestPoint get data in SMRAM or overflow!\n"));
    SmiHandlerTestPointParameterGetDataByOffset->Header.ReturnStatus = (UINT64)(INT64)(INTN)EFI_ACCESS_DENIED;
    goto Done;
  }
  
  DataSize = 0;
  Status = GetAllStandaloneMmTestPointData (&DataSize, NULL);
  if (Status != EFI_BUFFER_TOO_SMALL) {
    SmiHandlerTestPointParameterGetDataByOffset->Header.ReturnStatus = (UINT64)(INT64)(INTN)EFI_NOT_FOUND;
    goto Done;
  }
  Data = AllocatePool (DataSize);
  if (Data == NULL) {
    SmiHandlerTestPointParameterGetDataByOffset->Header.ReturnStatus = (UINT64)(INT64)(INTN)EFI_OUT_OF_RESOURCES;
    goto Done;
  }
  Status = GetAllStandaloneMmTestPointData (&DataSize, Data);
  if (EFI_ERROR(Status)) {
    SmiHandlerTestPointParameterGetDataByOffset->Header.ReturnStatus = (UINT64)(INT64)(INTN)Status;
    goto Done;
  }

  //
  // The SpeculationBarrier() call here is to ensure the previous range/content
  // checks for the CommBuffer have been completed before calling into
  // SmiHandlerTestPointCopyData().
  //
  SpeculationBarrier ();
  SmiHandlerTestPointCopyData (
    Data,
    DataSize,
    (VOID *)(UINTN)SmiHandlerTestPointGetDataByOffset.DataBuffer,
    &SmiHandlerTestPointGetDataByOffset.DataSize,
    &SmiHandlerTestPointGetDataByOffset.DataOffset
    );

  CopyMem (
    SmiHandlerTestPointParameterGetDataByOffset,
    &SmiHandlerTestPointGetDataByOffset,
    sizeof(SmiHandlerTestPointGetDataByOffset)
    );

  SmiHandlerTestPointParameterGetDataByOffset->Header.ReturnStatus = 0;

Done:
  if (Data != NULL) {
    FreePool (Data);
  }
}

/**
  Dispatch function for a Software SMI handler.

  Caution: This function may receive untrusted input.
  Communicate buffer and buffer size are external input, so this function will do basic validation.

  @param DispatchHandle  The unique handle assigned to this handler by SmiHandlerRegister().
  @param Context         Points to an optional handler context which was specified when the
                         handler was registered.
  @param CommBuffer      A pointer to a collection of data in memory that will
                         be conveyed from a non-StandlaoneMm environment into an StandaloneMm environment.
  @param CommBufferSize  The size of the CommBuffer.

  @retval EFI_SUCCESS Command is handled successfully.
**/
EFI_STATUS
EFIAPI
StandaloneMmTestPointSmiHandler (
  IN EFI_HANDLE  DispatchHandle,
  IN CONST VOID  *Context         OPTIONAL,
  IN OUT VOID    *CommBuffer      OPTIONAL,
  IN OUT UINTN   *CommBufferSize  OPTIONAL
  )
{
  SMI_HANDLER_TEST_POINT_PARAMETER_HEADER     *SmiHandlerTestPointParameterHeader;
  UINTN                                       TempCommBufferSize;

  DEBUG((DEBUG_ERROR, "StandaloneMmTestPointSmiHandler Enter\n"));

  // PROBLEM HERE FOR TESTPOINT

  //
  // If input is invalid, stop processing this SMI
  //
  if (CommBuffer == NULL || CommBufferSize == NULL) {
    return EFI_SUCCESS;
  }

  TempCommBufferSize = *CommBufferSize;

  if (TempCommBufferSize < sizeof(SMI_HANDLER_TEST_POINT_PARAMETER_HEADER)) {
    DEBUG((DEBUG_ERROR, "StandaloneMmTestPointSmiHandler: StandaloneMm communication buffer size invalid!\n"));
    return EFI_SUCCESS;
  }

  if (!MmCommBufferValid((UINTN)CommBuffer, TempCommBufferSize)) {
    DEBUG((DEBUG_ERROR, "StandaloneMmTestPointSmiHandler: StandaloneMm communication buffer in SMRAM or overflow!\n"));
    return EFI_SUCCESS;
  }

  SmiHandlerTestPointParameterHeader = (SMI_HANDLER_TEST_POINT_PARAMETER_HEADER *)((UINTN)CommBuffer);
  SmiHandlerTestPointParameterHeader->ReturnStatus = (UINT64)-1;

  switch (SmiHandlerTestPointParameterHeader->Command) {
  case SMI_HANDLER_TEST_POINT_COMMAND_GET_INFO:
    DEBUG((DEBUG_ERROR, "SmiHandlerTestPointHandlerGetInfo\n"));
    if (TempCommBufferSize != sizeof(SMI_HANDLER_TEST_POINT_PARAMETER_GET_INFO)) {
      DEBUG((DEBUG_ERROR, "StandaloneMmTestPointSmiHandler: StandaloneMm communication buffer size invalid!\n"));
      return EFI_SUCCESS;
    }
    StandaloneMmTestPointSmiHandlerGetInfo((SMI_HANDLER_TEST_POINT_PARAMETER_GET_INFO *)(UINTN)CommBuffer);
    break;
  case SMI_HANDLER_TEST_POINT_COMMAND_GET_DATA_BY_OFFSET:
    DEBUG((DEBUG_ERROR, "SmiHandlerTestPointHandlerGetDataByOffset\n"));
    if (TempCommBufferSize != sizeof(SMI_HANDLER_TEST_POINT_PARAMETER_GET_DATA_BY_OFFSET)) {
      DEBUG((DEBUG_ERROR, "StandaloneMmTestPointSmiHandler: StandaloneMm communication buffer size invalid!\n"));
      return EFI_SUCCESS;
    }
    StandaloneMmTestPointSmiHandlerGetDataByOffset((SMI_HANDLER_TEST_POINT_PARAMETER_GET_DATA_BY_OFFSET *)(UINTN)CommBuffer);
    break;
  default:
    break;
  }

  DEBUG((DEBUG_ERROR, "StandaloneMmTestPointSmiHandler Exit\n"));

  return EFI_SUCCESS;
}

/**
  Register StandaloneMm TestPoint handler.
**/
VOID
RegisterStandaloneMmTestPointSmiHandler (
  VOID
  )
{
  EFI_HANDLE                       DispatchHandle;
  EFI_STATUS                       Status;
  STATIC BOOLEAN                   Registered = FALSE;

  if (Registered) {
    return ;
  }
  
  Status = gMmst->MmiHandlerRegister (
                    StandaloneMmTestPointSmiHandler,
                    &gAdapterInfoPlatformTestPointGuid,
                    &DispatchHandle
                    );
  ASSERT_EFI_ERROR (Status);
  Registered = TRUE;
}