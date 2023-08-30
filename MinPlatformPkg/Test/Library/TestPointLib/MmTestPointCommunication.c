/** @file
  This file tests the comm buffer for both Traditional
  and Standalone MM.

  Copyright (c) 2017, Intel Corporation. All rights reserved.<BR>
  Copyright (c) Microsoft Corporation.
  SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#include "MmTestPoint.h"

EFI_STATUS
GetAllMmTestPointData (
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
  MM test point MMI handler to get info.

  @param MmiHandlerTestPointParameterGetInfo The parameter of MM test point MMI handler get info.

**/
VOID
MmTestPointMmiHandlerGetInfo (
  IN MMI_HANDLER_TEST_POINT_PARAMETER_GET_INFO   *MmiHandlerTestPointParameterGetInfo
  )
{
  UINTN       DataSize;
  EFI_STATUS  Status;
  
  DataSize = 0;
  Status = GetAllMmTestPointData (&DataSize, NULL);
  if (Status == EFI_BUFFER_TOO_SMALL) {
    MmiHandlerTestPointParameterGetInfo->DataSize = DataSize;
    MmiHandlerTestPointParameterGetInfo->Header.ReturnStatus = 0;
  } else {
    MmiHandlerTestPointParameterGetInfo->DataSize = 0;
    MmiHandlerTestPointParameterGetInfo->Header.ReturnStatus = (UINT64)(INT64)(INTN)EFI_NOT_FOUND;
  }
}

/**
  Copy MM Test Point data.

  @param DataBuffer  The buffer to hold MM Test Point data.
  @param DataSize    On input, data buffer size.
                     On output, actual data buffer size copied.
  @param DataOffset  On input, data buffer offset to copy.
                     On output, next time data buffer offset to copy.

**/
VOID
MmiHandlerTestPointCopyData (
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
  MM test point MMI handler to get data by offset.

  @param MmiHandlerTestPointParameterGetDataByOffset   The parameter of MM test point MMI handler get data by offset.

**/
VOID
MmTestPointMmiHandlerGetDataByOffset (
  IN MMI_HANDLER_TEST_POINT_PARAMETER_GET_DATA_BY_OFFSET     *MmiHandlerTestPointParameterGetDataByOffset
  )
{
  MMI_HANDLER_TEST_POINT_PARAMETER_GET_DATA_BY_OFFSET    MmiHandlerTestPointGetDataByOffset;
  VOID                                                   *Data;
  UINTN                                                  DataSize;
  EFI_STATUS                                             Status;

  Data = NULL;

  CopyMem (
    &MmiHandlerTestPointGetDataByOffset,
    MmiHandlerTestPointParameterGetDataByOffset,
    MmiHandlerTestPointParameterGetDataByOffset->DataSize
    );

  DEBUG((DEBUG_ERROR, "Struct Buffer Address: %x\n", (UINTN)MmiHandlerTestPointParameterGetDataByOffset));
  DEBUG((DEBUG_ERROR, "Struct Data Buffer Address: %x\n", (UINTN)(MmiHandlerTestPointParameterGetDataByOffset->Data)));
  DEBUG((DEBUG_ERROR, "STRUCTSIZE: %x\n", sizeof(MMI_HANDLER_TEST_POINT_PARAMETER_GET_DATA_BY_OFFSET)));

  //
  // Sanity check
  //
  /*if (!IsBufferOutsideMmValid((UINTN)&MmiHandlerTestPointParameterGetDataByOffset->Data[0], (UINTN)*Size)) {
    DEBUG((DEBUG_ERROR, "MmTestPointMmiHandlerGetDataByOffset: MmTestPoint get data in SMRAM or overflow!\n"));
    MmiHandlerTestPointParameterGetDataByOffset->ReturnStatus = (UINT64)(INT64)(INTN)EFI_ACCESS_DENIED;
    goto Done;
  }*/
  
  DataSize = 0;
  Status = GetAllMmTestPointData (&DataSize, NULL);
  if (Status != EFI_BUFFER_TOO_SMALL) {
    MmiHandlerTestPointParameterGetDataByOffset->Header.ReturnStatus = (UINT64)(INT64)(INTN)EFI_NOT_FOUND;
    goto Done;
  }
  Data = AllocatePool (DataSize);
  if (Data == NULL) {
    MmiHandlerTestPointParameterGetDataByOffset->Header.ReturnStatus = (UINT64)(INT64)(INTN)EFI_OUT_OF_RESOURCES;
    goto Done;
  }
  Status = GetAllMmTestPointData (&DataSize, Data);
  if (EFI_ERROR(Status)) {
    MmiHandlerTestPointParameterGetDataByOffset->Header.ReturnStatus = (UINT64)(INT64)(INTN)Status;
    goto Done;
  }

  //
  // The SpeculationBarrier() call here is to ensure the previous range/content
  // checks for the CommBuffer have been completed before calling into
  // MmiHandlerTestPointCopyData().
  //
  SpeculationBarrier ();
  DEBUG((DEBUG_ERROR, "InputSize: %x\n", DataSize));
  /*CopyMem (
    (VOID *)MmiHandlerTestPointGetDataByOffset.Data,
    Data,
    DataSize
    );*/
  /*MmiHandlerTestPointCopyData (
    Data,
    DataSize,
    (VOID *)(UINTN)MmiHandlerTestPointGetDataByOffset.Data,
    &(MmiHandlerTestPointGetDataByOffset.DataSize),
    0
    );*/
  DEBUG((DEBUG_ERROR, "DO WE GET HERE?\n"));
  CopyMem (
    (VOID *)(UINTN)MmiHandlerTestPointParameterGetDataByOffset->Data,
    Data,
    DataSize
    );

  MmiHandlerTestPointParameterGetDataByOffset->Header.ReturnStatus = 0;

Done:
  if (Data != NULL) {
    FreePool (Data);
  }
}

/**
  Dispatch function for a Software MMI handler.

  Caution: This function may receive untrusted input.
  Communicate buffer and buffer size are external input, so this function will do basic validation.

  @param DispatchHandle  The unique handle assigned to this handler by MmiHandlerRegister().
  @param Context         Points to an optional handler context which was specified when the
                         handler was registered.
  @param CommBuffer      A pointer to a collection of data in memory that will
                         be conveyed from a non-MM environment into an MM environment.
  @param CommBufferSize  The size of the CommBuffer.

  @retval Always returns EFI_SUCCESS.
**/
EFI_STATUS
EFIAPI
MmTestPointMmiHandler (
  IN EFI_HANDLE  DispatchHandle,
  IN CONST VOID  *Context         OPTIONAL,
  IN OUT VOID    *CommBuffer      OPTIONAL,
  IN OUT UINTN   *CommBufferSize  OPTIONAL
  )
{
  MMI_HANDLER_TEST_POINT_PARAMETER_HEADER     *MmiHandlerTestPointParameterHeader;
  UINTN                                       TempCommBufferSize;

  DEBUG((DEBUG_INFO, "MmTestPointMmiHandler Enter\n"));

  //
  // If input is invalid, stop processing this MMI
  //
  if (CommBuffer == NULL || CommBufferSize == NULL) {
    return EFI_SUCCESS;
  }

  TempCommBufferSize = *CommBufferSize;

  DEBUG((DEBUG_ERROR, "CommBuffer Real Address: %x\n", (UINTN)CommBuffer));
  
  DEBUG((DEBUG_ERROR, "CommBufferSize: %x, Struct size: %x\n", TempCommBufferSize, sizeof(MMI_HANDLER_TEST_POINT_PARAMETER_GET_DATA_BY_OFFSET)));

  if (TempCommBufferSize < sizeof(MMI_HANDLER_TEST_POINT_PARAMETER_HEADER)) {
    DEBUG((DEBUG_INFO, "MmTestPointMmiHandler: MM communication buffer size invalid!\n"));
    return EFI_SUCCESS;
  }

  if (!IsCommBufferOutsideMmValid((UINTN)CommBuffer, TempCommBufferSize)) {
    DEBUG((DEBUG_INFO, "MmTestPointMmiHandler: MM communication buffer in MMRAM or overflow!\n"));
    return EFI_SUCCESS;
  }

  MmiHandlerTestPointParameterHeader = (MMI_HANDLER_TEST_POINT_PARAMETER_HEADER *)((UINTN)CommBuffer);
  MmiHandlerTestPointParameterHeader->ReturnStatus = (UINT64)-1;

  switch (MmiHandlerTestPointParameterHeader->Command) {
  case MMI_HANDLER_TEST_POINT_COMMAND_GET_INFO:
    DEBUG((DEBUG_INFO, "MmiHandlerTestPointHandlerGetInfo\n"));
    if (TempCommBufferSize != sizeof(MMI_HANDLER_TEST_POINT_PARAMETER_GET_INFO)) {
      DEBUG((DEBUG_INFO, "MmTestPointMmiHandler: MM communication buffer size invalid!\n"));
      return EFI_SUCCESS;
    }
    MmTestPointMmiHandlerGetInfo((MMI_HANDLER_TEST_POINT_PARAMETER_GET_INFO *)(UINTN)CommBuffer);
    break;
  case MMI_HANDLER_TEST_POINT_COMMAND_GET_DATA_BY_OFFSET:
    DEBUG((DEBUG_INFO, "MmiHandlerTestPointHandlerGetDataByOffset\n"));
    /*if (TempCommBufferSize != sizeof(MMI_HANDLER_TEST_POINT_PARAMETER_HEADER)) {
      DEBUG((DEBUG_INFO, "MmTestPointMmiHandler: MM communication buffer size invalid!\n"));
      return EFI_SUCCESS;
    }*/
    MmTestPointMmiHandlerGetDataByOffset((MMI_HANDLER_TEST_POINT_PARAMETER_GET_DATA_BY_OFFSET *)(UINTN)CommBuffer);
    break;
  default:
    break;
  }

  DEBUG((DEBUG_INFO, "MmTestPointMmiHandler Exit\n"));

  return EFI_SUCCESS;
}

/**
  Register MM TestPoint handler.
**/
VOID
RegisterMmTestPointMmiHandler (
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
                    MmTestPointMmiHandler,
                    &gAdapterInfoPlatformTestPointGuid,
                    &DispatchHandle
                    );
  ASSERT_EFI_ERROR (Status);
  Registered = TRUE;
}
