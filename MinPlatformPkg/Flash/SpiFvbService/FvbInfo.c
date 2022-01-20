/**@file
  Defines data structure that is the volume header found.
  These data is intent to decouple FVB driver with FV header.

Copyright (c) 2017, Intel Corporation. All rights reserved.<BR>
Copyright (c) Microsoft Corporation.<BR>
SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#include "SpiFvbServiceCommon.h"

#define FIRMWARE_BLOCK_SIZE         0x10000
#define FVB_MEDIA_BLOCK_SIZE        FIRMWARE_BLOCK_SIZE
typedef struct {
  EFI_PHYSICAL_ADDRESS        BaseAddress;
  EFI_FIRMWARE_VOLUME_HEADER  FvbInfo;
  EFI_FV_BLOCK_MAP_ENTRY      End[1];
} EFI_FVB2_MEDIA_INFO;

// MU_CHANGE - START - TCBZ3478 - Add Dynamic Variable Store and Microcode Support
/**
  Returns FVB media information for NV variable storage.

  @return       FvbMediaInfo          A pointer to an instance of FVB media info produced by this function.
                                      The buffer is allocated internally to this function and it is the caller's
                                      responsibility to free the memory

**/
typedef
EFI_STATUS
(*FVB_MEDIA_INFO_GENERATOR)(
  OUT EFI_FVB2_MEDIA_INFO     *FvbMediaInfo
  );

/**
  Returns FVB media information for NV variable storage.

  @return       FvbMediaInfo          A pointer to an instance of FVB media info produced by this function.
                                      The buffer is allocated internally to this function and it is the caller's
                                      responsibility to free the memory

**/
EFI_STATUS
GenerateNvStorageFvbMediaInfo (
  OUT EFI_FVB2_MEDIA_INFO     *FvbMediaInfo
  )
{
  EFI_STATUS                  Status;
  UINT32                      NvBlockNum;
  UINT64                      TotalNvVariableStorageSize;
  EFI_PHYSICAL_ADDRESS        NvStorageBaseAddress;
  EFI_FIRMWARE_VOLUME_HEADER  FvbInfo = {
                                          {0,},                                   //ZeroVector[16]
                                          EFI_SYSTEM_NV_DATA_FV_GUID,             //FileSystemGuid
                                          0,                                      //FvLength
                                          EFI_FVH_SIGNATURE,                      //Signature
                                          0x0004feff,                             //Attributes
                                          sizeof (EFI_FIRMWARE_VOLUME_HEADER) +   //HeaderLength
                                            sizeof (EFI_FV_BLOCK_MAP_ENTRY),
                                          0,                                      //Checksum
                                          0,                                      //ExtHeaderOffset
                                          {0,},                                   //Reserved[1]
                                          2,                                      //Revision
                                          {                                       //BlockMap[1]
                                            {0,0}
                                          }
                                        };

  if (FvbMediaInfo == NULL) {
    return EFI_INVALID_PARAMETER;
  }

  ZeroMem (FvbMediaInfo, sizeof (*FvbMediaInfo));

  GetVariableFlashInfo (&NvStorageBaseAddress, (UINT32 *)&TotalNvVariableStorageSize);
  if ((NvStorageBaseAddress == 0) || (TotalNvVariableStorageSize == 0)) {
    return EFI_UNSUPPORTED;
  }

  Status = SafeUint64ToUint32 (TotalNvVariableStorageSize / FVB_MEDIA_BLOCK_SIZE, &NvBlockNum);
  ASSERT_EFI_ERROR (Status);
  if (EFI_ERROR (Status)) {
    return EFI_UNSUPPORTED;
  }

  FvbInfo.FvLength = (UINT64)(NvBlockNum * FVB_MEDIA_BLOCK_SIZE);
  FvbInfo.BlockMap[0].NumBlocks = NvBlockNum;
  FvbInfo.BlockMap[0].Length = FVB_MEDIA_BLOCK_SIZE;

  FvbMediaInfo->BaseAddress = NvStorageBaseAddress;
  CopyMem (&FvbMediaInfo->FvbInfo, &FvbInfo, sizeof (FvbInfo));

  return EFI_SUCCESS;
}

FVB_MEDIA_INFO_GENERATOR mFvbMediaInfoGenerators[] = {
  GenerateNvStorageFvbMediaInfo
};
// MU_CHANGE - END - TCBZ3478 - Add Dynamic Variable Store and Microcode Support

EFI_STATUS
GetFvbInfo (
  IN  EFI_PHYSICAL_ADDRESS         FvBaseAddress,
  OUT EFI_FIRMWARE_VOLUME_HEADER   **FvbInfo
  )
{
  // MU_CHANGE - START - TCBZ3478 - Add Dynamic Variable Store and Microcode Support
  EFI_STATUS                  Status;
  EFI_FVB2_MEDIA_INFO         FvbMediaInfo;
  // MU_CHANGE - END - TCBZ3478 - Add Dynamic Variable Store and Microcode Support
  UINTN                       Index;
  EFI_FIRMWARE_VOLUME_HEADER  *FvHeader;

  // MU_CHANGE - START - TCBZ3478 - Add Dynamic Variable Store and Microcode Support
  for (Index = 0; Index < ARRAY_SIZE (mFvbMediaInfoGenerators); Index++) {
    Status = mFvbMediaInfoGenerators[Index](&FvbMediaInfo);
    ASSERT_EFI_ERROR (Status);
    if (!EFI_ERROR (Status) && (FvbMediaInfo.BaseAddress == FvBaseAddress)) {
      FvHeader = &FvbMediaInfo.FvbInfo;
  // MU_CHANGE - END - TCBZ3478 - Add Dynamic Variable Store and Microcode Support
      //
      // Update the checksum value of FV header.
      //
      FvHeader->Checksum = CalculateCheckSum16 ( (UINT16 *) FvHeader, FvHeader->HeaderLength);

      *FvbInfo = FvHeader;

      DEBUG ((DEBUG_INFO, "BaseAddr: 0x%lx \n", FvBaseAddress));
      DEBUG ((DEBUG_INFO, "FvLength: 0x%lx \n", (*FvbInfo)->FvLength));
      DEBUG ((DEBUG_INFO, "HeaderLength: 0x%x \n", (*FvbInfo)->HeaderLength));
      DEBUG ((DEBUG_INFO, "Header Checksum: 0x%X\n", (*FvbInfo)->Checksum));
      DEBUG ((DEBUG_INFO, "FvBlockMap[0].NumBlocks: 0x%x \n", (*FvbInfo)->BlockMap[0].NumBlocks));
      DEBUG ((DEBUG_INFO, "FvBlockMap[0].BlockLength: 0x%x \n", (*FvbInfo)->BlockMap[0].Length));
      DEBUG ((DEBUG_INFO, "FvBlockMap[1].NumBlocks: 0x%x \n", (*FvbInfo)->BlockMap[1].NumBlocks));
      DEBUG ((DEBUG_INFO, "FvBlockMap[1].BlockLength: 0x%x \n\n", (*FvbInfo)->BlockMap[1].Length));

      return EFI_SUCCESS;
    }
  }
  return EFI_NOT_FOUND;
}
