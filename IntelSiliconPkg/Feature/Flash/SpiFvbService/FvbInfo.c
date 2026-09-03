/**@file
  Defines data structure that is the volume header found.
  These data is intent to decouple FVB driver with FV header.

  Copyright (c) 2017, Intel Corporation. All rights reserved.<BR>
  Copyright (c) Microsoft Corporation.<BR>
  SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#include "SpiFvbServiceCommon.h"

#define FIRMWARE_BLOCK_SIZE   SIZE_64KB
#define FVB_MEDIA_BLOCK_SIZE  FIRMWARE_BLOCK_SIZE

typedef struct {
  EFI_PHYSICAL_ADDRESS          BaseAddress;
  EFI_FIRMWARE_VOLUME_HEADER    FvbInfo;
  EFI_FV_BLOCK_MAP_ENTRY        End[1];
} EFI_FVB2_MEDIA_INFO;

/**
  Returns FVB media information for a firmware volume.

  @return       FvbMediaInfo          A pointer to an instance of FVB media info produced by this function.
                                      The buffer is allocated internally to this function and it is the caller's
                                      responsibility to free the memory

**/
typedef
EFI_STATUS
(*FVB_MEDIA_INFO_GENERATOR)(
  OUT EFI_FVB2_MEDIA_INFO  *FvbMediaInfo
  );

/**
  Returns FVB media information for NV variable storage.

  @param[out]   FvbMediaInfo          A pointer to an instance of FVB media info produced by this function.

  @retval       EFI_SUCCESS           A structure was successfully written to the FvbMediaInfo buffer.
  @retval       EFI_INVALID_PARAMETER The FvbMediaInfo parameter is NULL.
  @retval       EFI_UNSUPPORTED       An error occurred retrieving variable FV information.
  @retval       EFI_BAD_BUFFER_SIZE   An overflow or underflow of the FV buffer occurred with the information found.

**/
EFI_STATUS
GenerateNvStorageFvbMediaInfo (
  OUT EFI_FVB2_MEDIA_INFO  *FvbMediaInfo
  )
{
  EFI_STATUS                  Status;
  UINT32                      NvBlockNum;
  UINT32                      TotalNvVariableStorageSize;
  EFI_PHYSICAL_ADDRESS        NvStorageBaseAddress;
  EFI_FIRMWARE_VOLUME_HEADER  FvbInfo;

  if (FvbMediaInfo == NULL) {
    return EFI_INVALID_PARAMETER;
  }

  ZeroMem (&FvbInfo, sizeof (FvbInfo));
  CopyGuid (&FvbInfo.FileSystemGuid, &gEfiSystemNvDataFvGuid);
  FvbInfo.Signature    = EFI_FVH_SIGNATURE;
  FvbInfo.Attributes   = 0x0004feff;
  FvbInfo.HeaderLength = sizeof (EFI_FIRMWARE_VOLUME_HEADER) + sizeof (EFI_FV_BLOCK_MAP_ENTRY);
  FvbInfo.Revision     = 2;

  ZeroMem (FvbMediaInfo, sizeof (*FvbMediaInfo));

  GetVariableFvInfo (&NvStorageBaseAddress, &TotalNvVariableStorageSize);
  if ((NvStorageBaseAddress == 0) || (TotalNvVariableStorageSize == 0)) {
    return EFI_UNSUPPORTED;
  }

  NvBlockNum = TotalNvVariableStorageSize / FVB_MEDIA_BLOCK_SIZE;

  Status = SafeUint64Mult ((UINT64)NvBlockNum, FVB_MEDIA_BLOCK_SIZE, &FvbInfo.FvLength);
  if (EFI_ERROR (Status)) {
    return EFI_BAD_BUFFER_SIZE;
  }

  FvbInfo.BlockMap[0].NumBlocks = NvBlockNum;
  FvbInfo.BlockMap[0].Length    = FVB_MEDIA_BLOCK_SIZE;

  FvbMediaInfo->BaseAddress = NvStorageBaseAddress;
  CopyMem (&FvbMediaInfo->FvbInfo, &FvbInfo, sizeof (FvbInfo));

  return EFI_SUCCESS;
}

FVB_MEDIA_INFO_GENERATOR  mFvbMediaInfoGenerators[] = {
  GenerateNvStorageFvbMediaInfo
};

/**
  Returns an empty firmware volume for the firmware volume at the given base address.

  @param[in]    FvBaseAddress       The base address of the firmware volume requested.
  @param[out]   FvbInfo             A pointer that will be set to a buffer for the firmware volume header
                                    at the given base address. The buffer is a pool allocation made in this function.

  @retval     EFI_SUCCESS           The firmware volume was returned successfully.
  @retval     EFI_INVALID_PARAMETER The FvbInfo pointer argument is NULL.
  @retval     EFI_NOT_FOUND         The firmware volume was not found for the given base address.
  @retval     EFI_OUT_OF_RESOURCES  Insufficient memory to allocate a buffer to the hold the firmware volume.

**/
EFI_STATUS
GetGeneratedFvByAddress (
  IN  EFI_PHYSICAL_ADDRESS        FvBaseAddress,
  OUT EFI_FIRMWARE_VOLUME_HEADER  **FvbInfo
  )
{
  EFI_STATUS                  Status;
  EFI_FVB2_MEDIA_INFO         FvbMediaInfo;
  UINTN                       Index;
  EFI_FIRMWARE_VOLUME_HEADER  *FvHeader;

  if (FvbInfo == NULL) {
    return EFI_INVALID_PARAMETER;
  }

  for (Index = 0; Index < ARRAY_SIZE (mFvbMediaInfoGenerators); Index++) {
    Status = mFvbMediaInfoGenerators[Index](&FvbMediaInfo);
    ASSERT_EFI_ERROR (Status);
    if (!EFI_ERROR (Status) && (FvbMediaInfo.BaseAddress == FvBaseAddress)) {
      FvHeader = AllocateCopyPool (FvbMediaInfo.FvbInfo.HeaderLength, &FvbMediaInfo.FvbInfo);
      if (FvHeader == NULL) {
        ASSERT (FvHeader != NULL);
        return EFI_OUT_OF_RESOURCES;
      }

      //
      // Update the checksum value of FV header.
      //
      FvHeader->Checksum = CalculateCheckSum16 ((UINT16 *)FvHeader, FvHeader->HeaderLength);

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
