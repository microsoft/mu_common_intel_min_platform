/** @file
  Header file for the MM tests shared between Traditional and
  Standalone MM.  Also includes the wrapper functions that are
  used to separate different functionality between Traditional
  and Standalone MM.

  Copyright (c) 2017, Intel Corporation. All rights reserved.<BR>
  Copyright (c) Microsoft Corporation.
  SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#ifndef _MM_TEST_POINT_H_
#define _MM_TEST_POINT_H_

#include <PiMm.h>
#include <Library/BaseLib.h>
#include <Library/BaseMemoryLib.h>
#include <Library/MemoryAllocationLib.h>
#include <Library/MmServicesTableLib.h>
#include <Library/DebugLib.h>
#include <Library/TestPointLib.h>

#include <Protocol/AdapterInformation.h>

#define TEST_POINT_AIP_PRIVATE_SIGNATURE  SIGNATURE_32('T', 'S', 'P', 'T')

typedef struct {
  UINT32                            Signature;
  EFI_ADAPTER_INFORMATION_PROTOCOL  Aip;
  VOID                              *TestPoint;
  UINTN                             TestPointSize;
  UINTN                             TestPointMaxSize;
} TEST_POINT_AIP_PRIVATE_DATA;

#define TEST_POINT_AIP_PRIVATE_DATA_FROM_THIS(a) \
  CR (a, \
      TEST_POINT_AIP_PRIVATE_DATA, \
      Aip, \
      TEST_POINT_AIP_PRIVATE_SIGNATURE \
      )

extern EFI_ADAPTER_INFORMATION_PROTOCOL mMmAdapterInformationProtocol;

/**
  Return if input TestPoint data is valid.

  @param TestPointData  TestPoint data
  @param TestPointSize  TestPoint size

  @retval TRUE  TestPoint data is valid.
  @retval FALSE TestPoint data is not valid.
**/
BOOLEAN
InternalTestPointIsValidTable (
  IN VOID                     *TestPointData,
  IN UINTN                    TestPointSize
  );

/**
  Register MM TestPoint handler.
**/
VOID
RegisterMmTestPointMmiHandler (
  VOID
  );

/**
  This function check if the buffer is valid per processor architecture and not overlap with SMRAM.

  @param Buffer  The buffer start address to be checked.
  @param Length  The buffer length to be checked.

  @retval TRUE  This buffer is valid per processor architecture and not overlap with SMRAM.
  @retval FALSE This buffer is not valid per processor architecture or overlap with SMRAM.
**/
BOOLEAN
EFIAPI
IsBufferOutsideMmValid (
  IN EFI_PHYSICAL_ADDRESS  Buffer,
  IN UINT64                Length
  );

/**
  This function check if the buffer is valid per processor architecture and not overlap with SMRAM.
  A separate function exists because Standalone MM compares the comm buffer using a different function
  thus requiring two validation functions for the shared files.

  @param Buffer  The buffer start address to be checked.
  @param Length  The buffer length to be checked.

  @retval TRUE  This buffer is valid per processor architecture and not overlap with SMRAM.
  @retval FALSE This buffer is not valid per processor architecture or overlap with SMRAM.
**/
BOOLEAN
EFIAPI
IsCommBufferOutsideMmValid (
  IN EFI_PHYSICAL_ADDRESS  Buffer,
  IN UINT64                Length
  );

#endif
