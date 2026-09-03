/** @file
Library interface to retrieve structured records from Intel's FIT
Reference:
https://edc.intel.com/content/www/us/en/design/products-and-solutions/software-and-services/firmware-and-bios/firmware-interface-table/1.2/

Copyright (c) Microsoft Corporation.
SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#include <Uefi.h>

#include <Library/DebugLib.h>
#include <Library/FitQueryLib.h>

//
// This library was designed with advanced unit-test features.
// This define handles the configuration.
#if defined (INTERNAL_UNIT_TEST) || defined (EDKII_UNIT_TEST_FRAMEWORK_ENABLED)
  #undef STATIC
#define STATIC    // Nothing...
#endif

#define     MIN_FIT_ADDRESS  (UINT32)0xFF000000            // This is just a sanity check to make sure the FIT is in top 16MB

/**
  Internal helper that uses the FIT_POINTER_ADDRESS to locate the base
  of the FIT.

  @retval     32-bit system address of the FIT base.

**/
STATIC
CONST FIRMWARE_INTERFACE_TABLE_ENTRY *
InternalGetFitBase (
  VOID
  )
{
  UINT32  *FitBase;

  FitBase = (UINT32 *)(UINTN)FIT_POINTER_ADDRESS;
  return (FIRMWARE_INTERFACE_TABLE_ENTRY *)(UINTN)*FitBase;
}

/**
  This internal helper does all the heavy lifting for GetFitRecord(), but in a testable way.

  @param[in]  FitBase       A pointer to the FIT.
  @param[in]  RecordType    Same as GetFitRecord()
  @param[in]  RecordIndex   Same as GetFitRecord()
  @param[out] Result        Same as GetFitRecord()

  @retval     Others  Same as GetFitRecord()

**/
STATIC
EFI_STATUS
InternalGetFitRecord (
  IN CONST FIRMWARE_INTERFACE_TABLE_ENTRY  *FitBase,
  IN UINT8                                 RecordType,
  IN UINT16                                RecordIndex,
  OUT FIT_QUERY_RESULT                     *Result
  )
{
  EFI_STATUS  Status;
  UINTN       Index;
  UINTN       Count;

  // Check some quick parameters.
  ASSERT (FitBase != NULL);
  if ((Result == NULL) || (FitBase == NULL)) {
    return EFI_INVALID_PARAMETER;
  }

  // Check to make sure the requested record type is valid.
  if ((RecordType < FIT_TYPE_PLAT_MIN) || (RecordType > FIT_TYPE_PLAT_MAX)) {
    switch (RecordType) {
      case FIT_TYPE_00_HEADER:
      case FIT_TYPE_01_MICROCODE:
      case FIT_TYPE_02_STARTUP_ACM:
      case FIT_TYPE_07_BIOS_STARTUP_MODULE:
      case FIT_TYPE_08_TPM_POLICY:
      case FIT_TYPE_09_BIOS_POLICY:
      case FIT_TYPE_0A_TXT_POLICY:
      case FIT_TYPE_0B_KEY_MANIFEST:
      case FIT_TYPE_0C_BOOT_POLICY_MANIFEST:
      case FIT_TYPE_10_CSE_SECURE_BOOT:
      case FIT_TYPE_2D_TXTSX_POLICY:      // cspell:disable-line
      case FIT_TYPE_2F_JMP_DEBUG_POLICY:
        break;
      default:
        return EFI_INVALID_PARAMETER;
    }
  }

  // Now that we're sure we have a good request, let's check the FIT.
  if (FitBase->Address != FIT_TYPE_00_SIGNATURE) {
    return EFI_COMPROMISED_DATA;
  }

  // Iterate through the list and find the requested data.
  Index  = 0;
  Count  = GET_SIZE_FROM_FIT_ENTRY (FitBase[Index]);  // For the header entry, the size IS the count.
  Status = EFI_NOT_FOUND;
  for ( ; Index < Count; Index++) {
    if (FitBase[Index].Type == RecordType) {
      if (RecordIndex == 0) {
        Result->BaseAddress = FitBase[Index].Address;
        Result->Size        = GET_SIZE_FROM_FIT_ENTRY (FitBase[Index]);
        Status              = EFI_SUCCESS;
        break;
      } else {
        RecordIndex -= 1;
      }
    }
  }

  return Status;
}

/**
  This helper will walk the FIT and locate a record.

  @param[in]  RecordType    The type identifier of the record.
  @param[in]  RecordIndex   For records that allow multiple entries, this is the entry
                            being requested. 0-based.
  @param[out] Result        Pointer to the FIT_QUERY_RESULT output structure.

  @retval     EFI_SUCCESS             Record was returned.
  @retval     EFI_INVALID_PARAMETER   RecordType does not match a known record.
  @retval     EFI_INVALID_PARAMETER   Return pointer parameter is NULL.
  @retval     EFI_COMPROMISED_DATA    FIT pointer is invalid.
  @retval     EFI_COMPROMISED_DATA    Could not locate the FIT at all.
  @retval     EFI_NOT_FOUND           A matching record could not be found.

**/
EFI_STATUS
EFIAPI
GetFitRecord (
  IN UINT8              RecordType,
  IN UINT16             RecordIndex,
  OUT FIT_QUERY_RESULT  *Result
  )
{
  CONST FIRMWARE_INTERFACE_TABLE_ENTRY  *FitBase;

  FitBase = InternalGetFitBase ();
  if (((UINT32)(UINTN)FitBase < MIN_FIT_ADDRESS) || ((UINTN)FitBase > FIT_POINTER_ADDRESS)) {
    return EFI_COMPROMISED_DATA;
  }

  return InternalGetFitRecord (FitBase, RecordType, RecordIndex, Result);
}
