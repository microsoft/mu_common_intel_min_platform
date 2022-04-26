/** @file

Copyright (c) 2017, Intel Corporation. All rights reserved.<BR>
SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#include <PiMm.h>
#include <Library/MmServicesTableLib.h>
#include <Library/TestPointCheckLib.h>
#include <Library/TestPointLib.h>
#include <Library/DebugLib.h>
#include <Library/UefiLib.h>
#include <Library/PrintLib.h>
#include <Library/BaseMemoryLib.h>
#include <Library/MemoryAllocationLib.h>
#include <Library/PeCoffGetEntryPointLib.h>
#include <Guid/MemoryAttributesTable.h>
#include <Guid/PiSmmMemoryAttributesTable.h>
#include <Protocol/LoadedImage.h>

CHAR8 *mMemoryTypeShortName[] = {
  "Reserved  ",
  "LoaderCode",
  "LoaderData",
  "BS_Code   ",
  "BS_Data   ",
  "RT_Code   ",
  "RT_Data   ",
  "Available ",
  "Unusable  ",
  "ACPI_Recl ",
  "ACPI_NVS  ",
  "MMIO      ",
  "MMIO_Port ",
  "PalCode   ",
  "Persistent",
};

STATIC CHAR8 mUnknownStr[11];

VOID
TestPointDumpMemoryAttributesTable (
  IN EFI_MEMORY_ATTRIBUTES_TABLE                     *MemoryAttributesTable
  );

EFI_STATUS
TestPointCheckImageMemoryAttribute (
  IN EFI_MEMORY_ATTRIBUTES_TABLE     *MemoryAttributesTable,
  IN EFI_PHYSICAL_ADDRESS            ImageBase,
  IN UINT64                          ImageSize,
  IN BOOLEAN                         IsFromSmm
  );

CHAR8 *
ShortNameOfMemoryType(
  IN UINT32 Type
  )
{
  if (Type < sizeof(mMemoryTypeShortName) / sizeof(mMemoryTypeShortName[0])) {
    return mMemoryTypeShortName[Type];
  } else {
    AsciiSPrint(mUnknownStr, sizeof(mUnknownStr), "[%08x]", Type);
    return mUnknownStr;
  }
}

EFI_STATUS
TestPointCheckMemoryAttribute (
  IN EFI_MEMORY_ATTRIBUTES_TABLE     *MemoryAttributesTable,
  IN EFI_PHYSICAL_ADDRESS            Base,
  IN UINT64                          Size,
  IN BOOLEAN                         IsCode,
  IN BOOLEAN                         IsFromSmm
  )
{
  UINTN                 Index;
  EFI_MEMORY_DESCRIPTOR *Entry;
  
  DEBUG ((DEBUG_ERROR, "Attribute Checking 0x%lx - 0x%lx\n", Base, Size));
  Entry = (EFI_MEMORY_DESCRIPTOR *)(MemoryAttributesTable + 1);
  for (Index = 0; Index < MemoryAttributesTable->NumberOfEntries; Index++) {
    if (Base >= Entry->PhysicalStart && Base+Size <= Entry->PhysicalStart+MultU64x64 (SIZE_4KB,Entry->NumberOfPages)) {
      if (IsFromSmm) {
        if (IsCode) {
          if (Entry->Type != EfiRuntimeServicesCode) {
            DEBUG ((DEBUG_ERROR, "Invalid Entry->Type %d\n", Entry->Type));
            return EFI_INVALID_PARAMETER;
          }
          if ((Entry->Attribute & (EFI_MEMORY_RO | EFI_MEMORY_XP)) != EFI_MEMORY_RO) {
            DEBUG ((DEBUG_ERROR, "Invalid Code Entry->Attribute 0x%lx\n", Entry->Attribute));
            return EFI_INVALID_PARAMETER;
          }
        } else {
          if (Entry->Type != EfiRuntimeServicesData) {
            DEBUG ((DEBUG_ERROR, "Invalid Entry->Type %d\n", Entry->Type));
            return EFI_INVALID_PARAMETER;
          }
          if ((Entry->Attribute & (EFI_MEMORY_RO | EFI_MEMORY_XP)) != EFI_MEMORY_XP) {
            DEBUG ((DEBUG_ERROR, "Invalid Data Entry->Attribute 0x%lx\n", Entry->Attribute));
            return EFI_INVALID_PARAMETER;
          }
        }
      } else {
        if (Entry->Type != EfiRuntimeServicesCode) {
          DEBUG ((DEBUG_ERROR, "Invalid Entry->Type %d\n", Entry->Type));
          return EFI_INVALID_PARAMETER;
        }
        if (IsCode) {
          if ((Entry->Attribute & (EFI_MEMORY_RO | EFI_MEMORY_XP)) != EFI_MEMORY_RO) {
            DEBUG ((DEBUG_ERROR, "Invalid Code Entry->Attribute 0x%lx\n", Entry->Attribute));
            return EFI_INVALID_PARAMETER;
          }
        } else {
          if ((Entry->Attribute & (EFI_MEMORY_RO | EFI_MEMORY_XP)) != EFI_MEMORY_XP) {
            DEBUG ((DEBUG_ERROR, "Invalid Data Entry->Attribute 0x%lx\n", Entry->Attribute));
            return EFI_INVALID_PARAMETER;
          }
        }
      }
    }
  }

  return EFI_SUCCESS;
}

EFI_STATUS
TestPointCheckImageMemoryAttribute (
  IN EFI_MEMORY_ATTRIBUTES_TABLE     *MemoryAttributesTable,
  IN EFI_PHYSICAL_ADDRESS            ImageBase,
  IN UINT64                          ImageSize,
  IN BOOLEAN                         IsFromSmm
  )
{
  EFI_STATUS                           Status;
  EFI_STATUS                           ReturnStatus;
  VOID                                 *ImageAddress;
  EFI_IMAGE_DOS_HEADER                 *DosHdr;
  UINT32                               PeCoffHeaderOffset;
  UINT32                               SectionAlignment;
  EFI_IMAGE_SECTION_HEADER             *Section;
  EFI_IMAGE_OPTIONAL_HEADER_PTR_UNION  Hdr;
  UINT8                                *Name;
  UINTN                                Index;
  CHAR8                                *PdbPointer;

  ReturnStatus = EFI_SUCCESS;
  //
  // Check whole region
  //
  ImageAddress = (VOID *)(UINTN)ImageBase;

  PdbPointer = PeCoffLoaderGetPdbPointer (ImageAddress);
  if (PdbPointer != NULL) {
    DEBUG ((EFI_D_INFO, "  Image - %a\n", PdbPointer));
  }
  DEBUG ((DEBUG_ERROR, "THIS IS A TEST #1\n"));
  //
  // Check PE/COFF image
  //
  DosHdr = (EFI_IMAGE_DOS_HEADER *) (UINTN) ImageAddress;
  PeCoffHeaderOffset = 0;
  if (DosHdr->e_magic == EFI_IMAGE_DOS_SIGNATURE) {
    PeCoffHeaderOffset = DosHdr->e_lfanew;
  }

  Hdr.Pe32 = (EFI_IMAGE_NT_HEADERS32 *)((UINT8 *) (UINTN) ImageAddress + PeCoffHeaderOffset);
  if (Hdr.Pe32->Signature != EFI_IMAGE_NT_SIGNATURE) {
    DEBUG ((EFI_D_INFO, "Hdr.Pe32->Signature invalid - 0x%x\n", Hdr.Pe32->Signature));
    return EFI_INVALID_PARAMETER;
  }
  DEBUG ((DEBUG_ERROR, "THIS IS A TEST #2\n"));
  //
  // Measuring PE/COFF Image Header;
  // But CheckSum field and SECURITY data directory (certificate) are excluded
  //
  if (Hdr.Pe32->FileHeader.Machine == IMAGE_FILE_MACHINE_IA64 && Hdr.Pe32->OptionalHeader.Magic == EFI_IMAGE_NT_OPTIONAL_HDR32_MAGIC) {
    //
    // NOTE: Some versions of Linux ELILO for Itanium have an incorrect magic value 
    //       in the PE/COFF Header.
    //
    SectionAlignment  = Hdr.Pe32->OptionalHeader.SectionAlignment;
  } else {
    //
    // Get the section alignment value from the PE/COFF Optional Header
    //
    SectionAlignment  = Hdr.Pe32Plus->OptionalHeader.SectionAlignment;
  }

  if ((SectionAlignment & (RUNTIME_PAGE_ALLOCATION_GRANULARITY - 1)) != 0) {
    DEBUG ((EFI_D_INFO, "!!!!!!!!  RecordImageMemoryMap - Section Alignment(0x%x) is not %dK  !!!!!!!!\n", SectionAlignment, RUNTIME_PAGE_ALLOCATION_GRANULARITY >> 10));
    PdbPointer = PeCoffLoaderGetPdbPointer ((VOID*) (UINTN) ImageAddress);
    if (PdbPointer != NULL) {
      DEBUG ((EFI_D_INFO, "!!!!!!!!  Image - %a  !!!!!!!!\n", PdbPointer));
    }
    return EFI_INVALID_PARAMETER;
  }
  DEBUG ((DEBUG_ERROR, "THIS IS A TEST #3\n"));
  Section = (EFI_IMAGE_SECTION_HEADER *) (
               (UINT8 *) (UINTN) ImageAddress +
               PeCoffHeaderOffset +
               sizeof(UINT32) +
               sizeof(EFI_IMAGE_FILE_HEADER) +
               Hdr.Pe32->FileHeader.SizeOfOptionalHeader
               );

  Status = TestPointCheckMemoryAttribute (
             MemoryAttributesTable,
             (UINTN)ImageAddress,
             (UINTN)&Section[Hdr.Pe32->FileHeader.NumberOfSections] - (UINTN)ImageAddress,
             FALSE,
             IsFromSmm
             );
  DEBUG ((DEBUG_ERROR, "THIS IS A TEST #4\n"));
  if (EFI_ERROR(Status)) {
    DEBUG ((DEBUG_ERROR, "THIS IS A TEST #5\n"));
    ReturnStatus = Status;
  }

  for (Index = 0; Index < Hdr.Pe32->FileHeader.NumberOfSections; Index++) {
    Name = Section[Index].Name;
    DEBUG ((
      EFI_D_INFO,
      "  Section - '%c%c%c%c%c%c%c%c'\n",
      Name[0],
      Name[1],
      Name[2],
      Name[3],
      Name[4],
      Name[5],
      Name[6],
      Name[7]
      ));
      
    DEBUG ((EFI_D_INFO, "    VirtualSize          - 0x%08x\n", Section[Index].Misc.VirtualSize));
    DEBUG ((EFI_D_INFO, "    VirtualAddress       - 0x%08x\n", Section[Index].VirtualAddress));
    DEBUG ((EFI_D_INFO, "    SizeOfRawData        - 0x%08x\n", Section[Index].SizeOfRawData));
    DEBUG ((EFI_D_INFO, "    PointerToRawData     - 0x%08x\n", Section[Index].PointerToRawData));
    DEBUG ((EFI_D_INFO, "    PointerToRelocations - 0x%08x\n", Section[Index].PointerToRelocations));
    DEBUG ((EFI_D_INFO, "    PointerToLinenumbers - 0x%08x\n", Section[Index].PointerToLinenumbers));
    DEBUG ((EFI_D_INFO, "    NumberOfRelocations  - 0x%08x\n", Section[Index].NumberOfRelocations));
    DEBUG ((EFI_D_INFO, "    NumberOfLinenumbers  - 0x%08x\n", Section[Index].NumberOfLinenumbers));
    DEBUG ((EFI_D_INFO, "    Characteristics      - 0x%08x\n", Section[Index].Characteristics));
    if ((Section[Index].Characteristics & EFI_IMAGE_SCN_CNT_CODE) != 0) {
      //
      // Check code section
      //
      Status = TestPointCheckMemoryAttribute (
                 MemoryAttributesTable,
                 (UINTN)ImageAddress + Section[Index].VirtualAddress,
                 Section[Index].SizeOfRawData,
                 TRUE,
                 IsFromSmm
                 );
    } else {
      //
      // Check data section
      //
      Status = TestPointCheckMemoryAttribute (
                 MemoryAttributesTable,
                 (UINTN)ImageAddress + Section[Index].VirtualAddress,
                 Section[Index].SizeOfRawData,
                 FALSE,
                 IsFromSmm
                 );
    }
    if (EFI_ERROR(Status)) {
      DEBUG ((DEBUG_ERROR, "THIS IS A TEST #6\n"));
      ReturnStatus = Status;
    }
  }

  return ReturnStatus;
}

VOID
TestPointDumpMemoryAttributesTable (
  IN EFI_MEMORY_ATTRIBUTES_TABLE                     *MemoryAttributesTable
  )
{
  UINTN                 Index;
  EFI_MEMORY_DESCRIPTOR *Entry;
  UINT64                Pages[EfiMaxMemoryType];

  ZeroMem (Pages, sizeof(Pages));

  DEBUG ((DEBUG_INFO, "MemoryAttributesTable:"));
  DEBUG ((DEBUG_INFO, " Version=0x%x", MemoryAttributesTable->Version));
  DEBUG ((DEBUG_INFO, " Count=0x%x", MemoryAttributesTable->NumberOfEntries));
  DEBUG ((DEBUG_INFO, " DescriptorSize=0x%x\n", MemoryAttributesTable->DescriptorSize));
  Entry = (EFI_MEMORY_DESCRIPTOR *)(MemoryAttributesTable + 1);
  DEBUG ((DEBUG_INFO, "Type       Start            End              # Pages          Attributes\n"));
  for (Index = 0; Index < MemoryAttributesTable->NumberOfEntries; Index++) {
    DEBUG ((DEBUG_INFO, ShortNameOfMemoryType(Entry->Type)));
    DEBUG ((DEBUG_INFO, " %016LX-%016LX %016LX %016LX\n",
      Entry->PhysicalStart,
      Entry->PhysicalStart+MultU64x64 (SIZE_4KB,Entry->NumberOfPages) - 1,
      Entry->NumberOfPages,
      Entry->Attribute
      ));
    if (Entry->Type < EfiMaxMemoryType) {
      Pages[Entry->Type] += Entry->NumberOfPages;
    }
    Entry = NEXT_MEMORY_DESCRIPTOR (Entry, MemoryAttributesTable->DescriptorSize);
  }
  
  DEBUG ((DEBUG_INFO, "\n"));
  DEBUG ((DEBUG_INFO, "  RT_Code   : %14ld Pages (%ld Bytes)\n", Pages[EfiRuntimeServicesCode],     MultU64x64(SIZE_4KB, Pages[EfiRuntimeServicesCode])));
  DEBUG ((DEBUG_INFO, "  RT_Data   : %14ld Pages (%ld Bytes)\n", Pages[EfiRuntimeServicesData],     MultU64x64(SIZE_4KB, Pages[EfiRuntimeServicesData])));
  DEBUG ((DEBUG_INFO, "              -------------- \n"));
}

EFI_STATUS
TestPointCheckStandaloneMmMemoryAttributesTable (
  IN EFI_MEMORY_ATTRIBUTES_TABLE                     *MemoryAttributesTable
  )
{
  EFI_STATUS                             Status;
  EFI_LOADED_IMAGE_PROTOCOL              *LoadedImage;
  UINTN                                  Index;
  UINTN                                  HandleBufSize;
  EFI_HANDLE                             *HandleBuf;
  UINTN                                  HandleCount;
  EFI_STATUS                             ReturnStatus;
  
  ReturnStatus = EFI_SUCCESS;
  DEBUG ((DEBUG_INFO, "==== TestPointDumpStandaloneMmLoadedImage - Enter\n"));
  HandleBuf = NULL;
  HandleBufSize = 0;
  DEBUG ((DEBUG_ERROR, "THIS IS A TEST #6\n"));
  Status = gMmst->MmLocateHandle (
                    ByProtocol,
                    &gEfiLoadedImageProtocolGuid,
                    NULL,
                    &HandleBufSize,
                    HandleBuf
                    );
  if (Status != EFI_BUFFER_TOO_SMALL) {
    goto Done ;
  }
  HandleBuf = AllocateZeroPool (HandleBufSize);
  if (HandleBuf == NULL) {
    goto Done ;
  }
  Status = gMmst->MmLocateHandle (
                    ByProtocol,
                    &gEfiLoadedImageProtocolGuid,
                    NULL,
                    &HandleBufSize,
                    HandleBuf
                    );
  if (EFI_ERROR (Status)) {
    goto Done ;
  }
  HandleCount = HandleBufSize / sizeof(EFI_HANDLE);
  
  DEBUG ((DEBUG_INFO, "StandaloneMmLoadedImage (%d):\n", HandleCount));
  for (Index = 0; Index < HandleCount; Index++) {
    Status = gMmst->MmHandleProtocol (
                      HandleBuf[Index],
                      &gEfiLoadedImageProtocolGuid,
                      (VOID **)&LoadedImage
                      );
    if (EFI_ERROR(Status)) {
      continue;
    }
    // Failing here
    DEBUG ((DEBUG_ERROR, "THIS IS A TEST #7\n"));
    Status = TestPointCheckImageMemoryAttribute (
               MemoryAttributesTable,
               (EFI_PHYSICAL_ADDRESS)(UINTN)LoadedImage->ImageBase,
               LoadedImage->ImageSize,
               TRUE
               );
    if (EFI_ERROR(Status)) {
      ReturnStatus = Status;
    }
  }

Done:

  if (HandleBuf != NULL) {
    FreePool (HandleBuf);
  }

  return ReturnStatus;
}

/**
  Retrieves a pointer to the system configuration table from the StandaloneMM System Table
  based on a specified GUID.

  @param[in]   TableGuid       The pointer to table's GUID type.
  @param[out]  Table           The pointer to the table associated with TableGuid in the EFI System Table.

  @retval EFI_SUCCESS     A configuration table matching TableGuid was found.
  @retval EFI_NOT_FOUND   A configuration table matching TableGuid could not be found.

**/
EFI_STATUS
EFIAPI
StandaloneMmGetSystemConfigurationTable (
  IN  EFI_GUID  *TableGuid,
  OUT VOID      **Table
  )
{
  UINTN             Index;

  ASSERT (TableGuid != NULL);
  ASSERT (Table != NULL);

  *Table = NULL;
  DEBUG ((DEBUG_ERROR, "THIS IS A TEST ME #1\n"));
  DEBUG ((DEBUG_ERROR, "The number of table entries is : %lx\n", gMmst->NumberOfTableEntries));
  for (Index = 0; Index < gMmst->NumberOfTableEntries; Index++) {
    DEBUG ((DEBUG_ERROR, "THIS IS A TEST ME #2\n"));
    if (CompareGuid (TableGuid, &(gMmst->MmConfigurationTable[Index].VendorGuid))) {
      DEBUG ((DEBUG_ERROR, "THIS IS A TEST ME #3\n"));
      *Table = gMmst->MmConfigurationTable[Index].VendorTable;
      return EFI_SUCCESS;
    }
  }
  DEBUG ((DEBUG_ERROR, "THIS IS A TEST ME #4\n"));
  return EFI_NOT_FOUND;
}

EFI_STATUS
TestPointCheckStandaloneMmMemAttribute (
  VOID
  )
{
  EFI_STATUS  Status;
  VOID        *MemoryAttributesTable;
  
  DEBUG ((DEBUG_INFO, "==== TestPointCheckStandaloneMmMemAttribute - Enter\n"));
  Status = StandaloneMmGetSystemConfigurationTable (&gEdkiiPiSmmMemoryAttributesTableGuid, (VOID **)&MemoryAttributesTable);
  if (!EFI_ERROR (Status)) {
    // Look for standalone MM alternative
    //TestPointDumpMemoryAttributesTable(MemoryAttributesTable);
    // This is failing.  Look into why
    Status = TestPointCheckStandaloneMmMemoryAttributesTable(MemoryAttributesTable);
  }

  if (EFI_ERROR (Status)) {
    TestPointLibAppendErrorString (
      PLATFORM_TEST_POINT_ROLE_PLATFORM_IBV,
      NULL,
      TEST_POINT_BYTE6_SMM_READY_TO_LOCK_SMM_MEMORY_ATTRIBUTE_TABLE_FUNCTIONAL_ERROR_CODE \
        TEST_POINT_SMM_READY_TO_LOCK \
        TEST_POINT_BYTE6_SMM_READY_TO_LOCK_SMM_MEMORY_ATTRIBUTE_TABLE_FUNCTIONAL_ERROR_STRING
      );
  }
  DEBUG ((DEBUG_INFO, "==== TestPointCheckStandaloneMmMemAttribute - Exit\n"));

  return Status;
}
