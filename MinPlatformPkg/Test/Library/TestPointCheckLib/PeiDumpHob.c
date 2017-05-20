/** @file

Copyright (c) 2017, Intel Corporation. All rights reserved.<BR>
This program and the accompanying materials are licensed and made available under
the terms and conditions of the BSD License that accompanies this distribution.
The full text of the license may be found at
http://opensource.org/licenses/bsd-license.php.

THE PROGRAM IS DISTRIBUTED UNDER THE BSD LICENSE ON AN "AS IS" BASIS,
WITHOUT WARRANTIES OR REPRESENTATIONS OF ANY KIND, EITHER EXPRESS OR IMPLIED.

**/

#include <Uefi.h>
#include <PiPei.h>
#include <Library/TestPointCheckLib.h>
#include <Library/TestPointLib.h>
#include <Library/DebugLib.h>
#include <Library/BaseMemoryLib.h>
#include <Library/HobLib.h>
#include <Library/PrintLib.h>
#include <Guid/MemoryAllocationHob.h>

#define MEMORY_ATTRIBUTE_MASK (EFI_RESOURCE_ATTRIBUTE_PRESENT | \
                               EFI_RESOURCE_ATTRIBUTE_INITIALIZED | \
                               EFI_RESOURCE_ATTRIBUTE_TESTED | \
                               EFI_RESOURCE_ATTRIBUTE_16_BIT_IO | \
                               EFI_RESOURCE_ATTRIBUTE_32_BIT_IO | \
                               EFI_RESOURCE_ATTRIBUTE_64_BIT_IO \
                               )

#define TESTED_MEMORY_ATTRIBUTES      (EFI_RESOURCE_ATTRIBUTE_PRESENT | EFI_RESOURCE_ATTRIBUTE_INITIALIZED | EFI_RESOURCE_ATTRIBUTE_TESTED)

#define INITIALIZED_MEMORY_ATTRIBUTES (EFI_RESOURCE_ATTRIBUTE_PRESENT | EFI_RESOURCE_ATTRIBUTE_INITIALIZED)

#define PRESENT_MEMORY_ATTRIBUTES     (EFI_RESOURCE_ATTRIBUTE_PRESENT)

CHAR8 *mMemoryTypeShortName[] = {
  "Reserved",
  "LoaderCode",
  "LoaderData",
  "BS_Code",
  "BS_Data",
  "RT_Code",
  "RT_Data",
  "Available",
  "Unusable",
  "ACPI_Recl",
  "ACPI_NVS",
  "MMIO",
  "MMIO_Port",
  "PalCode",
  "Persistent",
};

CHAR8 *mResourceTypeShortName[] = {
  "Mem",
  "MMIO",
  "I/O",
  "FD",
  "MM Port I/O",
  "Reserved Mem",
  "Reserved I/O",
};

CHAR8 mUnknownStr[11];

CHAR8 *
ShortNameOfMemoryType (
  IN UINT32 Type
  )
{
  if (Type < sizeof(mMemoryTypeShortName) / sizeof(mMemoryTypeShortName[0])) {
    return mMemoryTypeShortName[Type];
  } else {
    AsciiSPrint(mUnknownStr, sizeof(mUnknownStr), "%08x", Type);
    return mUnknownStr;
  }
}

CHAR8 *
ShortNameOfResourceType (
  IN UINT32 Type
  )
{
  if (Type < sizeof(mResourceTypeShortName) / sizeof(mResourceTypeShortName[0])) {
    return mResourceTypeShortName[Type];
  } else {
    AsciiSPrint(mUnknownStr, sizeof(mUnknownStr), "%08x", Type);
    return mUnknownStr;
  }
}

EFI_STATUS
DumpPhitHob (
  IN VOID                        *HobList
  )
{
  EFI_HOB_HANDOFF_INFO_TABLE  *PhitHob;
  
  PhitHob = HobList;
  ASSERT(GET_HOB_TYPE(HobList) == EFI_HOB_TYPE_HANDOFF);
  DEBUG ((DEBUG_INFO, "PHIT HOB\n"));
  DEBUG ((DEBUG_INFO, "  PhitHob             - 0x%x\n", PhitHob));
  DEBUG ((DEBUG_INFO, "  BootMode            - 0x%x\n", PhitHob->BootMode));
  DEBUG ((DEBUG_INFO, "  EfiMemoryTop        - 0x%016lx\n", PhitHob->EfiMemoryTop));
  DEBUG ((DEBUG_INFO, "  EfiMemoryBottom     - 0x%016lx\n", PhitHob->EfiMemoryBottom));
  DEBUG ((DEBUG_INFO, "  EfiFreeMemoryTop    - 0x%016lx\n", PhitHob->EfiFreeMemoryTop));
  DEBUG ((DEBUG_INFO, "  EfiFreeMemoryBottom - 0x%016lx\n", PhitHob->EfiFreeMemoryBottom));
  DEBUG ((DEBUG_INFO, "  EfiEndOfHobList     - 0x%lx\n", PhitHob->EfiEndOfHobList));

  return EFI_SUCCESS;
}

EFI_STATUS
DumpCpuHob (
  IN VOID                        *HobList
  )
{
  EFI_PEI_HOB_POINTERS        Hob;
  EFI_HOB_CPU                 *CpuHob;

  DEBUG ((DEBUG_INFO, "CPU HOBs\n"));
  for (Hob.Raw = HobList; !END_OF_HOB_LIST(Hob); Hob.Raw = GET_NEXT_HOB(Hob)) {
    if (GET_HOB_TYPE(Hob) == EFI_HOB_TYPE_CPU) {
      CpuHob = Hob.Cpu;
      DEBUG ((DEBUG_INFO,
        "  SizeOfMemorySpace=%x  SizeOfIoSpace=%x\n",
        CpuHob->SizeOfMemorySpace,
        CpuHob->SizeOfIoSpace
        ));
    }
  }

  return EFI_SUCCESS;
}

EFI_STATUS
DumpResourceHob (
  IN VOID                        *HobList
  )
{
  EFI_PEI_HOB_POINTERS        Hob;
  EFI_HOB_RESOURCE_DESCRIPTOR *ResourceHob;
  
  DEBUG ((DEBUG_INFO, "Resource Descriptor HOBs\n"));
  for (Hob.Raw = HobList; !END_OF_HOB_LIST (Hob); Hob.Raw = GET_NEXT_HOB (Hob)) {

    if (GET_HOB_TYPE (Hob) == EFI_HOB_TYPE_RESOURCE_DESCRIPTOR) {

      ResourceHob = Hob.ResourceDescriptor;

      DEBUG ((DEBUG_INFO,
        "  BA=%016lx  L=%016lx  Attr=%08x  ",
        ResourceHob->PhysicalStart,
        ResourceHob->ResourceLength,
        ResourceHob->ResourceAttribute
        ));

      DEBUG ((DEBUG_INFO, ShortNameOfResourceType(ResourceHob->ResourceType)));
      switch (ResourceHob->ResourceType) {
      case EFI_RESOURCE_SYSTEM_MEMORY:
        if ((ResourceHob->ResourceAttribute & EFI_RESOURCE_ATTRIBUTE_PERSISTENT) != 0) {
          DEBUG ((DEBUG_INFO, " (Persistent)"));
        } else if ((ResourceHob->ResourceAttribute & EFI_RESOURCE_ATTRIBUTE_MORE_RELIABLE) != 0) {
          DEBUG ((DEBUG_INFO, " (MoreReliable)"));
        } else if ((ResourceHob->ResourceAttribute & MEMORY_ATTRIBUTE_MASK) == TESTED_MEMORY_ATTRIBUTES) {
          DEBUG ((DEBUG_INFO, " (Tested)"));
        } else if ((ResourceHob->ResourceAttribute & MEMORY_ATTRIBUTE_MASK) == INITIALIZED_MEMORY_ATTRIBUTES) {
          DEBUG ((DEBUG_INFO, " (Init)"));
        } else if ((ResourceHob->ResourceAttribute & MEMORY_ATTRIBUTE_MASK) == PRESENT_MEMORY_ATTRIBUTES) {
          DEBUG ((DEBUG_INFO, " (Present)"));
        } else {
          DEBUG ((DEBUG_INFO, " (Unknown)"));
        }
        break;
      default:
        break;
      }
      DEBUG ((DEBUG_INFO, "\n"));
    }
  }

  return EFI_SUCCESS;
}

EFI_STATUS
DumpFvHob (
  IN VOID                        *HobList
  )
{
  EFI_PEI_HOB_POINTERS        Hob;
  EFI_HOB_FIRMWARE_VOLUME     *FirmwareVolumeHob;
  EFI_HOB_FIRMWARE_VOLUME2    *FirmwareVolume2Hob;
  BOOLEAN                     Found;
  
  Found = FALSE;
  DEBUG ((DEBUG_INFO, "FV HOBs\n"));
  for (Hob.Raw = HobList; !END_OF_HOB_LIST (Hob); Hob.Raw = GET_NEXT_HOB (Hob)) {
    if (GET_HOB_TYPE (Hob) == EFI_HOB_TYPE_FV) {

      FirmwareVolumeHob = Hob.FirmwareVolume;

      DEBUG ((DEBUG_INFO,
        "  BA=%016lx  L=%016lx\n",
        FirmwareVolumeHob->BaseAddress,
        FirmwareVolumeHob->Length
        ));
      Found = TRUE;
    }
  }

  DEBUG ((DEBUG_INFO, "FV2 HOBs\n"));
  for (Hob.Raw = HobList; !END_OF_HOB_LIST (Hob); Hob.Raw = GET_NEXT_HOB (Hob)) {
    if (GET_HOB_TYPE (Hob) == EFI_HOB_TYPE_FV2) {

      FirmwareVolume2Hob = Hob.FirmwareVolume2;

      DEBUG ((DEBUG_INFO,
        "  BA=%016lx  L=%016lx  Fv={%g}  File={%g}\n",
        FirmwareVolume2Hob->BaseAddress,
        FirmwareVolume2Hob->Length,
        &FirmwareVolume2Hob->FvName,
        &FirmwareVolume2Hob->FileName
        ));
      Found = TRUE;
    }
  }

  if (!Found) {
    TestPointLibAppendErrorString (
      PLATFORM_TEST_POINT_ROLE_PLATFORM_IBV,
      NULL,
      TEST_POINT_BYTE1_END_OF_PEI_ERROR_CODE_3 TEST_POINT_END_OF_PEI TEST_POINT_BYTE1_END_OF_PEI_ERROR_STRING_3
      );
    return EFI_INVALID_PARAMETER;
  }

  return EFI_SUCCESS;
}

EFI_STATUS
DumpMemoryAllocationHob (
  IN VOID                        *HobList
  )
{
  EFI_PEI_HOB_POINTERS        Hob;
  EFI_HOB_MEMORY_ALLOCATION   *MemoryHob;

  DEBUG ((DEBUG_INFO, "Memory Allocation HOBs\n"));
  for (Hob.Raw = HobList; !END_OF_HOB_LIST (Hob); Hob.Raw = GET_NEXT_HOB (Hob)) {
    if (GET_HOB_TYPE(Hob) == EFI_HOB_TYPE_MEMORY_ALLOCATION) {

      MemoryHob = Hob.MemoryAllocation;

      DEBUG ((DEBUG_INFO,
        "  BA=%016lx  L=%016lx  ",
        MemoryHob->AllocDescriptor.MemoryBaseAddress,
        MemoryHob->AllocDescriptor.MemoryLength
        ));
      DEBUG ((DEBUG_INFO, ShortNameOfMemoryType(MemoryHob->AllocDescriptor.MemoryType)));
      if (!IsZeroGuid(&MemoryHob->AllocDescriptor.Name)) {
        if (CompareGuid(&gEfiHobMemoryAllocStackGuid, &MemoryHob->AllocDescriptor.Name)) {
          DEBUG ((DEBUG_INFO,
            "  {Stack}",
            &MemoryHob->AllocDescriptor.Name
            ));
        } else if (CompareGuid(&gEfiHobMemoryAllocBspStoreGuid, &MemoryHob->AllocDescriptor.Name)) {
          DEBUG ((DEBUG_INFO,
            "  {BspStore}",
            &MemoryHob->AllocDescriptor.Name
            ));
        } else if (CompareGuid(&gEfiHobMemoryAllocModuleGuid, &MemoryHob->AllocDescriptor.Name)) {
          DEBUG ((DEBUG_INFO,
            "  {Module=%g,Entry=0x%lx}",
            &((EFI_HOB_MEMORY_ALLOCATION_MODULE *)MemoryHob)->ModuleName,
            ((EFI_HOB_MEMORY_ALLOCATION_MODULE *)MemoryHob)->EntryPoint
            ));
        } else {
          DEBUG ((DEBUG_INFO,
            "  {%g}",
            &MemoryHob->AllocDescriptor.Name
            ));
        }
      }
      DEBUG ((DEBUG_INFO, "\n"));
    }
  }

  return EFI_SUCCESS;
}

EFI_STATUS
DumpGuidHob (
  IN VOID                        *HobList
  )
{
  EFI_PEI_HOB_POINTERS        Hob;
  EFI_HOB_GUID_TYPE           *GuidHob;

  DEBUG ((DEBUG_INFO, "GUID HOBs\n"));
  for (Hob.Raw = HobList; !END_OF_HOB_LIST (Hob); Hob.Raw = GET_NEXT_HOB (Hob)) {
    if (GET_HOB_TYPE (Hob) == EFI_HOB_TYPE_GUID_EXTENSION) {

      GuidHob = Hob.Guid;

      DEBUG ((DEBUG_INFO,
        "  GUID=%g  DataSize=0x%x\n",
        &GuidHob->Name,
        GET_GUID_HOB_DATA_SIZE(GuidHob)
        ));
    }
  }

  return EFI_SUCCESS;
}

EFI_STATUS
TestPointDumpHob (
  IN BOOLEAN  PhitHobOnly
  )
{
  VOID                        *HobList;
  EFI_STATUS                  Status;
  BOOLEAN                     Result;
  
  DEBUG ((DEBUG_INFO, "==== TestPointDumpHob - Enter\n"));
  //
  // Get Hob list
  //
  HobList = GetHobList ();

  Result = TRUE;
  
  Status = DumpPhitHob (HobList);
  if (EFI_ERROR(Status)) {
    Result = FALSE;
  }

  if (PhitHobOnly) {
    goto Done ;
  }

  Status = DumpCpuHob (HobList);
  if (EFI_ERROR(Status)) {
    Result = FALSE;
  }

  Status = DumpResourceHob (HobList);
  if (EFI_ERROR(Status)) {
    Result = FALSE;
  }

  Status = DumpFvHob (HobList);
  if (EFI_ERROR(Status)) {
    Result = FALSE;
  }

  Status = DumpMemoryAllocationHob (HobList);
  if (EFI_ERROR(Status)) {
    Result = FALSE;
  }

  Status = DumpGuidHob (HobList);
  if (EFI_ERROR(Status)) {
    Result = FALSE;
  }

Done:
  DEBUG ((DEBUG_INFO, "==== TestPointDumpHob - Exit\n"));

  if (!Result) {
    return EFI_INVALID_PARAMETER;
  }
  return EFI_SUCCESS;
}

