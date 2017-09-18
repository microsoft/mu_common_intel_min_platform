/** @file
  Source code file for Platform Init Pre-Memory PEI module

Copyright (c) 2017, Intel Corporation. All rights reserved.<BR>
This program and the accompanying materials are licensed and made available under
the terms and conditions of the BSD License that accompanies this distribution.
The full text of the license may be found at
http://opensource.org/licenses/bsd-license.php.

THE PROGRAM IS DISTRIBUTED UNDER THE BSD LICENSE ON AN "AS IS" BASIS,
WITHOUT WARRANTIES OR REPRESENTATIONS OF ANY KIND, EITHER EXPRESS OR IMPLIED.

**/

#include <Base.h>
#include <IndustryStandard/Pci30.h>
#include <Library/IoLib.h>
#include <Library/DebugLib.h>
#include <Library/HobLib.h>
#include <Library/PcdLib.h>
#include <Library/TimerLib.h>
#include <Library/BaseMemoryLib.h>
#include <Library/PeiServicesLib.h>
#include <Library/MtrrLib.h>
#include <Ppi/ReadOnlyVariable2.h>
#include <Ppi/MemoryDiscovered.h>
#include <Ppi/FirmwareVolumeInfo.h>
#include <Ppi/BootInRecoveryMode.h>
#include <Ppi/MasterBootMode.h>
#include <Guid/FirmwareFileSystem2.h>
#include <Library/PeiServicesTablePointerLib.h>
#include <Library/BoardInitLib.h>
#include <Library/TestPointCheckLib.h>
#include <Guid/MemoryTypeInformation.h>

EFI_STATUS
EFIAPI
PlatformInitPreMem (
  IN CONST EFI_PEI_SERVICES      **PeiServices,
  IN EFI_PEI_NOTIFY_DESCRIPTOR   *NotifyDescriptor,
  IN VOID                        *Ppi
  );

EFI_STATUS
EFIAPI
MemoryDiscoveredPpiNotifyCallback (
  IN CONST EFI_PEI_SERVICES      **PeiServices,
  IN EFI_PEI_NOTIFY_DESCRIPTOR   *NotifyDescriptor,
  IN VOID                        *Ppi
  );

static EFI_PEI_NOTIFY_DESCRIPTOR mPreMemNotifyList = {
  (EFI_PEI_PPI_DESCRIPTOR_NOTIFY_CALLBACK | EFI_PEI_PPI_DESCRIPTOR_TERMINATE_LIST),
  &gEfiPeiReadOnlyVariable2PpiGuid,
  (EFI_PEIM_NOTIFY_ENTRY_POINT) PlatformInitPreMem
};

static EFI_PEI_NOTIFY_DESCRIPTOR mMemDiscoveredNotifyList = {
  (EFI_PEI_PPI_DESCRIPTOR_NOTIFY_CALLBACK | EFI_PEI_PPI_DESCRIPTOR_TERMINATE_LIST),
  &gEfiPeiMemoryDiscoveredPpiGuid,
  (EFI_PEIM_NOTIFY_ENTRY_POINT) MemoryDiscoveredPpiNotifyCallback
};

GLOBAL_REMOVE_IF_UNREFERENCED EFI_PEI_PPI_DESCRIPTOR mPpiListRecoveryBootMode = {
  (EFI_PEI_PPI_DESCRIPTOR_PPI | EFI_PEI_PPI_DESCRIPTOR_TERMINATE_LIST),
  &gEfiPeiBootInRecoveryModePpiGuid,
  NULL
};

GLOBAL_REMOVE_IF_UNREFERENCED EFI_PEI_PPI_DESCRIPTOR mPpiBootMode = {
  (EFI_PEI_PPI_DESCRIPTOR_PPI | EFI_PEI_PPI_DESCRIPTOR_TERMINATE_LIST),
  &gEfiPeiMasterBootModePpiGuid,
  NULL
};

///
/// Memory Reserved should be between 125% to 150% of the Current required memory
/// otherwise BdsMisc.c would do a reset to make it 125% to avoid s4 resume issues.
///
GLOBAL_REMOVE_IF_UNREFERENCED EFI_MEMORY_TYPE_INFORMATION mDefaultMemoryTypeInformation[] = {
  { EfiACPIReclaimMemory,   FixedPcdGet32 (PcdPlatformEfiAcpiReclaimMemorySize) },  // ASL
  { EfiACPIMemoryNVS,       FixedPcdGet32 (PcdPlatformEfiAcpiNvsMemorySize) },      // ACPI NVS (including S3 related)
  { EfiReservedMemoryType,  FixedPcdGet32 (PcdPlatformEfiReservedMemorySize) },     // BIOS Reserved (including S3 related)
  { EfiRuntimeServicesData, FixedPcdGet32 (PcdPlatformEfiRtDataMemorySize) },       // Runtime Service Data
  { EfiRuntimeServicesCode, FixedPcdGet32 (PcdPlatformEfiRtCodeMemorySize) },       // Runtime Service Code
  { EfiMaxMemoryType, 0 }
};

VOID
BuildMemoryTypeInformation (
  VOID
  )
{
  EFI_STATUS                      Status;
  EFI_PEI_READ_ONLY_VARIABLE2_PPI *VariableServices;
  UINTN                           DataSize;
  EFI_MEMORY_TYPE_INFORMATION     MemoryData[EfiMaxMemoryType + 1];
  
  //
  // Locate system configuration variable
  //
  Status = PeiServicesLocatePpi(
             &gEfiPeiReadOnlyVariable2PpiGuid, // GUID
             0,                                // INSTANCE
             NULL,                             // EFI_PEI_PPI_DESCRIPTOR
             (VOID **) &VariableServices       // PPI
             );
  ASSERT_EFI_ERROR(Status);

  DataSize = sizeof (MemoryData);
  Status = VariableServices->GetVariable (
                               VariableServices,
                               EFI_MEMORY_TYPE_INFORMATION_VARIABLE_NAME,
                               &gEfiMemoryTypeInformationGuid,
                               NULL,
                               &DataSize,
                               &MemoryData
                               );
  if (EFI_ERROR(Status)) {
    DataSize = sizeof (mDefaultMemoryTypeInformation);
    CopyMem(MemoryData, mDefaultMemoryTypeInformation, DataSize);
  }

  ///
  /// Build the GUID'd HOB for DXE
  ///
  BuildGuidDataHob (
    &gEfiMemoryTypeInformationGuid,
    MemoryData,
    DataSize
    );
}

/**
  Set Cache Mtrr.
**/
VOID
SetCacheMtrr (
  VOID
  )
{
  EFI_STATUS                  Status;
  EFI_PEI_HOB_POINTERS        Hob;
  MTRR_SETTINGS               MtrrSetting;
  UINT64                      MemoryBase;
  UINT64                      MemoryLength;
  UINT64                      LowMemoryLength;
  UINT64                      HighMemoryLength;
  EFI_BOOT_MODE               BootMode;
  EFI_RESOURCE_ATTRIBUTE_TYPE ResourceAttribute;
  UINT64                      CacheMemoryLength;

  ///
  /// Reset all MTRR setting.
  ///
  ZeroMem(&MtrrSetting, sizeof(MTRR_SETTINGS));

  ///
  /// Cache the Flash area as WP to boost performance
  ///
  Status = MtrrSetMemoryAttributeInMtrrSettings (
                &MtrrSetting,
                (UINTN) FixedPcdGet32 (PcdFlashAreaBaseAddress),
                (UINTN) FixedPcdGet32 (PcdFlashAreaSize),
                CacheWriteProtected
                );
  ASSERT_EFI_ERROR (Status);

  ///
  /// Update MTRR setting from MTRR buffer for Flash Region to be WP to boost performance
  ///
  MtrrSetAllMtrrs (&MtrrSetting);

  ///
  /// Set low to 1 MB. Since 1MB cacheability will always be set
  /// until override by CSM.
  /// Initialize high memory to 0.
  ///
  LowMemoryLength   = 0x100000;
  HighMemoryLength  = 0;
  ResourceAttribute = (
                       EFI_RESOURCE_ATTRIBUTE_PRESENT |
                       EFI_RESOURCE_ATTRIBUTE_INITIALIZED |
                       EFI_RESOURCE_ATTRIBUTE_UNCACHEABLE |
                       EFI_RESOURCE_ATTRIBUTE_WRITE_COMBINEABLE |
                       EFI_RESOURCE_ATTRIBUTE_WRITE_THROUGH_CACHEABLE |
                       EFI_RESOURCE_ATTRIBUTE_WRITE_BACK_CACHEABLE
                       );

  Status = PeiServicesGetBootMode (&BootMode);
  ASSERT_EFI_ERROR (Status);

  if (BootMode != BOOT_ON_S3_RESUME) {
    ResourceAttribute |= EFI_RESOURCE_ATTRIBUTE_TESTED;
  }

  Status = PeiServicesGetHobList ((VOID **) &Hob.Raw);
  while (!END_OF_HOB_LIST (Hob)) {
    if (Hob.Header->HobType == EFI_HOB_TYPE_RESOURCE_DESCRIPTOR) {
      if ((Hob.ResourceDescriptor->ResourceType == EFI_RESOURCE_SYSTEM_MEMORY) ||
          ((Hob.ResourceDescriptor->ResourceType == EFI_RESOURCE_MEMORY_RESERVED) &&
           (Hob.ResourceDescriptor->ResourceAttribute == ResourceAttribute))
         ) {
        if (Hob.ResourceDescriptor->PhysicalStart >= 0x100000000ULL) {
          HighMemoryLength += Hob.ResourceDescriptor->ResourceLength;
        } else if (Hob.ResourceDescriptor->PhysicalStart >= 0x100000) {
          LowMemoryLength += Hob.ResourceDescriptor->ResourceLength;
        }
      }
    }

    Hob.Raw = GET_NEXT_HOB (Hob);
  }

  DEBUG ((DEBUG_INFO, "Memory Length (Below 4GB) = %lx.\n", LowMemoryLength));
  DEBUG ((DEBUG_INFO, "Memory Length (Above 4GB) = %lx.\n", HighMemoryLength));

  ///
  /// Assume size of main memory is multiple of 256MB
  ///
  MemoryLength = (LowMemoryLength + 0xFFFFFFF) & 0xF0000000;
  MemoryBase = 0;

  CacheMemoryLength = MemoryLength;
  ///
  /// Programming MTRRs to avoid override SPI region with UC when MAX TOLUD Length >= 3.5GB
  ///
  if (MemoryLength > 0xDC000000) {
     CacheMemoryLength = 0xC0000000;
     Status = MtrrSetMemoryAttributeInMtrrSettings (
                &MtrrSetting,
                MemoryBase,
                CacheMemoryLength,
                CacheWriteBack
                );
     ASSERT_EFI_ERROR (Status);

     MemoryBase = 0xC0000000;
     CacheMemoryLength = MemoryLength - 0xC0000000;
     if (MemoryLength > 0xE0000000) {
        CacheMemoryLength = 0x20000000;
        Status = MtrrSetMemoryAttributeInMtrrSettings (
                 &MtrrSetting,
                 MemoryBase,
                 CacheMemoryLength,
                 CacheWriteBack
                 );
        ASSERT_EFI_ERROR (Status);

        MemoryBase = 0xE0000000;
        CacheMemoryLength = MemoryLength - 0xE0000000;
     }
  }

  Status = MtrrSetMemoryAttributeInMtrrSettings (
                &MtrrSetting,
                MemoryBase,
                CacheMemoryLength,
                CacheWriteBack
                );
  ASSERT_EFI_ERROR (Status);

  if (LowMemoryLength != MemoryLength) {
     MemoryBase = LowMemoryLength;
     MemoryLength -= LowMemoryLength;
     Status = MtrrSetMemoryAttributeInMtrrSettings (
                   &MtrrSetting,
                   MemoryBase,
                   MemoryLength,
                   CacheUncacheable
                   );
      ASSERT_EFI_ERROR (Status);
  }

  ///
  /// VGA-MMIO - 0xA0000 to 0xC0000 to be UC
  ///
  Status = MtrrSetMemoryAttributeInMtrrSettings (
                &MtrrSetting,
                0xA0000,
                0x20000,
                CacheUncacheable
                );
  ASSERT_EFI_ERROR (Status);

  ///
  /// Update MTRR setting from MTRR buffer
  ///
  MtrrSetAllMtrrs (&MtrrSetting);

  return ;
}

VOID
ReportCpuHob (
  VOID
  )
{
  UINT8                         PhysicalAddressBits;
  UINT32                        RegEax;

  AsmCpuid (0x80000000, &RegEax, NULL, NULL, NULL);
  if (RegEax >= 0x80000008) {
    AsmCpuid (0x80000008, &RegEax, NULL, NULL, NULL);
    PhysicalAddressBits = (UINT8) RegEax;
  } else {
    PhysicalAddressBits = 36;
  }

  ///
  /// Create a CPU hand-off information
  ///
  BuildCpuHob (PhysicalAddressBits, 16);
}

VOID
ReportFv (
  VOID
  )
{
  EFI_STATUS                    Status;
  EFI_BOOT_MODE                 BootMode;

  Status = PeiServicesGetBootMode (&BootMode);
  ASSERT_EFI_ERROR (Status);

  ///
  /// Build HOB for DXE
  ///
  if (BootMode == BOOT_IN_RECOVERY_MODE) {
    ///
    /// Prepare the recovery service
    ///
  } else {

    PeiServicesInstallFvInfo2Ppi (
      &(((EFI_FIRMWARE_VOLUME_HEADER *) (UINTN) FixedPcdGet32 (PcdFlashFvPostMemoryBase))->FileSystemGuid),
      (VOID *) (UINTN) FixedPcdGet32 (PcdFlashFvPostMemoryBase),
      FixedPcdGet32 (PcdFlashFvPostMemorySize),
      NULL,
      NULL,
      0
      );
    PeiServicesInstallFvInfo2Ppi (
      &(((EFI_FIRMWARE_VOLUME_HEADER *) (UINTN) FixedPcdGet32 (PcdFlashFvUefiBootBase))->FileSystemGuid),
      (VOID *) (UINTN) FixedPcdGet32 (PcdFlashFvUefiBootBase),
      FixedPcdGet32 (PcdFlashFvUefiBootSize),
      NULL,
      NULL,
      0
      );
    PeiServicesInstallFvInfo2Ppi (
      &(((EFI_FIRMWARE_VOLUME_HEADER *) (UINTN) FixedPcdGet32 (PcdFlashFvOsBootBase))->FileSystemGuid),
      (VOID *) (UINTN) FixedPcdGet32 (PcdFlashFvOsBootBase),
      FixedPcdGet32 (PcdFlashFvOsBootSize),
      NULL,
      NULL,
      0
      );
  }

  //
  // Report resource HOB for flash FV
  //
  BuildResourceDescriptorHob (
    EFI_RESOURCE_MEMORY_MAPPED_IO,
    (EFI_RESOURCE_ATTRIBUTE_PRESENT    |
    EFI_RESOURCE_ATTRIBUTE_INITIALIZED |
    EFI_RESOURCE_ATTRIBUTE_UNCACHEABLE),
    (UINTN) FixedPcdGet32 (PcdFlashAreaBaseAddress),
    (UINTN) FixedPcdGet32 (PcdFlashAreaSize)
    );
  BuildMemoryAllocationHob (
    (UINTN) FixedPcdGet32 (PcdFlashAreaBaseAddress),
    (UINTN) FixedPcdGet32 (PcdFlashAreaSize),
    EfiMemoryMappedIO
    );

  BuildFvHob (
    (UINTN) FixedPcdGet32 (PcdFlashAreaBaseAddress),
    (UINTN) FixedPcdGet32 (PcdFlashAreaSize)
    );
}

/**
  Install Firmware Volume Hob's once there is main memory

  @param[in]  PeiServices       General purpose services available to every PEIM.
  @param[in]  NotifyDescriptor  Notify that this module published.
  @param[in]  Ppi               PPI that was installed.

  @retval     EFI_SUCCESS       The function completed successfully.
**/
EFI_STATUS
EFIAPI
MemoryDiscoveredPpiNotifyCallback (
  IN CONST EFI_PEI_SERVICES     **PeiServices,
  IN EFI_PEI_NOTIFY_DESCRIPTOR  *NotifyDescriptor,
  IN VOID                       *Ppi
  )
{
  EFI_STATUS                    Status;
  EFI_BOOT_MODE                 BootMode;
  
  Status = BoardInitAfterMemoryInit ();
  ASSERT_EFI_ERROR (Status);

  Status = PeiServicesGetBootMode (&BootMode);
  ASSERT_EFI_ERROR (Status);

  SetCacheMtrr ();

  ReportCpuHob ();

  ///
  /// If S3 resume, then we are done
  ///
  if (BootMode == BOOT_ON_S3_RESUME) {
    return EFI_SUCCESS;
  }

  ReportFv ();

  TestPointMemoryDiscovered ();
  
  if (PcdGetBool (PcdStopAfterMemInit)) {
    CpuDeadLoop ();
  }
  
  return Status;
}


/**
  This function handles PlatformInit task after PeiReadOnlyVariable2 PPI produced

  @param[in]  PeiServices  Pointer to PEI Services Table.
  @param[in]  NotifyDesc   Pointer to the descriptor for the Notification event that
                           caused this function to execute.
  @param[in]  Ppi          Pointer to the PPI data associated with this function.

  @retval     EFI_SUCCESS  The function completes successfully
  @retval     others
**/
EFI_STATUS
EFIAPI
PlatformInitPreMem (
  IN CONST EFI_PEI_SERVICES     **PeiServices,
  IN EFI_PEI_NOTIFY_DESCRIPTOR  *NotifyDescriptor,
  IN VOID                       *Ppi
  )
{
  EFI_STATUS                        Status;
  EFI_BOOT_MODE                     BootMode;

  //
  // Start board detection
  //
  BoardDetect ();

  BoardDebugInit ();

  TestPointDebugInitDone ();

  if (PcdGetBool (PcdStopAfterDebugInit)) {
    CpuDeadLoop ();
  }
  
  BootMode = BoardBootModeDetect ();
  Status = PeiServicesSetBootMode (BootMode);
  ASSERT_EFI_ERROR (Status);
  if (BootMode == BOOT_IN_RECOVERY_MODE) {
    Status = PeiServicesInstallPpi (&mPpiListRecoveryBootMode);
  }
  ///
  /// Signal possible dependent modules that there has been a
  /// final boot mode determination, it is used to build BIST
  /// Hob for Dxe use.
  ///
  Status = PeiServicesInstallPpi (&mPpiBootMode);
  ASSERT_EFI_ERROR (Status);
  
  BuildMemoryTypeInformation ();

  Status = BoardInitBeforeMemoryInit ();
  ASSERT_EFI_ERROR (Status);

  return Status;
}


/**
  Platform Init before memory PEI module entry point

  @param[in]  FileHandle           Not used.
  @param[in]  PeiServices          General purpose services available to every PEIM.

  @retval     EFI_SUCCESS          The function completes successfully
  @retval     EFI_OUT_OF_RESOURCES Insufficient resources to create database
**/
EFI_STATUS
EFIAPI
PlatformInitPreMemEntryPoint (
  IN       EFI_PEI_FILE_HANDLE  FileHandle,
  IN CONST EFI_PEI_SERVICES     **PeiServices
  )
{
  EFI_STATUS Status;

  ///
  /// Performing PlatformInitPreMem after PeiReadOnlyVariable2 PPI produced
  ///
  Status = PeiServicesNotifyPpi (&mPreMemNotifyList);

  ///
  /// After code reorangized, memorycallback will run because the PPI is already
  /// installed when code run to here, it is supposed that the InstallEfiMemory is
  /// done before.
  ///
  Status = PeiServicesNotifyPpi (&mMemDiscoveredNotifyList);

  return Status;
}
