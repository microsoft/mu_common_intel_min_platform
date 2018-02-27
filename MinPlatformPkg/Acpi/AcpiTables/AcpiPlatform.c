/** @file
  ACPI Platform Driver

Copyright (c) 2017, Intel Corporation. All rights reserved.<BR>
This program and the accompanying materials are licensed and made available under
the terms and conditions of the BSD License that accompanies this distribution.
The full text of the license may be found at
http://opensource.org/licenses/bsd-license.php.

THE PROGRAM IS DISTRIBUTED UNDER THE BSD LICENSE ON AN "AS IS" BASIS,
WITHOUT WARRANTIES OR REPRESENTATIONS OF ANY KIND, EITHER EXPRESS OR IMPLIED.

**/

#include "AcpiPlatform.h"

//
// Global variables
//

VOID  *mLocalTable[] = {
  &Facs,
  &Fadt,
  &Hpet,
  &Madt,
  &Mcfg,
  &Wsmt
};

GLOBAL_REMOVE_IF_UNREFERENCED EFI_CPU_ID_ORDER_MAP                      mCpuApicIdOrderTable[MAX_CPU_NUM];
GLOBAL_REMOVE_IF_UNREFERENCED EFI_CPU_APIC_ID_REORDER_MAP               mCpuApicIdReorderTable[MAX_CPU_NUM];

GLOBAL_REMOVE_IF_UNREFERENCED EFI_CPU_PACKAGE_INFO                      mSbspPackageInfo;

//
// Function implementations
//

/*
  This function will determine whether Native ASPM is supported on the platform.

  @return TRUE if Native ASPM is supported, FALSE otherwise
*/
BOOLEAN
IsNativeAspmSupported (
  VOID
  )
{
  if (PcdGet8 (PcdPciExpNative) == 0) {
    return FALSE;
  }
  switch (PcdGet8 (PcdNativeAspmEnable)) {
  case 0:
    return FALSE;
  case 1:
    return TRUE;
  default:
    ASSERT (0);
  }
  return TRUE;
}

/**
  This function will update any runtime platform specific information.
  This currently includes:
    Setting OEM table values, ID, table ID, creator ID and creator revision.
    Enabling the proper processor entries in the APIC tables
  It also indicates with which ACPI table version the table belongs.

  @param[in] Table        The table to update
  @param[in] Version      Where to install this table

  @retval EFI_SUCCESS     Updated tables commplete.
**/
EFI_STATUS
PlatformUpdateTables (
  IN OUT EFI_ACPI_COMMON_HEADER       *Table,
  IN OUT EFI_ACPI_TABLE_VERSION       *Version
  )
{
  EFI_ACPI_DESCRIPTION_HEADER                 *TableHeader;
  UINT8                                       *CurrPtr;
  UINT8                                       *EndPtr;
  EFI_ACPI_1_0_PROCESSOR_LOCAL_APIC_STRUCTURE *ApicPtr;
  EFI_STATUS                                  Status;
  EFI_MP_SERVICES_PROTOCOL                    *MpService;
  UINTN                                       NumberOfCPUs;
  UINTN                                       NumberOfEnabledCPUs;
  UINT32                                      HpetBaseAdress;
  UINT8                                       LocalApicCounter;

  CurrPtr           = NULL;
  EndPtr            = NULL;
  ApicPtr           = NULL;
  NumberOfCPUs      = 1;
  LocalApicCounter  = 0;
  
  //
  // This will be accurate except for FACS structure
  //
  TableHeader = (EFI_ACPI_DESCRIPTION_HEADER *) Table;

  //
  // Update the OEM and creator information for every table except FACS.
  //
  if (Table->Signature != EFI_ACPI_1_0_FIRMWARE_ACPI_CONTROL_STRUCTURE_SIGNATURE) {
    *(UINT32 *) (TableHeader->OemId)      = 'I' + ('N' << 8) + ('T' << 16) + ('E' << 24);
    *(UINT16 *) (TableHeader->OemId + 4)  = 'L' + (' ' << 8);

    //
    // Skip OEM table ID and creator information for DSDT, SSDT and PSDT tables, since these are
    // created by an ASL compiler and the creator information is useful.
    //
    if (Table->Signature != EFI_ACPI_1_0_DIFFERENTIATED_SYSTEM_DESCRIPTION_TABLE_SIGNATURE &&
        Table->Signature != EFI_ACPI_1_0_SECONDARY_SYSTEM_DESCRIPTION_TABLE_SIGNATURE &&
        Table->Signature != EFI_ACPI_1_0_PERSISTENT_SYSTEM_DESCRIPTION_TABLE_SIGNATURE
        ) {

      //
      // Update OEM table ID
      //
      // Check if the silicon is KBL
      TableHeader->OemTableId = PcdGet64 (PcdAcpiDefaultOemTableId);
      //
      // Update creator information
      //
      TableHeader->CreatorId        = EFI_ACPI_CREATOR_ID;
      TableHeader->CreatorRevision  = EFI_ACPI_CREATOR_REVISION;
    }
  }

  //
  // Locate the MP services protocol
  // Find the MP Protocol. This is an MP platform, so MP protocol must be there.
  //
  Status = gBS->LocateProtocol (
                  &gEfiMpServiceProtocolGuid,
                  NULL,
                  (VOID **) &MpService
                  );
  ASSERT_EFI_ERROR (Status);

  //
  // Determine the number of processors
  //
  MpService->GetNumberOfProcessors (
               MpService,
               &NumberOfCPUs,
               &NumberOfEnabledCPUs
               );

  //
  // By default, a table belongs in all ACPI table versions published.
  // Some tables will override this because they have different versions of the table.
  //
  *Version = EFI_ACPI_TABLE_VERSION_1_0B | EFI_ACPI_TABLE_VERSION_2_0 | EFI_ACPI_TABLE_VERSION_3_0;

  //
  // Update the various table types with the necessary updates
  //
  switch (Table->Signature) {

  case EFI_ACPI_1_0_APIC_SIGNATURE:
    //
    // if not MP and not APIC then don't publish the APIC tables.
    //

    //
    // Call for Local APIC ID Reorder
    //
    SortCpuLocalApicInTable (
      MpService,
      NumberOfCPUs,
      NumberOfEnabledCPUs
      );

    CurrPtr = (UINT8 *) &((EFI_ACPI_DESCRIPTION_HEADER *) Table)[1];
    CurrPtr = CurrPtr + 8;
    //
    // Size of Local APIC Address & Flag
    //
    EndPtr  = (UINT8 *) Table;
    EndPtr  = EndPtr + Table->Length;

    while (CurrPtr < EndPtr) {
      ApicPtr = (EFI_ACPI_1_0_PROCESSOR_LOCAL_APIC_STRUCTURE *) CurrPtr;

      //
      // Check table entry type
      //
      if (ApicPtr->Type == EFI_ACPI_1_0_PROCESSOR_LOCAL_APIC) {
        AppendCpuMapTableEntry (
          ApicPtr,
          NumberOfCPUs,
          NumberOfEnabledCPUs,
          LocalApicCounter
          );
        LocalApicCounter++;
      }

      //
      // Go to the next structure in the APIC table
      //
      CurrPtr = CurrPtr + ApicPtr->Length;
    }
    break;

  case EFI_ACPI_5_0_FIXED_ACPI_DESCRIPTION_TABLE_SIGNATURE:
    //
    // Fix up all FACP Table values if configuration requires it.
    // This code fixes up the following Table values:
    // (1) C2/C3/CST Enable FACP values
    // (2) RTC S4 Flag
    //
    {
      EFI_ACPI_5_0_FIXED_ACPI_DESCRIPTION_TABLE *FadtPointer;

      FadtPointer = (EFI_ACPI_5_0_FIXED_ACPI_DESCRIPTION_TABLE *) Table;

      //
      // Check the version of the table
      //
      *Version = EFI_ACPI_TABLE_VERSION_NONE;
      if (FadtPointer->Header.Revision == EFI_ACPI_1_0_FIXED_ACPI_DESCRIPTION_TABLE_REVISION) {
        *Version = EFI_ACPI_TABLE_VERSION_NONE;
      } else if (FadtPointer->Header.Revision == EFI_ACPI_2_0_FIXED_ACPI_DESCRIPTION_TABLE_REVISION) {
        *Version = EFI_ACPI_TABLE_VERSION_1_0B | EFI_ACPI_TABLE_VERSION_2_0;
      } else if (FadtPointer->Header.Revision == EFI_ACPI_3_0_FIXED_ACPI_DESCRIPTION_TABLE_REVISION) {
        *Version = EFI_ACPI_TABLE_VERSION_1_0B | EFI_ACPI_TABLE_VERSION_3_0;
      } else if (FadtPointer->Header.Revision == EFI_ACPI_5_0_FIXED_ACPI_DESCRIPTION_TABLE_REVISION) {
        *Version = EFI_ACPI_TABLE_VERSION_1_0B | EFI_ACPI_TABLE_VERSION_5_0;
      }

      //
      // Modify Preferred_PM_Profile field based on Board SKU's. Default is set to Mobile
      //
      FadtPointer->PreferredPmProfile = PcdGet8 (PcdPreferredPmProfile);

      //
      // if Native ASPM is disabled, set FACP table to skip Native ASPM
      //
      if (!IsNativeAspmSupported ()) {
        FadtPointer->IaPcBootArch |= 0x10;
      }

      //
      //PME WAKE supported, set PCI_EXP_WAK, BIT14 of Fixed feature flags.
      //
      FadtPointer->Flags |= (EFI_ACPI_6_0_PCI_EXP_WAK);

      if (PcdGet8 (PcdLowPowerS0Idle)) {
        // The Flags field within the FADT (offset 112)
        //   1) will have a new Low Power S0 Idle Capable ACPI flag (bit offset 21).
        FadtPointer->Flags = (BIT21 | FadtPointer->Flags);
        //Only passive docking available in Conected Standby mode. Clear Docking capability Bit
        FadtPointer->Flags &= ~BIT9;
      }
      //
      // Modify FADT Fixed Feature Flag to support 10 sec Power button.
      // If 10sec Power button is enabled: Set PWR_BUTTON(bit4) in Fixed Feature Flag(FACP offset 112)
      //
      if ((PcdGet8 (PcdLowPowerS0Idle) == 1) || (PcdGet8 (PcdTenSecondPowerButtonEnable) == 1)) {
        FadtPointer->Flags |= EFI_ACPI_2_0_PWR_BUTTON; // Set Fixed Power Button flag (Disabling Fixed Power button and enabling Control Method PB)
      } else {
        FadtPointer->Flags &= ~(EFI_ACPI_2_0_PWR_BUTTON); // Clear fixed Power Button flag, means enable Power Button as Fixed PB
      }

      //
      // 1. set header revision.
      //
      FadtPointer->Header.Revision = EFI_ACPI_5_0_FIXED_ACPI_DESCRIPTION_TABLE_REVISION;

      //
      // 2. set all GAR register AccessSize to valid value.
      //
      ((EFI_ACPI_5_0_FIXED_ACPI_DESCRIPTION_TABLE *)FadtPointer)->ResetReg.AccessSize    = EFI_ACPI_5_0_BYTE;
      ((EFI_ACPI_5_0_FIXED_ACPI_DESCRIPTION_TABLE *)FadtPointer)->XPm1aEvtBlk.AccessSize = EFI_ACPI_5_0_WORD;
      ((EFI_ACPI_5_0_FIXED_ACPI_DESCRIPTION_TABLE *)FadtPointer)->XPm1bEvtBlk.AccessSize = EFI_ACPI_5_0_WORD;
      ((EFI_ACPI_5_0_FIXED_ACPI_DESCRIPTION_TABLE *)FadtPointer)->XPm1aCntBlk.AccessSize = EFI_ACPI_5_0_WORD;
      ((EFI_ACPI_5_0_FIXED_ACPI_DESCRIPTION_TABLE *)FadtPointer)->XPm1bCntBlk.AccessSize = EFI_ACPI_5_0_WORD;
      ((EFI_ACPI_5_0_FIXED_ACPI_DESCRIPTION_TABLE *)FadtPointer)->XPm2CntBlk.AccessSize  = EFI_ACPI_5_0_BYTE;
      ((EFI_ACPI_5_0_FIXED_ACPI_DESCRIPTION_TABLE *)FadtPointer)->XPmTmrBlk.AccessSize   = EFI_ACPI_5_0_DWORD;
      ((EFI_ACPI_5_0_FIXED_ACPI_DESCRIPTION_TABLE *)FadtPointer)->XGpe0Blk.AccessSize    = EFI_ACPI_5_0_BYTE;
      ((EFI_ACPI_5_0_FIXED_ACPI_DESCRIPTION_TABLE *)FadtPointer)->XGpe1Blk.AccessSize    = EFI_ACPI_5_0_BYTE;

      ((EFI_ACPI_5_0_FIXED_ACPI_DESCRIPTION_TABLE *)FadtPointer)->SleepControlReg.AddressSpaceId    = 0x1;
      ((EFI_ACPI_5_0_FIXED_ACPI_DESCRIPTION_TABLE *)FadtPointer)->SleepControlReg.RegisterBitWidth  = 0x8;
      ((EFI_ACPI_5_0_FIXED_ACPI_DESCRIPTION_TABLE *)FadtPointer)->SleepControlReg.RegisterBitOffset = 0;
      ((EFI_ACPI_5_0_FIXED_ACPI_DESCRIPTION_TABLE *)FadtPointer)->SleepControlReg.AccessSize        = EFI_ACPI_5_0_DWORD;
      ((EFI_ACPI_5_0_FIXED_ACPI_DESCRIPTION_TABLE *)FadtPointer)->SleepControlReg.Address           = EFI_ACPI_PM1A_EVT_BLK_ADDRESS + 4;

      ((EFI_ACPI_5_0_FIXED_ACPI_DESCRIPTION_TABLE *)FadtPointer)->SleepStatusReg.AddressSpaceId     = 0x1;
      ((EFI_ACPI_5_0_FIXED_ACPI_DESCRIPTION_TABLE *)FadtPointer)->SleepStatusReg.RegisterBitWidth   = 0x8;
      ((EFI_ACPI_5_0_FIXED_ACPI_DESCRIPTION_TABLE *)FadtPointer)->SleepStatusReg.RegisterBitOffset  = 0;
      ((EFI_ACPI_5_0_FIXED_ACPI_DESCRIPTION_TABLE *)FadtPointer)->SleepStatusReg.AccessSize         = EFI_ACPI_5_0_DWORD;
      ((EFI_ACPI_5_0_FIXED_ACPI_DESCRIPTION_TABLE *)FadtPointer)->SleepStatusReg.Address            = EFI_ACPI_PM1A_EVT_BLK_ADDRESS;

    }
    break;

  case EFI_ACPI_3_0_HIGH_PRECISION_EVENT_TIMER_TABLE_SIGNATURE:
    //
    // If HPET is disabled in setup, don't publish the table.
    //
      //
      // Get HPET base address
      //
      HpetBaseAdress = PcdGet32 (PcdHpetBaseAddress);
      //
      // Adjust HPET Table to correct the Base Address
      //
      ((EFI_ACPI_HIGH_PRECISION_EVENT_TIMER_TABLE_HEADER*) Table)->BaseAddressLower32Bit.Address = HpetBaseAdress;
    break;
    
  default:
    break;
  }
  return EFI_SUCCESS;
}

/**
  This function calculates RCR based on PCI Device ID and Vendor ID from the devices
  available on the platform.
  It also includes other instances of BIOS change to calculate CRC and provides as
  HWSignature filed in FADT table.
**/
VOID
IsHardwareChange (
  VOID
  )
{
  EFI_STATUS                    Status;
  UINTN                         Index;
  UINTN                         HandleCount;
  EFI_HANDLE                    *HandleBuffer;
  EFI_PCI_IO_PROTOCOL           *PciIo;
  UINT32                        CRC;
  UINT32                        *HWChange;
  UINTN                         HWChangeSize;
  UINT32                        PciId;
  UINTN                         Handle;
  EFI_ACPI_2_0_FIRMWARE_ACPI_CONTROL_STRUCTURE *FacsPtr;
  EFI_ACPI_3_0_FIXED_ACPI_DESCRIPTION_TABLE    *pFADT;

  HandleCount  = 0;
  HandleBuffer = NULL;

  Status = gBS->LocateHandleBuffer (
                  ByProtocol,
                  &gEfiPciIoProtocolGuid,
                  NULL,
                  &HandleCount,
                  &HandleBuffer
                  );
  if (EFI_ERROR (Status)) {
    return; // PciIO protocol not installed yet!
  }

  //
  // Allocate memory for HWChange and add additional entrie for
  // pFADT->XDsdt
  //
  HWChangeSize = HandleCount + 1;
  HWChange = AllocateZeroPool( sizeof(UINT32) * HWChangeSize );
  ASSERT( HWChange != NULL );

  if (HWChange == NULL) return;

  //
  // add HWChange inputs: PCI devices
  //
  for (Index = 0; HandleCount > 0; HandleCount--) {
    PciId = 0;
    Status = gBS->HandleProtocol (HandleBuffer[Index], &gEfiPciIoProtocolGuid, (VOID **) &PciIo);
    if (!EFI_ERROR (Status)) {
      Status = PciIo->Pci.Read (PciIo, EfiPciIoWidthUint32, 0, 1, &PciId);
      if (EFI_ERROR (Status)) {
        continue;
      }
      HWChange[Index++] = PciId;
    }
  }

  //
  // Locate FACP Table
  //
  Handle = 0;
  Status = LocateAcpiTableBySignature (
              EFI_ACPI_1_0_FIXED_ACPI_DESCRIPTION_TABLE_SIGNATURE,
              (EFI_ACPI_DESCRIPTION_HEADER **) &pFADT,
              &Handle
              );
  if (EFI_ERROR (Status) || (pFADT == NULL)) {
    return;  //Table not found or out of memory resource for pFADT table
  }

  //
  // add HWChange inputs: others
  //
  HWChange[Index++] = (UINT32)pFADT->XDsdt;

  //
  // Calculate CRC value with HWChange data.
  //
  Status = gBS->CalculateCrc32(HWChange, HWChangeSize, &CRC);
  DEBUG((DEBUG_INFO, "CRC = %x and Status = %r\n", CRC, Status));

  //
  // Set HardwareSignature value based on CRC value.
  //
  FacsPtr = (EFI_ACPI_2_0_FIRMWARE_ACPI_CONTROL_STRUCTURE *)(UINTN)pFADT->FirmwareCtrl;
  FacsPtr->HardwareSignature = CRC;
  FreePool( HWChange );
}

VOID
UpdateLocalTable (
  VOID
  )
{
  EFI_STATUS                    Status;
  EFI_ACPI_COMMON_HEADER        *CurrentTable;
  EFI_ACPI_TABLE_VERSION        Version;
  UINTN                         TableHandle;
  EFI_ACPI_TABLE_PROTOCOL       *AcpiTable;
  UINTN                         Index;

  Status = gBS->LocateProtocol (
                  &gEfiAcpiTableProtocolGuid,
                  NULL,
                  (VOID **)&AcpiTable
                  );

  for (Index = 0; Index < sizeof(mLocalTable)/sizeof(mLocalTable[0]); Index++) {
    CurrentTable = mLocalTable[Index];
  
      PlatformUpdateTables (CurrentTable, &Version);

      //
      // Add the table
      //
      TableHandle = 0;

      if (Version != EFI_ACPI_TABLE_VERSION_NONE) {
        Status = AcpiTable->InstallAcpiTable (
                              AcpiTable,
                              CurrentTable,
                              CurrentTable->Length,
                              &TableHandle
                              );
      }

      ASSERT_EFI_ERROR (Status);
  }
}


VOID
EFIAPI
AcpiEndOfDxeEvent (
  EFI_EVENT           Event,
  VOID                *ParentImageHandle
  )
{

  if (Event != NULL) {
    gBS->CloseEvent(Event);
  }


  //
  // Calculate Hardware Signature value based on current platform configurations
  //
  IsHardwareChange();
}

/**
  ACPI Platform driver installation function.

  @param[in] ImageHandle     Handle for this drivers loaded image protocol.
  @param[in] SystemTable     EFI system table.

  @retval EFI_SUCCESS        The driver installed without error.
  @retval EFI_ABORTED        The driver encountered an error and could not complete installation of
                             the ACPI tables.

**/
EFI_STATUS
EFIAPI
InstallAcpiPlatform (
  IN EFI_HANDLE         ImageHandle,
  IN EFI_SYSTEM_TABLE   *SystemTable
  )
{
  EFI_STATUS                    Status;
  EFI_EVENT                     EndOfDxeEvent;

  //
  // Create an End of DXE event.
  //
  Status = gBS->CreateEventEx (
                  EVT_NOTIFY_SIGNAL,
                  TPL_CALLBACK,
                  AcpiEndOfDxeEvent,
                  NULL,
                  &gEfiEndOfDxeEventGroupGuid,
                  &EndOfDxeEvent
                  );
  ASSERT_EFI_ERROR (Status);

  //
  // Update local table
  //
  UpdateLocalTable ();

  //
  // Finished
  //
  return EFI_SUCCESS;
}

/**
  Sort ordering of CPUs according to the priorities of cores and threads.
  ** ASSUMPTION: 1) single CPU package systsem wide; 2) two threads per core

  @param[in] MpService             The MP servicde protocol (used to retrievel MP info)
  @param[in] NumberOfCPUs          Number of CPUs
  @param[in] NumberOfEnabledCPUs   Number of Enabled CPUs.

  @retval EFI_SUCCESS              The driver installed without error.

**/
EFI_STATUS
SortCpuLocalApicInTable (
  IN  EFI_MP_SERVICES_PROTOCOL          *MpService,
  IN  UINTN                             NumberOfCPUs,
  IN  UINTN                             NumberOfEnabledCPUs
  )
{
  EFI_PROCESSOR_INFORMATION                 *MpContext;
  INTN                                      Index2;
  UINTN                                     Index1;
  UINTN                                     Index;
  UINT8                                     CpuThreadIndex;
  UINTN                                     BspIndex;
  UINT8                                     CurrProcessor;
  EFI_STATUS                                Status;
  UINT8                                     MaxCpuPackage;
  UINT8                                     MaxCpuCore;
  UINT8                                     MaxCpuThread;

  MpContext                     = NULL;
  MaxCpuPackage                 = 0;
  MaxCpuCore                    = 0;
  MaxCpuThread                  = 0;

  Status = MpService->WhoAmI (
                        MpService,
                        &BspIndex
                        );

  //
  // Fill mCpuApicIdOrderTable
  //
  for (CurrProcessor = 0; CurrProcessor < NumberOfCPUs; CurrProcessor++) {

    MpContext = AllocatePool (sizeof(EFI_PROCESSOR_INFORMATION));
    ASSERT (MpContext != NULL);
    Status = MpService->GetProcessorInfo (
                          MpService,
                          CurrProcessor,
                          MpContext
                          );
    ASSERT_EFI_ERROR (Status);

    if (MpContext == NULL) {
      return Status;
    }
    mCpuApicIdOrderTable[CurrProcessor].ApicId  = (UINT8) MpContext->ProcessorId;
    DEBUG((DEBUG_INFO, "The CurrProcessor 0x%x ApicId is 0x%x\n", CurrProcessor, mCpuApicIdOrderTable[CurrProcessor].ApicId));
    mCpuApicIdOrderTable[CurrProcessor].Flags   = (MpContext->StatusFlag | PROCESSOR_ENABLED_BIT)? 1: 0;
    mCpuApicIdOrderTable[CurrProcessor].Package = (UINT8) MpContext->Location.Package;
    mCpuApicIdOrderTable[CurrProcessor].Die     = (UINT8) 0;
    mCpuApicIdOrderTable[CurrProcessor].Core    = (UINT8) MpContext->Location.Core;
    mCpuApicIdOrderTable[CurrProcessor].Thread  = (UINT8) MpContext->Location.Thread;

    if (MaxCpuThread < (UINT8) MpContext->Location.Thread) {
      MaxCpuThread = (UINT8) MpContext->Location.Thread;
    }

    if (MaxCpuCore < (UINT8) MpContext->Location.Core) {
      MaxCpuCore = (UINT8) MpContext->Location.Core;
    }

    if (MaxCpuPackage < (UINT8) MpContext->Location.Package) {
      MaxCpuPackage = (UINT8) MpContext->Location.Package;
    }
  }

  //
  // Do some statistics about the SBSP package
  //
  for (CurrProcessor = 0; CurrProcessor < NumberOfCPUs; CurrProcessor++) {
    if (CurrProcessor == BspIndex) {
      mSbspPackageInfo.BspApicId = mCpuApicIdOrderTable[CurrProcessor].ApicId;
      mSbspPackageInfo.PackageNo   = mCpuApicIdOrderTable[CurrProcessor].Package;
      mSbspPackageInfo.TotalThreads = 0;
      mSbspPackageInfo.CoreNo = 0;
      mSbspPackageInfo.LogicalThreadNo = 0;
    }
  }

  for (CurrProcessor = 0; CurrProcessor < NumberOfCPUs; CurrProcessor++) {
    if (mCpuApicIdOrderTable[CurrProcessor].Package == mSbspPackageInfo.PackageNo) {
      mSbspPackageInfo.TotalThreads++;
      if (mCpuApicIdOrderTable[CurrProcessor].Thread == 0) {
        mSbspPackageInfo.CoreNo++;
      } else {
        mSbspPackageInfo.LogicalThreadNo++;
      }
    }
  }

  //
  // Output debug info
  //
  for (Index = 0; Index < NumberOfCPUs; Index++) {
    DEBUG((DEBUG_INFO, "Package = %x,  Die = %x,  Core = %x,  Thread = %x,  ApicId = %x\n", \
      mCpuApicIdOrderTable[Index].Package, \
      mCpuApicIdOrderTable[Index].Die, \
      mCpuApicIdOrderTable[Index].Core, \
      mCpuApicIdOrderTable[Index].Thread, \
      mCpuApicIdOrderTable[Index].ApicId));
  }

  DEBUG((DEBUG_INFO, "MaxCpuPackage = %x\n", MaxCpuPackage));
  DEBUG((DEBUG_INFO, "MaxCpuCore    = %x\n", MaxCpuCore));
  DEBUG((DEBUG_INFO, "MaxCpuThread    = %x\n\n", MaxCpuThread));
  DEBUG((DEBUG_INFO, "mSbspPackageInfo.BspApicId        = %x\n", mSbspPackageInfo.BspApicId));
  DEBUG((DEBUG_INFO, "mSbspPackageInfo.TotalThreads     = %x\n", mSbspPackageInfo.TotalThreads));
  DEBUG((DEBUG_INFO, "mSbspPackageInfo.PackageNo        = %x\n", mSbspPackageInfo.PackageNo));
  DEBUG((DEBUG_INFO, "mSbspPackageInfo.CoreNo           = %x\n", mSbspPackageInfo.CoreNo));
  DEBUG((DEBUG_INFO, "mSbspPackageInfo.LogicalThreadNo  = %x\n", mSbspPackageInfo.LogicalThreadNo));

  //
  // First entry is always SBSP
  //
  CurrProcessor = 0;
  mCpuApicIdReorderTable[CurrProcessor].ApicId = mSbspPackageInfo.BspApicId;
  mCpuApicIdReorderTable[CurrProcessor].Package = mSbspPackageInfo.PackageNo;
  mCpuApicIdReorderTable[CurrProcessor].Flags = 1;
  CurrProcessor++;

  //
  // Reorder Core and threads
  //
  for (Index2 = -1; Index2 <= MaxCpuPackage; Index2 ++) {
    INTN PackageIndex;

    PackageIndex = Index2;
    if (Index2 == -1) {
      // add Sbsp as first
      PackageIndex = mSbspPackageInfo.PackageNo;
    } else if (Index2 == mSbspPackageInfo.PackageNo) {
      // Skip Sbsp
      continue;
    }
    for (Index1 = 0; Index1 <= MaxCpuThread; Index1 ++) {
      for (Index = 0; Index <= MaxCpuCore; Index++) {
        for (CpuThreadIndex = 0; CpuThreadIndex < NumberOfCPUs; CpuThreadIndex++) {
          if ((mCpuApicIdOrderTable[CpuThreadIndex].Package == PackageIndex) &&
              (mCpuApicIdOrderTable[CpuThreadIndex].Thread == Index1) &&
              (mCpuApicIdOrderTable[CpuThreadIndex].Core == Index) &&
              (mCpuApicIdOrderTable[CpuThreadIndex].ApicId != mCpuApicIdReorderTable[0].ApicId)) {
            mCpuApicIdReorderTable[CurrProcessor].ApicId = mCpuApicIdOrderTable[CpuThreadIndex].ApicId;
            mCpuApicIdReorderTable[CurrProcessor].Package = (UINT8)PackageIndex;
            mCpuApicIdReorderTable[CurrProcessor].Flags = mCpuApicIdOrderTable[CpuThreadIndex].Flags;
            CurrProcessor++;
            break;
          }
        }
      }
    }
  }

  //
  // Output debug info
  //
  for (Index = 0; Index < NumberOfCPUs; Index++) {
    DEBUG((DEBUG_INFO, "Index = %x,  ApicId = %x,  Package = %x\n", \
      Index, \
      mCpuApicIdReorderTable[Index].ApicId, \
      mCpuApicIdReorderTable[Index].Package));
  }

  FreePool (MpContext);

  return  EFI_SUCCESS;
}


EFI_STATUS
AppendCpuMapTableEntry (
  IN  EFI_ACPI_1_0_PROCESSOR_LOCAL_APIC_STRUCTURE   *AcpiLocalApic,
  IN  UINTN                                         NumberOfCPUs,
  IN  UINTN                                         NumberOfEnabledCPUs,
  IN  UINT8                                         LocalApicCounter
  )
{
  if (LocalApicCounter < NumberOfCPUs) {
    AcpiLocalApic->Flags           = mCpuApicIdReorderTable[LocalApicCounter].Flags;
    AcpiLocalApic->ApicId          = mCpuApicIdReorderTable[LocalApicCounter].ApicId;
    //
    // Make AcpiProcessorIds 1-based, matching the ones in Processor() definitions
    //
    AcpiLocalApic->AcpiProcessorId = LocalApicCounter + 1;
  } else {
    AcpiLocalApic->Flags           = 0;
    AcpiLocalApic->ApicId          = 0xFF;
    //
    // Make AcpiProcessorIds 1-based, matching the ones in Processor() definitions
    //
    AcpiLocalApic->AcpiProcessorId = LocalApicCounter + 1;
  }

  //
  // Display the results
  //
  DEBUG((DEBUG_INFO, "AcpiLocalApic: AcpiProcessorId=%x, ApicId=%x, Flags=%x\n", \
  AcpiLocalApic->AcpiProcessorId, \
  AcpiLocalApic->ApicId, \
  AcpiLocalApic->Flags));

  return EFI_SUCCESS;
}
