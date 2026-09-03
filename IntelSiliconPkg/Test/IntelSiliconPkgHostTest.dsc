## @file
# IntelSiliconPkg DSC file used to build host-based unit tests.
#
# Copyright (c) Microsoft Corporation.
# SPDX-License-Identifier: BSD-2-Clause-Patent
#
##

[Defines]
  PLATFORM_NAME           = IntelSiliconPkgHostTest
  PLATFORM_GUID           = 32ACFCB9-D37D-4203-BEBB-FB66EF00E113
  PLATFORM_VERSION        = 0.1
  DSC_SPECIFICATION       = 0x00010005
  OUTPUT_DIRECTORY        = Build/IntelSiliconPkg/HostTest
  SUPPORTED_ARCHITECTURES = IA32|X64
  BUILD_TARGETS           = NOOPT
  SKUID_IDENTIFIER        = DEFAULT

!include UnitTestFrameworkPkg/UnitTestFrameworkPkgHost.dsc.inc

[Components]
  IntelSiliconPkg/Library/BaseFitQueryLib/UnitTest/BaseFitQueryLibUnitTest.inf {
    <LibraryClasses>
      FitQueryLib|IntelSiliconPkg/Library/BaseFitQueryLib/BaseFitQueryLib.inf
  }

[BuildOptions]
  MSFT:NOOPT_*_*_CC_FLAGS   = -DINTERNAL_UNIT_TEST      # cspell:disable-line
  GCC:NOOPT_*_*_CC_FLAGS    = -DINTERNAL_UNIT_TEST      # cspell:disable-line
