========================================
Project Mu Intel Common MinPlatform Repo
========================================

============================= ================= =============== ===================
 Host Type & Toolchain        Build Status      Test Status     Code Coverage
============================= ================= =============== ===================
Windows_VS2022_               |WindowsCiBuild|  |WindowsCiTest| |WindowsCiCoverage|
Ubuntu_GCC5_                  |UbuntuCiBuild|   |UbuntuCiTest|  |UbuntuCiCoverage|
============================= ================= =============== ===================

This repository is a restructuring of open packages contributed by Intel.

It is organized so that common code can be made available to any platform with minimal difficulty.

This repository is part of Project Mu.  Please see Project Mu for details https://microsoft.github.io/mu

Branch Status - release/202208
==============================

:Status:
  In Development

:Entered Development:
  September 2022

:Anticipated Stabilization:
  November 2022

Branch Changes - release/202208
===============================

Breaking Changes-dev
--------------------

- None

Main Changes-dev
----------------

- None

Bug Fixes-dev
-------------

- None

2208_RefBoot Changes
--------------------

- Incomplete

2208_CIBuild Changes
--------------------

- Incomplete

2208_Rebase Changes
-------------------

| Starting commit: 7d2732a6 ("pip: update edk2-pytool-extensions requirement from ~=0.17.2 to ~=0.18.0", 2022-09-15)
| Destination commit: 5d93559d ("MinPlatformPkg: Add PcdAcpiGpe1BlockLength for FADT from board package", 2022-08-15)

Repo Maintenance
================

Upstream Sync Details
---------------------

- edk2_platforms - 3c3b116801 ("Maintainers.txt: Update maintainers list for edk2-platforms", 2022-08-25)

Instructions
------------

This repo is a composite repo of packages from 'edk2-platforms'. To maintain it simply, we have established an 'upstream' branch to track the current state of things. To take a new integration, follow the steps below:

First go to a local copy of edk2-platforms and dump all patches since the last upstream sync (see `Upstream Sync Details`_)::

  # In edk2-platforms...
  git format-patch <last_sync_commit>..<new_sync_commit> -- Platform/Intel/MinPlatformPkg

Then apply them to the 'upstream' branch in this repo while modifying the path length (to bring things to the top level)::

  # -p 3 will drop 3 path elements, including 'a' or 'b' off the diff path.
  git am -p 3 ../../edk2-platforms/*.patch

Make sure to update the `Upstream Sync Details`_ once done.

To perform an integration, simply set your XXXX_Upstream tag to the top of 'upstream' and rebase as normal. Make sure to push 'upstream' to the server after integration, along with new release branch.

Code of Conduct
===============

This project has adopted the Microsoft Open Source Code of Conduct https://opensource.microsoft.com/codeofconduct/

For more information see the Code of Conduct FAQ https://opensource.microsoft.com/codeofconduct/faq/
or contact `opencode@microsoft.com <mailto:opencode@microsoft.com>`_. with any additional questions or comments.

Contributions
=============

Contributions are always welcome and encouraged!
Please open any issues in the Project Mu GitHub tracker and read https://microsoft.github.io/mu/How/contributing/


Copyright & License
===================

| Copyright (C) Microsoft Corporation
| SPDX-License-Identifier: BSD-2-Clause-Patent

Upstream License (TianoCore)
============================

Copyright (c) 2019, TianoCore and contributors.  All rights reserved.

SPDX-License-Identifier: BSD-2-Clause-Patent

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:

1. Redistributions of source code must retain the above copyright notice,
   this list of conditions and the following disclaimer.

2. Redistributions in binary form must reproduce the above copyright notice,
   this list of conditions and the following disclaimer in the documentation
   and/or other materials provided with the distribution.

Subject to the terms and conditions of this license, each copyright holder
and contributor hereby grants to those receiving rights under this license
a perpetual, worldwide, non-exclusive, no-charge, royalty-free, irrevocable
(except for failure to satisfy the conditions of this license) patent
license to make, have made, use, offer to sell, sell, import, and otherwise
transfer this software, where such license applies only to those patent
claims, already acquired or hereafter acquired, licensable by such copyright
holder or contributor that are necessarily infringed by:

(a) their Contribution(s) (the licensed copyrights of copyright holders and
    non-copyrightable additions of contributors, in source or binary form)
    alone; or

(b) combination of their Contribution(s) with the work of authorship to
    which such Contribution(s) was added by such copyright holder or
    contributor, if, at the time the Contribution is added, such addition
    causes such combination to be necessarily infringed. The patent license
    shall not apply to any other combinations which include the
    Contribution.

Except as expressly stated above, no rights or licenses from any copyright
holder or contributor is granted under this license, whether expressly, by
implication, estoppel or otherwise.

DISCLAIMER

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDERS OR CONTRIBUTORS BE
LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
POSSIBILITY OF SUCH DAMAGE.

.. ===================================================================
.. This is a bunch of directives to make the README file more readable
.. ===================================================================

.. CoreCI

.. _Windows_VS2022: https://dev.azure.com/projectmu/mu/_build/latest?definitionId=71&&branchName=release%2F202208
.. |WindowsCiBuild| image:: https://dev.azure.com/projectmu/mu/_apis/build/status/CI/Mu%20Common%20Intel%20MinPlatform%20CI%20VS2022?branchName=release%2F202208
.. |WindowsCiTest| image:: https://img.shields.io/azure-devops/tests/projectmu/mu/71.svg
.. |WindowsCiCoverage| image:: https://img.shields.io/badge/coverage-coming_soon-blue

.. _Ubuntu_GCC5: https://dev.azure.com/projectmu/mu/_build/latest?definitionId=72&branchName=release%2F202202
.. |UbuntuCiBuild| image:: https://dev.azure.com/projectmu/mu/_apis/build/status/CI/Mu%20Common%20Intel%20MinPlatform%20CI%20Ubuntu%20GCC5?branchName=release%2F202202
.. |UbuntuCiTest| image:: https://img.shields.io/azure-devops/tests/projectmu/mu/72.svg
.. |UbuntuCiCoverage| image:: https://img.shields.io/badge/coverage-coming_soon-blue
