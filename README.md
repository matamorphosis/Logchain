# Logchain
[![License: GPL v3](https://img.shields.io/badge/License-GPLv3-blue.svg)](https://www.gnu.org/licenses/gpl-3.0)  

<p align="center">
  <img width="150" height="150" src="/lib/Logchain.png">
</p>

Logchain is a log backup tool that uses distributed ledger technology (DLT, also commonly known as blockchain) for integrity purposes. This solution is compiled of three programs:
 - Ledger API
 - Backup Agent
 - Verification Agent

Both agents should be installed on **any** server that you wish to backup logs for. The Ledger API, which includes a ledger and the API to access it, can be installed on as many servers as the user would like. Both the technical design of the ledger and the concept of DLT means that only one ledger should be installed on a server at any given time. If you really want to save money on infrastructure, docker is the recommended solution.

For further information, please refer to the Wiki [here](https://github.com/matamorphosis/Logchain/wiki/Installation)
