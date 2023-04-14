# Nextcloud Antivirus for Files
[![Build Status](https://travis-ci.org/nextcloud/files_antivirus.svg?branch=master)](https://travis-ci.org/nextcloud/files_antivirus/branches)
[![Scrutinizer Code Quality](https://scrutinizer-ci.com/g/nextcloud/files_antivirus/badges/quality-score.png?b=master)](https://scrutinizer-ci.com/g/nextcloud/files_antivirus/?branch=master)
[![Code Coverage](https://scrutinizer-ci.com/g/nextcloud/files_antivirus/badges/coverage.png?b=master)](https://scrutinizer-ci.com/g/nextcloud/files_antivirus/?branch=master)

`files_antivirus` **is an antivirus app for [Nextcloud](https://nextcloud.com/) using [ClamAV](http://www.clamav.net) or Kaspersky.**

![](https://raw.githubusercontent.com/nextcloud/files_antivirus/master/screenshots/1.png)

## Features

* :chipmunk: When the user uploads a file, it's checked
* :biohazard: Infected files will be deleted and a notification will be shown and/or sent via email 
* :mag_right: It runs a background job to scan all files
* :safety_vest: It will block all uploads if the file cannot be checked to ensure all files are getting scanned.

## Requirements

One of

* ClamAV as binaries on the Nextcloud server
* ClamAV running in daemon mode
* Kaspersky Scan Engine running in HTTP mode
* Any virus scanner supporting ICAP (ClamAV and Kaspersky are tested, others *should* work)

## Install

Documentation about installing ClamAV and this app can be found in [our documentation](https://docs.nextcloud.com/server/latest/admin_manual/configuration_server/antivirus_configuration.html).

## ClamAV Details

This app can be configured to work with the executable or the daemon mode (recommended :heart:) of ClamAV. If this is used in daemon mode, it can connect through network or local file-socket. In daemon mode, it sends files to a remote/local server using the `INSTREAM` command.

## Kaspersky HTTP Details

When running Kaspersky in HTTP mode the [`SessionTimeout`](https://support.kaspersky.com/ScanEngine/2.1/en-US/201030.htm) will need to be set to a value higher than default, a value of 10 minutes (600000 millisecond) or higher is recommended to properly deal with larger uploads

## ICAP (version 5.0 and later)

The app support the ICAP protocol which is a standard supported by various antivirus software products.

Some additional configuration is required depending on the antivirus software used:

- ICAP service: The name of the service the antivirus software expects
- ICAP virus response header: The name of the header the antivirus software send the details of the detected virus in

### ClamAV ICAP

- ICAP service: `avscan`
- ICAP virus response header: `X-Infection-Found`

### Kaspersky ICAP

- ICAP service: `req`
- ICAP virus response header: `X-Virus-ID`

Additionally, the Kaspersky scan engine needs some additional configuration:

- ["Allow204"](https://support.kaspersky.com/ScanEngine/1.0/en-US/201151.htm) should be enabled.
- For version 2.0 and later, the [virus response header](https://support.kaspersky.com/ScanEngine/1.0/en-US/201214.htm) needs to be configured
