# Nextcloud Antivirus for Files
[![Build Status](https://travis-ci.org/nextcloud/files_antivirus.svg?branch=master)](https://travis-ci.org/nextcloud/files_antivirus/branches)
[![Scrutinizer Code Quality](https://scrutinizer-ci.com/g/nextcloud/files_antivirus/badges/quality-score.png?b=master)](https://scrutinizer-ci.com/g/nextcloud/files_antivirus/?branch=master)
[![Code Coverage](https://scrutinizer-ci.com/g/nextcloud/files_antivirus/badges/coverage.png?b=master)](https://scrutinizer-ci.com/g/nextcloud/files_antivirus/?branch=master)

`files_antivirus` **is an antivirus app for [Nextcloud](https://nextcloud.com/) using [ClamAV](http://www.clamav.net).**

![](https://raw.githubusercontent.com/nextcloud/files_antivirus/master/screenshots/1.png)

## Features

* When the user uploads a file, it's checked
* ☢️ Infected files will be deleted and a notification will be shown and/or sent via email 
* It runs a background job to scan all files

## What is planned

* File size limit
* Configuration Tuneups
* Wider OS testing
* Looking for ideas

## Requirements

* Nextcloud 12 or 13
* ClamAV as binaries or as server running ClamAV in daemon mode (recommended ❤️)

## Install

Documentation about installing ClamAV and this app can be found in [our documentation](https://docs.nextcloud.com/server/13/admin_manual/configuration_server/antivirus_configuration.html).

## Details

This app can be configured to work with the executable or the daemon mode (recommended ❤️) of ClamAV. If this is used in daemon mode it can conntect through network- or local file-socket. In daemon mode, it sends files to a remote/local server using `INSTREAM`-command.

## Maintainers:

- [Roeland Jago Douma](https://github.com/rullzer)

**Past contributors:**

- [Manuel Delgado López](https://github.com/valarauco/)
- [Bart Visscher](https://github.com/bartv2/)
