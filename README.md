# Nextcloud Antivirus App   

files_antivirus is an antivirus app for [Nextcloud](https://github.com/nextcloud) based on [ClamAV](http://www.clamav.net).

## Details

The idea is to check for virus at upload-time, notifying the user (on screen and/or email) and
remove the file if it's infected.

## QA metrics on master branch:

[![Build Status](https://travis-ci.org/nextcloud/files_antivirus.svg?branch=master)](https://travis-ci.org/nextcloud/files_antivirus/branches)
[![Scrutinizer Code Quality](https://scrutinizer-ci.com/g/nextcloud/files_antivirus/badges/quality-score.png?b=master)](https://scrutinizer-ci.com/g/nextcloud/files_antivirus/?branch=master)
[![Code Coverage](https://scrutinizer-ci.com/g/nextcloud/files_antivirus/badges/coverage.png?b=master)](https://scrutinizer-ci.com/g/nextcloud/files_antivirus/?branch=master)

## Status

The App currently has the following features:
* It can be configured to work with the executable or the daemon mode of ClamAV
* If used in daemon mode (recommended) it can connect through network- or local file-socket
* In daemon mode, it sends files to a remote/local server using INSTREAM command
* When the user uploads a file, it's checked
* If an uploaded file is infected, it's deleted and a notification is shown to the user on screen and an email is sent with details.
* Background Job to scan all files

## ToDo

* File size limit
* Configurations Tuneups
* Wider OS Testing
* Look for ideas :P

## Requirements

* Nextcloud 12 or 13
* ClamAV (Binaries or a server running ClamAV in daemon mode <- we recommend to do that)


## Install

* Install and enable the App
* Go to Admin Panel and configure the App


Authors:

[Manuel Delgado López](https://github.com/valarauco/) :: manuel.delgado at ucr.ac.cr  
[Bart Visscher](https://github.com/bartv2/)
