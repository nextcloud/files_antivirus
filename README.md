# Nextcloud Antivirus App   

files_antivirus is an antivirus app for [Nextcloud](https://github.com/nextcloud) based on [ClamAV](http://www.clamav.net).

##Details

The idea is to check for virus at upload-time, notifying the user (on screen and/or email) and
remove the file if it's infected.

## QA metrics on master branch:

[![Build Status](https://travis-ci.org/nextcloud/files_antivirus.svg?branch=master)](https://travis-ci.org/nextcloud/files_antivirus/branches)
[![Scrutinizer Code Quality](https://scrutinizer-ci.com/g/nextcloud/files_antivirus/badges/quality-score.png?b=master)](https://scrutinizer-ci.com/g/nextcloud/files_antivirus/?branch=master)
[![Code Coverage](https://scrutinizer-ci.com/g/nextcloud/files_antivirus/badges/coverage.png?b=master)](https://scrutinizer-ci.com/g/nextcloud/files_antivirus/?branch=master)

## QA metrics on stable8 branch:

[![Build Status](https://travis-ci.org/nextcloud/files_antivirus.svg?branch=stable8)](https://travis-ci.org/nextcloud/files_antivirus/branches)
[![Scrutinizer Code Quality](https://scrutinizer-ci.com/g/nextcloud/files_antivirus/badges/quality-score.png?b=stable8)](https://scrutinizer-ci.com/g/nextcloud/files_antivirus/?branch=stable8)
[![Code Coverage](https://scrutinizer-ci.com/g/nextcloud/files_antivirus/badges/coverage.png?b=stable8)](https://scrutinizer-ci.com/g/nextcloud/files_antivirus/?branch=stable8)

##Status

The App is not complete yet, the following works/is done:
* It can be configured to work with the executable or the daemon mode of ClamAV
* If used in daemon mode it can connect through network- or local file-socket
* In daemon mode, it sends files to a remote/local server using INSTREAM command
* When the user uploads a file, it's checked
* If an uploaded file is infected, it's deleted and a notification is shown to the user on screen and an email is sent with details.
* Tested in Linux only
* Background Job to scan all files

##In progress

* Test uploading from clients

##ToDo

* File size limit
* Configurations Tuneups
* Other OS Testing
* Look for ideas :P

## Requirements

* Nextcloud 10
* ClamAV (Binaries or a server running ClamAV in daemon mode)


## Install

* Install and enable the App
* Go to Admin Panel and configure the App


Authors:

[Manuel Delgado López](https://github.com/valarauco/) :: manuel.delgado at ucr.ac.cr  
[Bart Visscher](https://github.com/bartv2/)
