# PSVVX

PowerShell module for Polycom VVX devices

## Description

PowerShell module for Polycom VVX devices

## Introduction

The Polycom VVX series devices have a RESTful interface. This module takes advantage of that to simplify scripting against a fleet of such devices if you need to do so.

## Requirements

I wrote and tested this with PowerShell 5 but 3 or 4 will probably work just fine. Most of the script ideas were pulled from [this script](http://www.myskypelab.com/2015/10/skype-for-business-lync-polycom-vvx.html) and all of the same device requirements listed therin will apply here as well.

If passing credentials for admin then use the default admin user of 'Polycom'.

## Installation

Powershell Gallery (PS 5.0, Preferred method)
`install-module PSVVX`

Manual Installation
`iex (New-Object Net.WebClient).DownloadString("https://github.com/zloeber/psvvx/raw/master/Install.ps1")`

Or clone this repository to your local machine, extract, go to the .\releases\PSVVX directory
and import the module to your session to test, but not install this module.

## Features

- A simple mechanism to script a wide range of activities against Polycom VVX phones
- Abstraction of several common phone tasks.
- More to come, the base function can be used for almost any task though.

## Versions

0.0.1 - Initial Release

## Contribute

Please feel free to contribute by opening new issues or providing pull requests.
For the best development experience, open this project as a folder in Visual
Studio Code and ensure that the PowerShell extension is installed.

* [Visual Studio Code]
* [PowerShell Extension]


## Other Information

**Author:** Zachary Loeber

**Website:** https://github.com/zloeber/psvvx

