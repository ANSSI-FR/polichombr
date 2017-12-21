# Polichombr

[![Build Status](https://travis-ci.org/ANSSI-FR/polichombr.svg?branch=master)](https://travis-ci.org/ANSSI-FR/polichombr)
[![Maintainability](https://api.codeclimate.com/v1/badges/b78688130c309307618f/maintainability)](https://codeclimate.com/github/ANSSI-FR/polichombr/maintainability)
[![Test Coverage](https://api.codeclimate.com/v1/badges/b78688130c309307618f/test_coverage)](https://codeclimate.com/github/ANSSI-FR/polichombr/test_coverage)

This tool aim to provide a collaborative malware analysis framework.
It was originally presented at [SSTIC 2016](https://www.sstic.org/2016/presentation/demarche_d_analyse_collaborative_de_codes_malveillants/),


# Documentation
A more detailled documentation is placed in the `docs` folder

## Analysis platform
Polichombr is designed to help analysts to reverse malwares, as a team.
It provides an engine to automate the analysis tasks,
and identify hotpoints in the binary, a script to collaborate during the reverse of binaries,
and can be used to store and manage informations about malware families.

### Example scripts
Scripts under the folder [examples](https://github.com/ANSSI-FR/polichombr/tree/master/examples)
permits some basic actions for a Polichombr instance.

### Generic sample informations 
![screenshot](docs/screenshots/screen_sample_view.png)

### Family/Threat overview
![screenshot](docs/screenshots/screen_family_view.png)


### Online disassembly
![screenshot](docs/screenshots/screen_disass.png)


### Share IDA Pro informations from the WebUI / directly to other users
![screenshot](docs/screenshots/screen_names.png)

### Automated hotpoints detection 
![screenshot](docs/screenshots/screen_analyzeit.png)

### Taking notes right from IDA
![screenshot](docs/screenshots/ida_abstract.png)

### Plugins / tasks
Tasks are loaded from the app/controllers/tasks directory, and must inherit from the Task object.
In particular, several tasks are already implemented:
 * AnalyzeIt, a ruby script based on metasm, wich is used to identify interesting points in the binary.
   The goal is to help the analyst by giving hints about where to start. For example,
   we try to identify crypto loops, functions wich calls sensitive API (file, process, network, ...)

 * Peinfo : We load the PE metadata with the peinfo library.
 * Strings : extract ASCII and Unicode strings

### Signatures
We use several signature models to classify malware:
 * Yara
 * imphash
 * Machoc

### Machoc
Machoc is a CFG-based algorithm to classify malware.
For more informations, please refer to the following [paper] (https://www.sstic.org/media/SSTIC2016/SSTIC-actes/demarche_d_analyse_collaborative_de_codes_malveill/SSTIC2016-Article-demarche_d_analyse_collaborative_de_codes_malveillants-chevalier_le-berre_pourcelot.pdf)

## Skelenox
This is an IDAPython script, wich is used to synchronize the names and comments
with the knowledge base, and with other users database

# Installation
Please see the corresponding file in the [docs](https://github.com/ANSSI-FR/polichombr/tree/master/docs) directory

# Contributing
Contributions are welcome, so please read [CONTRIBUTING.md](https://github.com/ANSSI-FR/polichombr/blob/master/CONTRIBUTING.md)
to have a quick start on how to get help or add features in Polichombr
