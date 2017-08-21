# TODO
This file lists some work items that we have identified,
with some current bugs too

## Core
	[ ] Add a link relationship between dropper/dropped samples
	[ ] x86/x64 emulation
	[ ] Manage plugins in config

## Analysis tasks
	[ ] Resources / overlay extraction
	[ ] Section hashing/matching
	[ ] file carving
	[ ] xor bruteforce
	[ ] Parse authenticode signatures (metadata)

## API
	[ ] In the disassembly view, change the ugly JS to a proper Jquery UI, wich will get/post on the API to get names/comments
	[ ] Change the JS UI to pop the window for comments/name on the right place
	[ ] Retrieve function names by machoc hash
	[ ] Return a correct error if failing to add sample with the API

## Views
	[ ] Problems (unassociated yaras, alone machoc, false positives, ...)
	[ ] User management (creation, logs, etc)
	[ ] Executive overview (family progress, who worked on what at this time?, ...)
	[ ] Add a tag "packed"
	[ ] Display the exports names by sample

## Skelenox
	[ ] Function identification by machoc hash
	[ ] Highlight cryptoblocks
	[ ] Local names (prefix) are not pushed.
	[ ] Make difference between regular comments and RptCmts
	[ ] Hook for segments / structs / enums etc
	[ ] Integrates with HexRays decompiler
	[ ] Put the coms/names blacklist in a config file
	[ ] Make the proposed names view clickable

## Tests
	The tests are far from complete, so more tests are needed

## Others
	[ ] Machine learning tools that use the metadata presented via the API
	[ ] autodeployment tools
	[ ] Make an export module that can speak to other tools (eg MISP, Viper, ...)

# Known bugs
	[ ] If we kill an analysis (when restarting service for example), we cannot reschedule it
	[ ] The disassembly view does not check if the disassembly svg is empty
	[ ] Even when the user have uncategorized sample, the view doesn't hilight it
	[ ] IDA Actions are not attributed to a user
