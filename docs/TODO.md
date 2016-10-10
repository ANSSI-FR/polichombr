# TODO
This file lists some work items that we have identified,
with some current bugs too

## Core
	[ ] Add a link relationship between dropper/dropped samples
	[ ] x86/x64 emulation

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
	[x] Implement an API class that could be used by scripts (à la PyMISP)

## Views
	[ ] Problems (unassociated yaras, alone machoc, false positives, ...)
	[ ] User management (creation, logs, etc)
	[ ] Executive overview (family progress, who worked on what at this time?, ...)
	[ ] Add a tag "packed"
	[ ] Display the exports names by sample

## Skelenox
	[ ] Manage timestamp
	[ ] Function identification by machoc hash
	[ ] Highlight cryptoblocks
	[x] Fix upload of sample if it is new
	[ ] Fix note pad destruction when calling exit_skelenox
	[x] Proper logging
	[ ] Local names (prefix) are not pushed.
	[ ] Make difference for comments
	[ ] Hook for segments / structs / enums etc
	[ ] Integrates with HexRays decompiler

## Tests
	The tests are far from complete, so more tests are needed

## Others
	[ ] Machine learning tools that use the metadata presented via the API
	[ ] autodeployment tools
	[ ] Make an export module that can speak to other tools (eg MISP, Viper, ...)

# Known bugs
	[ ] If we kill an analysis (when restarting service for example), we cannot reschedule it
	[ ] The disassembly view does not check if the disassembly svg is empty
	[x] Date file is buggy (not displaying the hour?)
	[ ] Even when the user have uncategorized sample, the view doesn't hilight it
	[ ] IDA Actions are not attributed to a user
	[x] When reopening a sample in IDA, skelenox does not take that in account
