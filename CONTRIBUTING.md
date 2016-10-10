# Contributing to Polichombr
You are welcome to contribute to the Polichombr framework!
This document provides some guidelines on how to report issues
or open pull requests for this repository.

## Found an Issue?
s this software is still in a pre-release state,
bugs are presents in the codebase. If you find something that might need a fix or require special attention,
please open an Issue describing precisely where the bug is, and what lead to it's discovery.

## Want a feature?
Please open an issue describing the feature that is missing for your use case,
or directly open a pull request with your changes

## Want some help?
If the documentation in [docs](https://github.com/ANSSI-FR/polichombr/tree/master/docs)
is not sufficient, please open an Issue describing your problem so we can provide some insight.
Afterwards, you are welcome to improve the documentation!

## Want to get started in the code?
If you want to write scripts that uses the Polichombr API, a `Python` module
can be imported in [poliapi](https://github.com/ANSSI-FR/polichombr/tree/master/poliapi).

If you want to take a peek in the core, please have a look at the [TODO.md](https://github.com/ANSSI-FR/polichombr/tree/master/docs/TODO.md)
file for finding things to improve, or look for open issues to be resolved

## Submitting a Pull Request
You are welcome to open pull request against the `dev` branch for
new features!
Below are some guidelines that you can use to create appropriate pull requests.

 * First clone the repository

 * Create a separated branch
	```shell
	git checkout -b my-fix-branch dev
	```

 * Make your patches and the appropriates test cases

 * Verify that your build pass the tests
	```shell
	python -m unittest discover tests
	```

 * Push your changes to Github:
	```shell
	git push origin my-fix-branch
	```

 * On Github, open a pull request against `polichombr:dev`
We will then review your changes, and if the review is correct we will merge it.

## Coding style
Every new API endpoint or functionality should be tested,
and `pep8` coding guidelines applies.
