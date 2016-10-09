# Contributing to Needle

:+1::tada: First off, thanks for taking the time to contribute! :tada::+1:

The following is a set of guidelines for contributing to Needle, which is hosted in the [MWRLabs Organization](https://github.com/mwrlabs) on GitHub.

These are just guidelines, not rules, use your best judgment and feel free to propose changes to this document in a pull request.



## What should I know before I get started?

### Needle Architecture

Needle is an open source project, designed to be highly-modular. Needle is indeed easily extensible and new modules can be added in the form of python scripts.

When you initially consider contributing to it, you might be unsure about which of those components implements the functionality you want to change or report a bug for.
This section should help you with that.

To get a sense for the components that compose Needle, here's a list that explains each one's task:

```
needle
|-- core                                    
|   |-- device                              
|   |   |-- app.py                          [wrapper for managing installed apps]
|   |   |-- device.py                       [manage connection with the device & basic commands]
|   |   |-- installer.py                    [install all the tools/dependencies needed on the device]
|   |   `-- remote_operations.py            [APIs to interact with the remote OS]
|   |-- framework                           
|   |   |-- cli.py                          [command line interface for Needle, the UI]
|   |   |-- framework.py                    [init and manage all the other components]
|   |   |-- local_operations.py             [APIs to interact with the local OS]
|   |   |-- module.py                       [base class, inherited by module's implementations]
|   |   `-- options.py                      [wrapper for the global/local options]
|   `-- utils
|       |-- constants.py                    [global constants for the framework]
|       |-- __init__.py
|       |-- menu.py                         [show menus to the user]
|       |-- printer.py                      [provides logging]
|       `-- utils.py                        [various utils (path manipulation, escaping, etc)]
|-- libs                                    [dependencies that needs to be bundled within Needle]
`-- modules                                 [collection of features, in the form of python scripts]
```

### APIs

As mentioned in the section above, the framework core exposes APIs to interact with the local and remote OS.
These APIs wraps common functionalities, like file and data access, command execution, networking.

A high-level view of the design is shown in the following image:

![](https://labs.mwrinfosecurity.com/assets/BlogFiles/Needle/api-design.png)


### Module Templates

Needle supports multiple kinds of modules, each type developed for a particular use case.
Templates for each type of module are provided in the `modules/_templates` folder:

Template                 | Type
------------- 	         | ------------- 	 	
`BaseModule`             | Standard module
`BackgroundModule`       | To be used for background processes (jobs)
`DebugModule`            | To be used for modules relying on LLDB
`FridaModule`            | To be used for modules relying on Frida
`FridaScript`            | To be used for modules that just needs to execute a JS payload
`StaticModule`           | To be used for modules that do not require a connection with the device







## How Can I Contribute?

### Reporting Bugs

This section guides you through submitting a bug report for Needle. Following these guidelines helps maintainers and the community understand your report :pencil:, reproduce the behavior :computer: :computer:, and find related reports :mag_right:.

When you are creating a bug report, please [include as many details as possible](#how-do-i-submit-a-good-bug-report). If you'd like, you can use [this template](#template-for-submitting-bug-reports) to structure the information.


#### How Do I Submit A (Good) Bug Report?

Bugs are tracked as [GitHub issues](https://guides.github.com/features/issues/). After you've determined [which component](#needle-architecture) your bug is related to, create an issue and provide the following information.

Explain the problem and include additional details to help maintainers reproduce the problem:

* _Use a clear and descriptive title_ for the issue to identify the problem.
* _Describe the exact steps which reproduce the problem_ in as many details as possible.
* _Provide specific examples to demonstrate the steps_. Include links to files or GitHub projects, or copy/pasteable snippets, which you use in those examples. If you're providing snippets in the issue, use [Markdown code blocks](https://help.github.com/articles/markdown-basics/#multiple-lines).
* _Describe the behavior you observed after following the steps_ and point out what exactly is the problem with that behavior.
* _Explain which behavior you expected to see instead and why._
* _Include screenshots and animated GIFs_ which show you following the described steps and clearly demonstrate the problem.
* _If the problem wasn't triggered by a specific action_, describe what you were doing before the problem happened and share more information using the guidelines below.

#### Template For Submitting Bug Reports

```
## Issue

### Expected behaviour
Tell us what should happen.

### Actual behaviour
Tell us what happens instead.

### Steps to reproduce
1.
2.
3.

### needle error logs
Ensure verbose and debug mode are enabled:

  [needle] > set VERBOSE True
  VERBOSE => True
  [needle] > set DEBUG True
  DEBUG => True

## Environment

#### Workstation Operating System

#### Python Version

#### Python Packages (`pip freeze`)

#### Device iOS Version

```


### Suggesting Enhancements

This section guides you through submitting an enhancement suggestion for Needle, including completely new features and minor improvements to existing functionality. Following these guidelines helps maintainers and the community understand your suggestion :pencil: and find related suggestions :mag_right:.

When you are creating an enhancement suggestion, please [include as many details as possible](#how-do-i-submit-a-good-enhancement-suggestion). If you'd like, you can use [this template](#template-for-submitting-enhancement-suggestions) to structure the information.


#### How Do I Submit A (Good) Enhancement Suggestion?

Enhancement suggestions are tracked as [GitHub issues](https://guides.github.com/features/issues/). After you've determined [which component](#needle-architecture) your enhancement suggestions is related to, create an issue and provide the following information:

* _Use a clear and descriptive title_ for the issue to identify the suggestion.
* _Provide a step-by-step description of the suggested enhancement_ in as many details as possible.
* _Provide specific examples to demonstrate the steps_. Include copy/pasteable snippets which you use in those examples, as [Markdown code blocks](https://help.github.com/articles/markdown-basics/#multiple-lines).
* _Describe the current behavior_ and _explain which behavior you expected to see instead_ and why.
* _Include screenshots and animated GIFs_ which help you demonstrate the steps.


#### Template For Submitting Enhancement Suggestions

```
## Enhancement

### Expected behaviour
Tell us what should happen.

### Actual behaviour
Tell us what happens instead.

### Steps which explain the enhancement
1.
2.
3.
```


### Your First Code Contribution

Unsure where to begin contributing? You can start by looking through the [open issues](https://github.com/mwrlabs/needle/issues) or the [new features that needs to be implemented](https://github.com/mwrlabs/needle/projects/1).

MWR mantains also a collection of features/improvements needed by Needle. Just get in touch ([@mwrneedle](https://twitter.com/mwrneedle), [@lancinimarco](https://twitter.com/lancinimarco)) to know more!


### Pull Requests

* Use the `develop` as target branch.
* Include screenshots in your pull request whenever possible.
* Follow the [styleguides](#styleguides) whenever possible.
* Document new code.



## Styleguides

### Git Commit Messages

* Use the present tense ("Add feature" not "Added feature")
* Use the imperative mood ("Move cursor to..." not "Moves cursor to...")
* Limit the first line to 72 characters or less
* Reference issues and pull requests liberally


### Python Styleguide

Python code should adhere (as much as possible) to [PEP 8](https://www.python.org/dev/peps/pep-0008/).
