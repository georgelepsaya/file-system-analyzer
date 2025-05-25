# File System Analyzer

![CI](https://github.com/georgelepsaya/file-system-analyzer/actions/workflows/tests.yaml/badge.svg) 

![Demo of the tool](docs/demo.gif)

## Motivation for chosen tools and approach

1. **uv** for project and package management.

Previously I have used both `setuptools` and `poetry` for project and dependency management. However this time I have chosen `uv` as a project and package manager, because it is fast, easy to set up, and I was curious to try a new tool gaining wide adoption recently.

As a build backend by default `uv` uses `hatchling`, which is a modern standard option with minimal dependencies.

2. **argparse** for command line interface.

I have used `click` and `argparse` in my previous projects and I thought that `argparse` is a good fit for this task.