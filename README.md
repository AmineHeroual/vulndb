# Introduction

Vulndb is a vulnerability database and package search for sources such as NVD, GitHub and so on. It uses a built-in tinydb based storage engine to allow offline access.

## Installation

```bash
pip install vulndb
```

## Usage

This package is meant to be used as a library along with another cli based tool. However, there is a limited cli capability available with few features.

### Cache vulnerability data

```bash
vdb --cache
```

It is possible to customise the cache behaviour by increasing the historic data period to cache by setting the following environment variables.

- NVD_START_YEAR - Default: 2016. Supports upto 2002
- GITHUB_PAGE_COUNT - Default: 5. Supports upto 20

### Periodic sync

To periodically sync the latest vulnerabilities and update the database cache.

```bash
vdb --sync
```

### Basic search

It is possible to perform simple search using the cli.

```bash
vdb --search android:8.0

vdb --search android:8.0,simplesamlphp:1.14.11
```

Syntax is package:version,package:version
