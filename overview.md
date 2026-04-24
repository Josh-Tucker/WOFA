---
title: WOFA
slug: wofa
description: Windows Organised Feed for Admins — machine-readable Windows update and CVE feeds
tech: Python, MSRC CVRF API, CISA KEV
status: active
repo: http://plugsocket:3001/josh/wofa
---

## What it is

WOFA aggregates Windows cumulative security update data from the [MSRC CVRF API](https://api.msrc.microsoft.com/cvrf/v3.0) and [CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) into machine-readable feeds for system administrators and MDM tooling. OS versions are discovered automatically from the MSRC ProductTree.

## Outputs

- **`windows_data_feed.json`** — Full feed with CVE severity, exploitation status, and patch details per OS version
- **`metadata.json`** — Summary stats and SHA-256 hash of the feed
- **`windows_release_feed.rss`** — RSS feed of the latest release per OS version
- **Static HTML** — Browseable site for reviewing the data

## Features

- Automatic OS version discovery — no manual config when Microsoft adds a new version
- Cross-references CISA KEV to flag actively exploited vulnerabilities
- Produces both human-readable and machine-readable outputs
- Designed to be run on a schedule and the outputs committed/served statically

## Status

Active. Running on a schedule to keep feeds current.
