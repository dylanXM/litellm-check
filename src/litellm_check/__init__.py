"""LiteLLM Check - exposure self-audit for the compromised v1.107.0 release.

Scans a source tree and/or local Python environments for the exposure
surface of the 2026-10-21 LiteLLM supply-chain incident: dependency
specs and lockfiles that pin or admit litellm==1.107.0, container image
tags/digests named in the incident announcement, installed-distribution
metadata, and the implant/marker files the announcement lists.

Every detection rule is derived from LiteLLM's official incident
announcement. The tool collects evidence only; it never certifies an
environment as safe.
"""

__version__ = "0.1.0"
