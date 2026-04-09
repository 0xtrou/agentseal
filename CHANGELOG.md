# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

### Changed
- Builder signatures are now mandatory at launch. Payloads assembled before commit `977a6dc` that were never signed will now fail to launch with `MissingSignature`; run `seal sign` before `seal launch`.
