# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

### Fixed

- Prevent unbounded growth of `pending_requests` on bodyless traffic when body
  inspection is enabled: known-empty requests complete at `request_headers`,
  pending entries drop on response start and request completion, stale entries
  age out, the map is capped, and orphan body chunks fail closed instead of
  being allowed.
