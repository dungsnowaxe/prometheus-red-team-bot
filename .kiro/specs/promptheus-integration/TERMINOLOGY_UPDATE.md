# Terminology Update: PROMPTHEUS → PROMPTHEUS

## Overview

This document clarifies the terminology used in the specification. PROMPTHEUS is the product name, and we are enhancing it with agent-based security scanning capabilities.

## Key Changes

### Product Name
- **Before**: "PROMPTHEUS PROMPTHEUS Integration"
- **After**: "PROMPTHEUS Agent-Based Security Scanning"
- **Rationale**: PROMPTHEUS is the product. We're not integrating with an external product called "PROMPTHEUS" - we're enhancing PROMPTHEUS with new capabilities.

### Artifacts Directory
- **Before**: `.promptheus/` (PROMPTHEUS_Directory)
- **After**: `.promptheus/` (Artifacts_Directory)
- **Rationale**: Artifacts should be stored in a directory named after the product (PROMPTHEUS).

### Environment Variables
- **Before**: `PROMPTHEUS_<AGENT>_MODEL`
- **After**: `PROMPTHEUS_<AGENT>_MODEL`
- **Rationale**: Environment variables should use the product name prefix.

### Documentation Titles
- **Before**: "PROMPTHEUS PROMPTHEUS Integration"
- **After**: "PROMPTHEUS Agent-Based Security Scanning"
- **Rationale**: Clearer description of what we're building.

## What Stays the Same

### Technical Architecture
- All technical designs remain unchanged
- Agent definitions, workflows, and algorithms are identical
- Test infrastructure and implementation plan are the same

### File Paths
- Spec directory name remains: `.kiro/specs/promptheus-promptheus-integration/`
- **Rationale**: Keeping the directory name avoids breaking existing references and git history

### Core Concepts
- Agent-based scanning workflow
- DAST validation
- Skill system
- Progress tracking
- Security hooks

## Updated Glossary

| Term | Definition |
|------|------------|
| **PROMPTHEUS** | The security scanning CLI tool and product |
| **Agent** | A specialized Claude-powered sub-agent for security analysis |
| **Artifacts_Directory** | The `.promptheus/` directory where scan artifacts are stored |
| **Scanner** | The unified security scanning system in PROMPTHEUS |
| **Agent Mode** | Multi-phase agent-based scanning mode |
| **Legacy Mode** | Original payload-based scanning mode |
| **Hybrid Mode** | Combined legacy + agent scanning |

## Migration Notes

When implementing:
1. Use `.promptheus/` for artifacts directory (not `.promptheus/`)
2. Use `PROMPTHEUS_` prefix for environment variables
3. Reference "PROMPTHEUS agent-based scanning" in user-facing messages
4. Keep internal code references consistent with product name

## Summary

This is a terminology clarification, not a technical change. PROMPTHEUS is being enhanced with powerful agent-based security scanning capabilities. All technical specifications remain valid - only naming has been clarified to reflect that PROMPTHEUS is the product name.
