# Epistery Config: A Unified Path-Based Configuration System

**Date:** October 27, 2025
**Author:** Epistery Core Team

## The Problem

As the Epistery ecosystem grew, configuration management became fragmented. We had:
- Multiple config file locations (`.epistery/`, `.rhonda/`, `.metric/`)
- Confusing API distinctions (`config.data` vs `config.domains`)
- Duplicated code across projects
- Case-sensitivity bugs causing duplicate folders

Different tools had different approaches, making it hard for developers to know where their data lived.

## The Solution: Config as a Core Feature

We realized that **configuration management is fundamentally about trust and data security** - exactly what Epistery is for. So we made Config a first-class feature of Epistery itself.

The new design is **filesystem-like** and **brand-centric**:

```javascript
const config = new Config('epistery');

// Navigate like a filesystem
config.setPath('/');                    // Root level
config.load();
config.data.profile.email = 'user@example.com';
config.save();

config.setPath('/wiki.rootz.global');   // Domain level
config.load();
config.data.verified = true;
config.save();

config.setPath('/.ssl/wiki.rootz.global');  // Arbitrary paths
config.load();
config.data.certData = '...';
config.save();
```

## Key Benefits

### 1. **Single Source of Truth**
All Epistery applications use `~/.epistery/` - no namespace collisions, no confusion.

### 2. **Clean API**
No more `config.data` vs `config.loadDomain()` distinction. Just:
- `config.setPath(path)` - navigate to a location
- `config.load()` - read config
- `config.save()` - write config

### 3. **Flexible**
The path-based approach works for any use case:
- `/domain` - domain configurations
- `/.ssl/domain` - SSL certificates
- `/sessions/user` - session data
- Whatever you need

### 4. **Automatic Case Normalization**
Domain names are automatically lowercased, preventing duplicate folders on case-sensitive filesystems.

### 5. **Library-Friendly**
Libraries like Metric can accept a `rootName` parameter but default to the brand they're used in:

```javascript
// In Rhonda (an Epistery app)
const config = new Config('epistery');  // Not 'rhonda'

// In a standalone Metric app
const config = new Config('metric');    // Defaults to 'metric'
```

## File Structure

```
~/.epistery/
├── config.ini                    # Global epistery settings
├── wiki.rootz.global/
│   ├── config.ini                # Domain: verified, admin, provider
│   └── sessions/                 # Session tokens
├── blackfire.fish/
│   └── config.ini
└── .ssl/                         # SSL certificates
    ├── wiki.rootz.global/
    └── blackfire.fish/
```

## Marketing to Engineers

For developers, the experience is clean and familiar:

```bash
# Install epistery
npm install epistery

# All configs go here
ls ~/.epistery/
```

The pattern follows industry standards (like `~/.docker/`, `~/.kube/`) while providing flexibility for complex applications.

## Implementation

Config is now exported from the main Epistery module:

```javascript
import { Epistery, Config } from 'epistery';
```

This makes it clear: **Epistery provides configuration management as a core security feature**, not as an afterthought.

## Conclusion

By making Config a first-class Epistery feature, we've:
- Eliminated code duplication
- Simplified the developer experience
- Created a single, trusted namespace for the ecosystem
- Made it easier to build applications on Epistery

Configuration management is about data security and trust - exactly what Epistery is built for.

---

*Questions or feedback? Open an issue at [github.com/rootz-global/epistery](https://github.com/rootz-global/epistery)*