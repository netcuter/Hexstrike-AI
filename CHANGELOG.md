# Changelog - Hexstrike 7 PL

All notable changes to this project will be documented in this file.

This project is a Polish community fork of [HexStrike AI v6.0](https://github.com/0x4m4/hexstrike-ai) by m0x4m4.

## [7.0.0-PL] - 2025-01-21

### 🔒 Security Enhancements

#### Critical Security Fixes
- **Command Injection Protection**: Added comprehensive input validation to prevent command injection attacks
  - Created `security_utils.py` module with whitelist-based validation
  - Validates all commands against a whitelist of 150+ security tools
  - Blocks dangerous command patterns (rm -rf /, fork bombs, etc.)
  - Sanitizes parameters to remove dangerous characters (;, |, &, `, $)

- **API Authentication**: Added optional API key authentication system
  - Configurable via `HEXSTRIKE_REQUIRE_API_KEY` environment variable
  - Supports API key in header (`X-API-Key`) or query parameter
  - Protects all endpoints except `/health`

- **Rate Limiting**: Implemented IP-based rate limiting
  - Default: 100 requests per 60 seconds
  - Configurable via environment variables
  - Thread-safe implementation with automatic cleanup
  - Returns HTTP 429 when limit exceeded

#### Input Validation
- Added whitelist of 150+ authorized security tools
- Parameter sanitization for all user inputs
- Safe command parsing using `shlex`
- Protection against path traversal attacks

### ⚙️ Configuration Management

- **Environment-Based Configuration**: All settings now configurable via environment variables
  ```bash
  HEXSTRIKE_VALIDATE_COMMANDS=true    # Command validation (default: true)
  HEXSTRIKE_REQUIRE_API_KEY=false     # API authentication (default: false)
  HEXSTRIKE_API_KEY=your-key          # API key if authentication enabled
  HEXSTRIKE_RATE_LIMIT=true           # Rate limiting (default: true)
  HEXSTRIKE_RATE_LIMIT_REQUESTS=100   # Max requests per window
  HEXSTRIKE_RATE_LIMIT_WINDOW=60      # Time window in seconds
  HEXSTRIKE_PORT=8888                 # Server port
  HEXSTRIKE_HOST=127.0.0.1           # Server host
  ```

### 📚 Documentation

- **Dual Language Support**: Complete documentation in Polish and English
- **Enhanced README**:
  - Clear fork attribution to original HexStrike AI v6.0
  - Security configuration examples
  - Quick start guide in both languages
  - Architecture diagrams with security layer
  - Comprehensive feature list

- **License File**: Added proper MIT license with attribution to original author
- **This Changelog**: Detailed documentation of all changes

### 🐛 Bug Fixes

- **Improved Error Handling**:
  - Fixed bare `except:` clauses to use specific exceptions
  - Better error messages and logging
  - Proper exception handling in tool availability checks

### ⚡ Performance & Optimization

- **Cache Management**:
  - Confirmed cache size limits are properly implemented
  - LRU eviction working correctly
  - Memory optimization verified

- **Code Organization**:
  - Better separation of security concerns
  - Modular security utilities
  - Cleaner configuration management

### 🔧 Technical Changes

#### New Files
- `security_utils.py`: Security validation and sanitization module
  - `SecurityValidator` class
  - `validate_command()` function
  - `sanitize_parameter()` function
  - `parse_command_safely()` function
  - `build_safe_command()` function

- `LICENSE`: MIT license with proper attribution
- `CHANGELOG.md`: This file

#### Modified Files
- `hexstrike_server.py`:
  - Added security middleware (rate limiting, API auth)
  - Integrated command validation in API endpoints
  - Updated version to 7.0.0-PL
  - Enhanced health check endpoint with security status
  - Environment-based configuration

- `README.md`:
  - Complete rewrite with dual language support
  - Polish version first, English version second
  - Enhanced security documentation
  - Fork attribution and credits

### 📊 Statistics

- **Lines of Code Added**: ~1,000+
- **Security Vulnerabilities Fixed**: 2 critical (command injection)
- **Configuration Options Added**: 8 new environment variables
- **Documentation Pages**: 2 languages (Polish + English)

### 🙏 Credits

- **Original Author**: m0x4m4 - Creator of HexStrike AI v6.0
- **Fork Maintainer**: netcuter
- **Based On**: [HexStrike AI v6.0](https://github.com/0x4m4/hexstrike-ai)

### 📝 Notes

This release focuses on security hardening while maintaining full compatibility with the original HexStrike AI v6.0 functionality. All security features are configurable and can be disabled for testing or trusted environments.

**Migration from v6.0**:
- No breaking changes - fully backward compatible
- Security features are opt-in (command validation is enabled by default)
- Existing installations will work without modifications
- To enable API authentication, set `HEXSTRIKE_REQUIRE_API_KEY=true`

### 🔗 Links

- **This Repository**: https://github.com/netcuter/Hexstrike-AI
- **Original Project**: https://github.com/0x4m4/hexstrike-ai
- **Original Author**: https://www.0x4m4.com

---

## [6.0.0] - Original Release

This fork is based on HexStrike AI v6.0 by m0x4m4, which included:
- 150+ security tools
- 12+ AI agents
- Modern visual engine
- Intelligent decision engine
- Bug bounty workflows
- CTF solver
- CVE intelligence
- AI exploit generator
- And much more...

For complete history of v6.0 and earlier versions, see the [original repository](https://github.com/0x4m4/hexstrike-ai).
