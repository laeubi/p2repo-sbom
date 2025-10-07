# CPE Integration - Quick Reference

This directory contains documentation for CPE (Common Platform Enumeration) integration in the p2 SBOM generator.

## Documents

### 1. [CPE_INTEGRATION.md](CPE_INTEGRATION.md)
**Comprehensive Investigation Document**

- What is CPE and why it matters
- Analysis of 6+ public CPE data sources
- Detailed injection point analysis in the codebase
- Recommended implementation approach
- Future enhancement strategies
- Configuration considerations

**Read this if you want to**:
- Understand the full context and research
- Learn about alternative CPE data sources
- Plan future enhancements
- Understand design decisions

### 2. [CPE_SUMMARY.md](CPE_SUMMARY.md)
**Implementation Summary**

- What was implemented
- Technical details of the 4 new methods
- Integration points in the code
- Current limitations
- Benefits and use cases
- Files modified

**Read this if you want to**:
- Quick overview of what changed
- Understand the code changes
- See what limitations exist
- Know what files were modified

### 3. [CPE_EXAMPLE.md](CPE_EXAMPLE.md)
**Examples and Usage**

- Real-world JSON and XML output examples
- CPE format breakdown and explanation
- Multiple component examples (Apache, Spring, Google, etc.)
- Vendor name normalization rules
- Use cases for vulnerability scanning
- Integration with vulnerability databases

**Read this if you want to**:
- See what CPE looks like in output
- Understand CPE format
- Learn how to use CPE for security
- Examples of different vendors

## Quick Start

### What is CPE?

CPE (Common Platform Enumeration) is a standardized naming scheme for IT products that enables:
- Correlation with vulnerability databases (NVD, CVE)
- Integration with security scanning tools
- Standardized component identification

### Example

For Maven artifact `org.apache.commons:commons-logging:1.2`, the generator creates:

```
cpe:2.3:a:apache:commons_logging:1.2:*:*:*:*:*:*:*
```

Where:
- `apache` = vendor (from groupId)
- `commons_logging` = product (from artifactId)
- `1.2` = version

### How It Works

The CPE gathering happens automatically when:
1. A component has Maven coordinates available
2. The SBOM is being generated

The process:
1. Extract Maven groupId, artifactId, version
2. Normalize vendor name (e.g., `org.apache.*` → `apache`)
3. Normalize product name (e.g., `commons-logging` → `commons_logging`)
4. Construct CPE 2.3 format identifier
5. Set CPE on the component

### Supported Vendors

Well-known vendor mappings:
- `org.apache.*` → `apache`
- `com.google.*` → `google`
- `org.eclipse.*` → `eclipse`
- `com.fasterxml.*` → `fasterxml`
- `org.springframework.*` → `springframework`
- `io.netty.*` → `netty`
- `org.slf4j.*` → `slf4j`

For other vendors, uses the last component of groupId.

### Code Location

Main implementation: `SBOMApplication.java`

New methods:
- `gatherCPEInformation()` - Main orchestration
- `constructCPEFromMavenCoordinates()` - CPE construction
- `normalizeVendorName()` - Vendor name mapping
- `normalizeCPEComponent()` - String normalization

Integration points:
- `gatherLicences()` method (line ~1354)
- `createMavenJarComponent()` method (line ~1026)

### Testing

Test: `SBOMTest.testCPESupport()`

Verifies:
- CPE field is supported in CycloneDX model
- CPE appears in JSON output
- CPE appears in XML output

## Benefits

✅ **Security Analysis**: Enables vulnerability correlation with NVD, CVE databases

✅ **Standards Compliant**: Uses official CPE 2.3 format

✅ **Tool Integration**: Compatible with security scanning tools

✅ **Non-Intrusive**: Failures don't affect SBOM generation

✅ **Extensible**: Design supports future API integration

## Current State

**Status**: ✅ Implemented and Functional

**Coverage**:
- ✅ Components with Maven coordinates
- ✅ Nested JAR components with Maven coordinates
- ❌ Components without Maven coordinates (no CPE)

**Sources**:
- ✅ Constructed from Maven coordinates
- ❌ NVD API queries (future enhancement)
- ❌ Cached lookups (future enhancement)

## Future Enhancements

See [CPE_INTEGRATION.md](CPE_INTEGRATION.md) for detailed future plans:

1. **NVD API Integration** - Query authoritative CPE database
2. **Caching** - Reduce API calls and improve performance
3. **Configuration** - Add command-line options for CPE features
4. **Additional Sources** - OSV, OWASP Dependency-Check data
5. **Enhanced Mapping** - More comprehensive vendor name rules

## Use Cases

### 1. Vulnerability Scanning

Security tools can use CPE to:
- Query NVD for known vulnerabilities
- Match components against CVE databases
- Generate security reports

### 2. Compliance

Organizations can:
- Create component allowlists by CPE
- Block vulnerable versions
- Track approved components

### 3. Supply Chain Security

Development teams can:
- Standardize component naming across tools
- Track dependencies across projects
- Assess security risk of dependencies

## Related Documentation

- [Main Documentation](index.md) - Complete p2 SBOM generator docs
- [CycloneDX CPE Spec](https://cyclonedx.org/docs/1.6/json/#components_items_cpe)
- [NVD CPE](https://nvd.nist.gov/products/cpe)
- [CPE Specification](https://nvd.nist.gov/products/cpe)

## Questions?

For detailed information, see:
- **Implementation details** → [CPE_SUMMARY.md](CPE_SUMMARY.md)
- **Research and sources** → [CPE_INTEGRATION.md](CPE_INTEGRATION.md)
- **Examples and usage** → [CPE_EXAMPLE.md](CPE_EXAMPLE.md)
