# CPE Integration Investigation

## Overview

This document investigates the integration of Common Platform Enumeration (CPE) information into the SBOM generator. CPE is a standardized method for naming IT products and platforms, making it easier to identify and correlate vulnerability data.

## What is CPE?

Common Platform Enumeration (CPE) is a structured naming scheme for information technology systems, software, and packages. CPE identifiers follow the format:

```
cpe:2.3:part:vendor:product:version:update:edition:language:sw_edition:target_sw:target_hw:other
```

Example:
```
cpe:2.3:a:apache:commons-logging:1.2:*:*:*:*:*:*:*
```

Where:
- `a` = application
- `apache` = vendor
- `commons-logging` = product
- `1.2` = version

CPE data is critical for vulnerability management as it's used by:
- National Vulnerability Database (NVD)
- Common Vulnerabilities and Exposures (CVE) databases
- Security scanning tools

## CycloneDX CPE Support

CycloneDX 1.6 specification supports CPE through the `cpe` field on Component objects:
- Field: `component.cpe` (string)
- Documentation: https://cyclonedx.org/docs/1.6/json/#components_items_cpe
- The CPE field accepts CPE 2.2 or CPE 2.3 formatted strings

## Public Sources for CPE Information

### 1. National Vulnerability Database (NVD) CPE Dictionary

**URL**: https://nvd.nist.gov/products/cpe

**Features**:
- Official CPE dictionary maintained by NIST
- RESTful API available: https://nvd.nist.gov/developers/products
- Search by product name, vendor, version
- Provides CPE 2.3 formatted identifiers

**API Example**:
```
GET https://services.nvd.nist.gov/rest/json/cpes/2.0?cpeMatchString=cpe:2.3:a:apache:*:*:*:*:*:*:*:*:*
```

**Pros**:
- Authoritative source
- Free API (with rate limiting)
- Comprehensive coverage

**Cons**:
- Requires API key for higher rate limits
- May not have all open-source libraries
- Complex matching logic needed

### 2. OSV (Open Source Vulnerabilities) Database

**URL**: https://osv.dev/

**Features**:
- Aggregates vulnerability data from multiple sources
- Supports querying by package ecosystem (Maven, npm, etc.)
- API available: https://google.github.io/osv.dev/api/

**API Example**:
```
POST https://api.osv.dev/v1/query
{
  "package": {
    "name": "commons-logging",
    "ecosystem": "Maven"
  },
  "version": "1.2"
}
```

**Pros**:
- Open-source friendly
- No authentication required
- Good coverage of Maven Central packages

**Cons**:
- Does not directly provide CPE identifiers
- Would need CPE mapping layer

### 3. OWASP Dependency-Check CPE Data

**URL**: https://github.com/jeremylong/DependencyCheck

**Features**:
- Maintains mapping of Maven coordinates to CPE identifiers
- Used by Dependency-Check tool
- Data files available in GitHub repository

**Data Location**: https://github.com/jeremylong/DependencyCheck/tree/main/core/src/main/resources/data

**Pros**:
- Maven-specific mappings
- Well-maintained
- No API rate limits (static files)

**Cons**:
- Requires downloading and parsing data files
- May not be up-to-date for latest packages

### 4. Sonatype OSS Index

**URL**: https://ossindex.sonatype.org/

**Features**:
- Free vulnerability database
- Supports Maven coordinates
- REST API available

**API Example**:
```
POST https://ossindex.sonatype.org/api/v3/component-report
{
  "coordinates": [
    "pkg:maven/org.apache.commons/commons-logging@1.2"
  ]
}
```

**Pros**:
- Specifically designed for open-source components
- Supports PURL format
- Free tier available

**Cons**:
- Requires authentication
- Rate limiting on free tier

### 5. ClearlyDefined (Already Used)

**URL**: https://clearlydefined.io/

**Current Usage**: Already queried for license information at:
```
https://api.clearlydefined.io/definitions/maven/mavencentral/<groupId>/<artifactId>/<version>
```

**Enhancement Potential**:
- ClearlyDefined response may include vulnerability/CPE data in the future
- Currently focused on licensing

### 6. Hash-based CPE Lookup Services

**Concept**: Query CPE by artifact hash (SHA-1, SHA-256)

**Potential Sources**:
- No widely-available public service currently exists
- Could potentially leverage NVD API with hash matching
- Maven Central provides hash-to-coordinate mapping (already used in current implementation)

**Approach**:
1. Use existing hash to find Maven coordinates (already implemented)
2. Use Maven coordinates to query CPE from other sources

## Injection Points in Current Code

Based on analysis of `SBOMApplication.java`, here are the key injection points:

### 1. Component Creation Methods

**Location**: Lines 1034-1100 (`createComponent` method)

This is where components are initially created from InstallableUnit data. This would be the primary location to add CPE information.

```java
private Component createComponent(IInstallableUnit iu) {
    var component = new Component();
    component.setName(iu.getId());
    component.setType(Component.Type.LIBRARY);
    component.setVersion(iu.getVersion().toString());
    component.setScope(Scope.REQUIRED);
    
    // INJECTION POINT: Add CPE gathering here
    // gatherCPEInformation(component, iu);
    
    // ... existing code ...
}
```

### 2. Maven Information Gathering

**Location**: Lines 1333-1379 (`gatherLicences` method)

This method already queries Maven Central and ClearlyDefined. CPE gathering could be added alongside existing external data queries.

```java
private void gatherLicences(Component component, IInstallableUnit iu, 
                            IArtifactDescriptor artifactDescriptor, byte[] bytes) {
    // ... existing license gathering ...
    
    var mavenDescriptor = MavenDescriptor.create(iu, artifactDescriptor, bytes, 
                                                  queryCentral, contentHandler);
    if (mavenDescriptor != null && !mavenDescriptor.isSnapshot()) {
        // INJECTION POINT: Query CPE information using Maven coordinates
        // gatherCPEInformation(component, mavenDescriptor);
    }
}
```

### 3. POM Information Gathering

**Location**: Lines 1596-1650 (`gatherInformationFromPOM` method)

When POM files are parsed, additional metadata could include CPE information if present in the POM.

```java
private void gatherInformationFromPOM(Component component, Document document,
                                       Map<String, String> licenseToName) {
    // ... existing POM parsing ...
    
    // INJECTION POINT: Check for CPE in POM properties/metadata
    // var cpe = extractCPEFromPOM(document);
    // if (cpe != null) {
    //     component.setCpe(cpe);
    // }
}
```

### 4. Nested JAR Processing

**Location**: Lines 1012-1024 (`createMavenJarComponent`, `createJarComponent`)

Nested JARs with Maven coordinates should also get CPE information.

## Recommended Approach

### Strategy

1. **Primary Source**: Use NVD CPE API for CPE lookups
2. **Fallback**: Cache CPE mappings locally to reduce API calls
3. **Input Data**: Use Maven coordinates (groupId, artifactId, version) when available
4. **Performance**: 
   - Implement caching to avoid repeated lookups
   - Use async/batch processing for multiple components
   - Add rate limiting to respect API constraints

### Implementation Method

Here's a proposed method signature for gathering CPE information:

```java
/**
 * Gathers CPE (Common Platform Enumeration) information for a component
 * based on its Maven coordinates and updates the component with the CPE identifier.
 * 
 * @param component The component to update with CPE information
 * @param mavenDescriptor The Maven coordinates (groupId, artifactId, version)
 */
private void gatherCPEInformation(Component component, MavenDescriptor mavenDescriptor) {
    if (mavenDescriptor == null) {
        return;
    }
    
    try {
        // Build CPE search query
        String vendor = normalizeVendorName(mavenDescriptor.groupId());
        String product = mavenDescriptor.artifactId();
        String version = mavenDescriptor.version();
        
        // Query NVD CPE API
        URI cpeApiUri = buildNVDCPEQueryURI(vendor, product, version);
        String cpeResponse = contentHandler.getContent(cpeApiUri);
        
        // Parse response and extract CPE identifier
        String cpe = extractCPEFromNVDResponse(cpeResponse, product, version);
        
        if (cpe != null) {
            component.setCpe(cpe);
        } else {
            // Construct CPE from Maven coordinates as fallback
            String constructedCpe = constructCPEFromMavenCoordinates(vendor, product, version);
            component.setCpe(constructedCpe);
        }
    } catch (Exception e) {
        // Log but don't fail - CPE is supplementary information
        System.err.println("Failed to gather CPE for " + mavenDescriptor.mavenPURL() + ": " + e.getMessage());
    }
}

private URI buildNVDCPEQueryURI(String vendor, String product, String version) {
    // Build NVD API query
    String cpeMatchString = String.format("cpe:2.3:a:%s:%s:%s:*:*:*:*:*:*:*", 
                                          urlEncodeQueryParameter(vendor),
                                          urlEncodeQueryParameter(product),
                                          urlEncodeQueryParameter(version));
    return URI.create("https://services.nvd.nist.gov/rest/json/cpes/2.0?cpeMatchString=" + cpeMatchString);
}

private String extractCPEFromNVDResponse(String jsonResponse, String product, String version) {
    // Parse JSON response from NVD
    // Look for exact match on product and version
    // Return first matching CPE 2.3 identifier
    // Implementation would use JSON parsing
    return null; // Placeholder
}

private String constructCPEFromMavenCoordinates(String vendor, String product, String version) {
    // Construct CPE 2.3 format identifier
    // Format: cpe:2.3:a:vendor:product:version:*:*:*:*:*:*:*
    return String.format("cpe:2.3:a:%s:%s:%s:*:*:*:*:*:*:*",
                        normalizeCPEComponent(vendor),
                        normalizeCPEComponent(product),
                        normalizeCPEComponent(version));
}

private String normalizeVendorName(String groupId) {
    // Convert Maven groupId to vendor name
    // e.g., "org.apache.commons" -> "apache"
    if (groupId.startsWith("org.apache.")) {
        return "apache";
    } else if (groupId.startsWith("com.google.")) {
        return "google";
    }
    // Return last component by default
    String[] parts = groupId.split("\\.");
    return parts[parts.length - 1];
}

private String normalizeCPEComponent(String component) {
    // CPE components use lowercase and replace certain characters
    return component.toLowerCase()
                   .replace(" ", "_")
                   .replace("-", "_");
}
```

## Configuration Considerations

### API Keys

The NVD API requires an API key for higher rate limits:
- Without key: 5 requests per 30 seconds
- With key: 50 requests per 30 seconds

**Recommendation**: Add optional configuration parameter for NVD API key:
```
-nvdApiKey=<key>
```

### Caching

Implement local caching to reduce API calls:
- Cache CPE lookups in memory during generation
- Optionally persist cache to disk for subsequent runs
- Cache key: Maven coordinates (groupId:artifactId:version)

### Toggle Feature

Add command-line option to enable/disable CPE gathering:
```
-gatherCPE=true|false (default: false initially)
```

## Integration Steps

1. **Phase 1**: Add basic CPE support
   - Add `gatherCPEInformation` method
   - Integrate with `createComponent` method
   - Use fallback CPE construction from Maven coordinates

2. **Phase 2**: Add NVD API integration
   - Implement NVD CPE API client
   - Add API key configuration
   - Implement response parsing

3. **Phase 3**: Add caching and optimization
   - Implement in-memory caching
   - Add rate limiting
   - Implement batch processing

4. **Phase 4**: Documentation and testing
   - Update docs/index.md with CPE information
   - Add tests for CPE gathering
   - Update www/index.html to display CPE information

## Documentation Updates Needed

### docs/index.md

Add new section after "External References":

```markdown
### CPE (Common Platform Enumeration)

The generator can optionally gather CPE (Common Platform Enumeration) identifiers
for components, which are standardized names for IT products used in vulnerability
databases like the National Vulnerability Database (NVD).

CPE identifiers follow the CPE 2.3 format:
`cpe:2.3:a:vendor:product:version:*:*:*:*:*:*:*`

The generator gathers CPE information from:
- NVD CPE Dictionary API (when available)
- Constructed from Maven coordinates as fallback

CPE information enables better correlation with vulnerability data and security
scanning tools.
```

### www/index.html

Add CPE display in component details (similar to how PURL is displayed).

## Conclusion

CPE integration is feasible and would add significant value for security analysis:

1. **Recommended Source**: NVD CPE API with local fallback construction
2. **Injection Points**: Component creation and Maven information gathering
3. **Implementation**: Add dedicated `gatherCPEInformation` method
4. **Configuration**: Optional feature with API key support
5. **Documentation**: Update existing docs to describe CPE support

The implementation should be:
- Non-blocking (failures shouldn't stop SBOM generation)
- Configurable (can be disabled)
- Cached (to minimize API calls)
- Well-documented (explain CPE purpose and sources)
