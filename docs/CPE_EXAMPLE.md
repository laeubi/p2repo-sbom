# CPE Integration - Example Output

This document shows example SBOM outputs with CPE information included.

## JSON Output Example

Here's what a component with CPE information looks like in CycloneDX JSON format:

```json
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.6",
  "version": 1,
  "components": [
    {
      "type": "library",
      "bom-ref": "pkg:maven/org.apache.commons/commons-logging@1.2",
      "group": "org.apache.commons",
      "name": "commons-logging",
      "version": "1.2",
      "purl": "pkg:maven/org.apache.commons/commons-logging@1.2",
      "cpe": "cpe:2.3:a:apache:commons_logging:1.2:*:*:*:*:*:*:*",
      "hashes": [
        {
          "alg": "SHA-256",
          "content": "daddea1ea0be0f56978ab3006b8ac92834afeefbd9b7e4e6316fca57df0fa636"
        }
      ],
      "licenses": [
        {
          "license": {
            "id": "Apache-2.0",
            "url": "https://www.apache.org/licenses/LICENSE-2.0"
          }
        }
      ],
      "externalReferences": [
        {
          "type": "vcs",
          "url": "https://github.com/apache/commons-logging"
        },
        {
          "type": "website",
          "url": "https://commons.apache.org/proper/commons-logging/"
        }
      ]
    }
  ]
}
```

## XML Output Example

The same component in CycloneDX XML format:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<bom xmlns="http://cyclonedx.org/schema/bom/1.6" version="1">
  <components>
    <component type="library" bom-ref="pkg:maven/org.apache.commons/commons-logging@1.2">
      <group>org.apache.commons</group>
      <name>commons-logging</name>
      <version>1.2</version>
      <purl>pkg:maven/org.apache.commons/commons-logging@1.2</purl>
      <cpe>cpe:2.3:a:apache:commons_logging:1.2:*:*:*:*:*:*:*</cpe>
      <hashes>
        <hash alg="SHA-256">daddea1ea0be0f56978ab3006b8ac92834afeefbd9b7e4e6316fca57df0fa636</hash>
      </hashes>
      <licenses>
        <license>
          <id>Apache-2.0</id>
          <url>https://www.apache.org/licenses/LICENSE-2.0</url>
        </license>
      </licenses>
      <externalReferences>
        <reference type="vcs">
          <url>https://github.com/apache/commons-logging</url>
        </reference>
        <reference type="website">
          <url>https://commons.apache.org/proper/commons-logging/</url>
        </reference>
      </externalReferences>
    </component>
  </components>
</bom>
```

## CPE Format Breakdown

The CPE identifier `cpe:2.3:a:apache:commons_logging:1.2:*:*:*:*:*:*:*` breaks down as:

- `cpe:2.3` - CPE version 2.3 format
- `a` - Part: Application (vs. `h` for hardware, `o` for OS)
- `apache` - Vendor: Normalized from `org.apache.commons` groupId
- `commons_logging` - Product: Normalized from `commons-logging` artifactId
- `1.2` - Version: From Maven version
- `*:*:*:*:*:*:*` - Wildcards for update, edition, language, sw_edition, target_sw, target_hw, other

## More Examples

### Spring Framework Component

Maven coordinates: `org.springframework:spring-core:5.3.20`

```json
{
  "group": "org.springframework",
  "name": "spring-core",
  "version": "5.3.20",
  "cpe": "cpe:2.3:a:springframework:spring_core:5.3.20:*:*:*:*:*:*:*"
}
```

### Google Guava Component

Maven coordinates: `com.google.guava:guava:31.1-jre`

```json
{
  "group": "com.google.guava",
  "name": "guava",
  "version": "31.1-jre",
  "cpe": "cpe:2.3:a:google:guava:31.1_jre:*:*:*:*:*:*:*"
}
```

### Eclipse Platform Component

Maven coordinates: `org.eclipse.platform:org.eclipse.core.runtime:3.26.0`

```json
{
  "group": "org.eclipse.platform",
  "name": "org.eclipse.core.runtime",
  "version": "3.26.0",
  "cpe": "cpe:2.3:a:eclipse:org.eclipse.core.runtime:3.26.0:*:*:*:*:*:*:*"
}
```

### Netty Component

Maven coordinates: `io.netty:netty-all:4.1.79.Final`

```json
{
  "group": "io.netty",
  "name": "netty-all",
  "version": "4.1.79.Final",
  "cpe": "cpe:2.3:a:netty:netty_all:4.1.79.final:*:*:*:*:*:*:*"
}
```

## Vendor Name Normalization

The following vendor name mappings are applied:

| Maven GroupId Pattern | CPE Vendor |
|----------------------|------------|
| `org.apache.*` | `apache` |
| `com.google.*` | `google` |
| `org.eclipse.*` | `eclipse` |
| `com.fasterxml.*` | `fasterxml` |
| `org.springframework.*` | `springframework` |
| `io.netty.*` | `netty` |
| `org.slf4j.*` | `slf4j` |
| Other | Last component of groupId |

## Product Name Normalization

Product names (artifactIds) are normalized by:
1. Converting to lowercase
2. Replacing hyphens (`-`) with underscores (`_`)
3. Replacing spaces with underscores (`_`)

Examples:
- `commons-logging` → `commons_logging`
- `spring-core` → `spring_core`
- `netty-all` → `netty_all`

## Use Cases

### Vulnerability Scanning

The CPE identifiers enable vulnerability scanners to:

1. **Match against NVD**: Query the National Vulnerability Database using the CPE
2. **Correlate CVEs**: Link components to known Common Vulnerabilities and Exposures
3. **Track vulnerabilities**: Monitor for new vulnerabilities affecting specific components

Example NVD query:
```
https://nvd.nist.gov/vuln/search/results?cpe_name=cpe:2.3:a:apache:commons_logging:1.2:*:*:*:*:*:*:*
```

### Security Policy Enforcement

Organizations can use CPE identifiers to:

1. **Create allowlists**: Approve specific CPE identifiers
2. **Block vulnerable versions**: Identify and block components with known CVEs
3. **Compliance reporting**: Generate reports based on CPE-identified components

### Supply Chain Security

CPE identifiers help with:

1. **Component identification**: Standardized naming across tools and databases
2. **Dependency tracking**: Track components across different projects
3. **Risk assessment**: Evaluate security risk of component dependencies

## Integration with Vulnerability Databases

### National Vulnerability Database (NVD)

Search for vulnerabilities by CPE:
```
https://services.nvd.nist.gov/rest/json/cves/2.0?cpeName=cpe:2.3:a:apache:commons_logging:1.2:*:*:*:*:*:*:*
```

### OSV (Open Source Vulnerabilities)

While OSV doesn't directly use CPE, the Maven coordinates can be used:
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

### OWASP Dependency-Check

Dependency-Check uses CPE identifiers internally to match components with NVD data.

## Future Enhancements

As described in `CPE_INTEGRATION.md`, future versions may:

1. Query NVD API for authoritative CPE identifiers
2. Use hash-based lookups for additional accuracy
3. Support multiple CPE identifiers per component
4. Cache CPE lookups for performance
5. Allow custom vendor name mappings via configuration
