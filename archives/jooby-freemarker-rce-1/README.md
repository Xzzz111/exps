# Jooby FreeMarker RCE Vulnerability - CVE Submission Package

This directory contains the complete CVE submission package for a Remote Code Execution vulnerability in the Jooby FreeMarker module.

## Vulnerability Summary

**Vulnerability**: Remote Code Execution via Unsafe FreeMarker Class Resolver Configuration
**Product**: Jooby Framework - FreeMarker Module (io.jooby:jooby-freemarker)
**Severity**: HIGH (CVSS 8.8) / CRITICAL (CVSS 9.8)
**Status**: Unpatched (as of 2025-11-02)

## Files in This Directory

### 1. `report.md`
Complete technical vulnerability report including:
- Detailed vulnerability description
- Root cause analysis
- Multiple proof-of-concept exploits
- Attack vectors and scenarios
- CVSS scoring
- Remediation recommendations
- Timeline

**Use**: Share with Jooby maintainers, reference in CVE entry, public disclosure

### 2. `cve-application-form.md`
Formatted CVE application form ready for submission to MITRE/CVE Program, including:
- Structured vulnerability information
- Vendor and product details
- Attack vectors and impact assessment
- Suggested CVE description
- References and additional context

**Use**: Copy/paste into CVE request form at https://cveform.mitre.org/

### 3. `README.md` (this file)
Overview and instructions for this vulnerability disclosure package.

## Submission Checklist

- [x] Technical analysis completed
- [x] Proof-of-concept developed and tested
- [x] Vulnerability report written
- [x] CVE application form filled
- [ ] Vendor notified (pending)
- [ ] CVE ID requested from MITRE
- [ ] Public disclosure coordinated
- [ ] Security advisory published

## Next Steps

1. **Request CVE ID**:
   - Visit https://cveform.mitre.org/
   - Copy content from `cve-application-form.md`
   - Submit the request
   - Wait for CVE ID assignment

2. **Notify Vendor**:
   - Contact: https://github.com/jooby-project/jooby/security/advisories/new
   - Provide: `report.md` content
   - Propose: 90-day disclosure timeline
   - Offer: Assistance with patch development

3. **Coordinate Disclosure**:
   - Work with vendor on patch
   - Update CVE entry with patch information
   - Prepare public advisory
   - Notify affected users

## Contact

**Discoverer**: s1ain
**Disclosure Policy**: Responsible disclosure with 90-day timeline

## Vulnerability Details Quick Reference

- **File**: `modules/jooby-freemarker/src/main/java/io/jooby/freemarker/FreemarkerModule.java`
- **Line**: 127
- **Issue**: `configuration.setNewBuiltinClassResolver(TemplateClassResolver.UNRESTRICTED_RESOLVER)`
- **Fix**: Change to `TemplateClassResolver.SAFER_RESOLVER`

## Impact

All applications using jooby-freemarker module are potentially vulnerable if:
- Users can control template content
- Users can control template model data
- Application has template customization features

**Potential Impact**: Complete server compromise via RCE
