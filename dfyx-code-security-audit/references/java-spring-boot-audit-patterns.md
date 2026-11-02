# Java Spring Boot Security Audit - Quick Reference

Real-world findings from auditing JHipster-based Java admin backends.

## 1. Reconnaissance (30 seconds)

```bash
# Tech stack
cat pom.xml | grep -A1 "<groupId>org.springframework" | head -10

# File count
find src/main/java -name "*.java" | wc -l

# Controllers (attack surface)
find src/main/java -name "*Resource.java" | wc -l

# Config files with secrets
ls src/main/resources/config/application*.yml
```

## 2. Critical Greps (run all)

```bash
# Hardcoded secrets in prod config
grep -n "password\|secret" src/main/resources/config/application-prod.yml
grep -n "password\|secret" src/main/resources/config/application-live.yml

# Missing authorization (0 results = critical)
grep -rn "@PreAuthorize\|@RolesAllowed\|@Secured" src/main/java --include="*Resource.java"

# Auth logic flaw (always-success login)
grep -rn "ResponseObject.success\|doAuth" src/main/java --include="*.java" -A5

# Native SQL queries
grep -rn "createNativeQuery\|@Query.*nativeQuery" src/main/java --include="*.java"

# File upload sinks
grep -rn "getOriginalFilename\|MultipartFile" src/main/java --include="*.java" | grep -v import

# Path traversal sanitizer
grep -rn "cleanString\|cleanChar" src/main/java --include="*.java" -A15

# CORS misconfiguration
grep -A5 "cors:" src/main/resources/config/application.yml
```

## 3. Common Findings

### 3.1 Hardcoded Credentials (always check)

**application-live.yml or application-prod.yml:**
```yaml
spring:
  datasource:
    url: jdbc:postgresql://prod-db.company.com:5432/db
    username: appuser
    password: PlaintextPass123  # CRITICAL

minioServer:
  endpoint: https://minio.company.com/
  accessKey: minioadmin
  secretKey: minioadmin  # Default creds

service:
  api:
    secretKey: admin123  # Weak secret
```

**Test:** Try MinIO login at endpoint with minioadmin/minioadmin

### 3.2 Authentication Logic Flaw

**Pattern:** Login proxies to LDAP but NEVER validates response

```java
// LoginResource.java
@RequestMapping("/auth/login")
public ResponseEntity<?> login(@RequestBody LoginReq req) {
    ResponseObject<LoginResponse> res = loginService.login(req);  // Proxies to LDAP
    Authentication auth = loginService.doAuth(req, res.getData());  // NO verification!
    String jwt = tokenProvider.createToken(auth, false);  // Always issues JWT
    res.getData().setJwtNextgen(jwt);
    return ResponseEntity.ok(res);
}

// LoginService.java
public Authentication doAuth(LoginReq req, LoginResponse res) {
    List<GrantedAuthority> authorities = new ArrayList<>();
    authorities.add(new SimpleGrantedAuthority("ROLE_USER"));  // No check!
    return new UsernamePasswordAuthenticationToken(principal, "", authorities);
}
```

**Test:** POST /api/auth/login with wrong password → if JWT returned, auth bypass confirmed

### 3.3 Missing Authorization (JHipster default)

**Symptom:** No `@PreAuthorize` annotations on ANY controller

**Impact:** All 300+ endpoints accessible with ANY valid JWT (user role doesn't matter)

**Verify:**
```bash
grep -rn "@PreAuthorize\|hasRole" src/main/java --include="*Resource.java" | wc -l
# 0 = critical
```

### 3.4 Path Traversal in File Upload

**Pattern:**
```java
// MinioService.java
public MinioUploadRes uploadMultipartFile(MultipartFile file, String bucketName) {
    String fileName = file.getOriginalFilename();  // User-controlled
    String path = multipartToFile(file, fileName);
}

private String multipartToFile(MultipartFile multipart, String fileName) {
    // Weak sanitizer
    File convFile = new File(CommonUtils.cleanString(tmpdir + "/" + fileName));
    multipart.transferTo(convFile);
}

// CommonUtils.java
public static String cleanString(String str) {
    // Whitelist includes: / . - _ space → BYPASS
    switch (aChar) {
        case '/': return '/';  // Allows ../..
        case '.': return '.';
        // ...
    }
}
```

**Exploit:** Upload file with filename `../../webapps/ROOT/shell.jsp`

### 3.5 CORS Misconfiguration

**application.yml:**
```yaml
cors:
  allowed-origins: "*"
  allow-credentials: true  # CRITICAL combo
  allowed-headers: "*"
```

**Impact:** CSRF possible from any origin if JWT in cookie (less severe if JWT in Authorization header)

## 4. SQL Injection Check

Most Spring Data JPA repos use parameterized queries (safe). Look for:

```bash
# Native queries (manual review needed)
grep -rn "createNativeQuery\|nativeQuery.*=.*true" src/main/java --include="*.java"

# Sort injection (Spring Data JPA)
grep -rn "getSort\|Sort.by\|pageable.getSort" src/main/java --include="*.java"
```

**Safe pattern:**
```java
@Query(value = "select * from users where id = :id", nativeQuery = true)
User findByIdNative(@Param("id") Long id);  // Parameterized, safe
```

**Unsafe pattern (rare in JPA):**
```java
@Query(value = "select * from users where name = '" + name + "'")  // Concatenation
```

## 5. Report Template

```
## CRITICAL
- [ ] Hardcoded prod credentials in application-live.yml
- [ ] Auth bypass via login logic flaw (test with wrong password)
- [ ] Missing @PreAuthorize on N controllers

## HIGH
- [ ] Path traversal in file upload (MinioService.uploadMultipartFile)
- [ ] CORS: allowed-origins "*" + allow-credentials true

## MEDIUM
- [ ] Default JWT secret in application.yml
- [ ] MinIO default credentials (minioadmin/minioadmin)

## LOW
- [ ] Sensitive endpoints exposed (/management/*, /swagger)
```

## 6. Exploitation Priority

1. Test login bypass (wrong password → JWT?)
2. Try MinIO login with default creds
3. Upload file with `../../` filename
4. Check if JWT secret is default ("my-secret-token-to-change-in-production")
5. Access admin endpoints with low-priv user JWT

## 7. Tools

- **Decompile JAR:** `jd-gui` or `cfr` for com.swib.services lib
- **Test endpoints:** Postman/curl with forged JWT
- **File upload:** Burp Suite → modify filename in multipart request
