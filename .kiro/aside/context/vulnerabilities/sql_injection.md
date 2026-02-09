# SQL Injection (CWE-89)

## Vulnerability Overview
- **CWE**: CWE-89 - Improper Neutralization of Special Elements used in an SQL Command
- **OWASP**: A03:2021 - Injection
- **Severity**: Critical
- **CVSS Base**: 9.8

## Detection Patterns

### JavaScript/TypeScript

**Dangerous Patterns:**
```javascript
// String concatenation in queries
db.query(`SELECT * FROM users WHERE id = ${userId}`);
db.query("SELECT * FROM users WHERE id = " + userId);

// Template literals without parameterization
connection.execute(`SELECT * FROM ${table} WHERE ${column} = ${value}`);

// Raw query builders
sequelize.query(`SELECT * FROM users WHERE email = '${email}'`);
knex.raw(`SELECT * FROM users WHERE name = '${name}'`);
```

**Safe Patterns:**
```javascript
// Parameterized queries - PostgreSQL
db.query('SELECT * FROM users WHERE id = $1', [userId]);

// Parameterized queries - MySQL
connection.execute('SELECT * FROM users WHERE id = ?', [userId]);

// ORM with parameter binding
await User.findOne({ where: { email } });
await knex('users').where('id', userId);

// Sequelize replacements
sequelize.query('SELECT * FROM users WHERE email = :email', {
  replacements: { email }
});
```

### Python

**Dangerous Patterns:**
```python
# String formatting
cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")
cursor.execute("SELECT * FROM users WHERE id = " + user_id)
cursor.execute("SELECT * FROM users WHERE id = %s" % user_id)

# String concatenation with format
query = "SELECT * FROM users WHERE name = '{}'".format(name)
```

**Safe Patterns:**
```python
# Parameterized queries
cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))
cursor.execute("SELECT * FROM users WHERE id = :id", {"id": user_id})

# ORM usage
User.objects.filter(id=user_id)
session.query(User).filter_by(id=user_id)
```

### Java

**Dangerous Patterns:**
```java
// String concatenation
Statement stmt = conn.createStatement();
stmt.executeQuery("SELECT * FROM users WHERE id = " + userId);

// String format
String query = String.format("SELECT * FROM users WHERE name = '%s'", name);
```

**Safe Patterns:**
```java
// PreparedStatement
PreparedStatement pstmt = conn.prepareStatement("SELECT * FROM users WHERE id = ?");
pstmt.setInt(1, userId);

// JPA/Hibernate named parameters
Query query = em.createQuery("SELECT u FROM User u WHERE u.id = :id");
query.setParameter("id", userId);
```

## Detection Regex

```regex
# JavaScript/TypeScript template literal injection
(query|execute|sql|raw)\s*\(\s*`[^`]*\$\{[^}]+\}[^`]*`

# JavaScript string concatenation
(query|execute|sql)\s*\(\s*[`'"].*\s*\+\s*(?![\s]*[`'"])

# Python f-string injection
cursor\.execute\s*\(\s*f['\"]

# Python % formatting
cursor\.execute\s*\([^)]*%\s*(?!\s*\()

# Java Statement.execute with concatenation
(executeQuery|executeUpdate)\s*\([^)]*\+[^)]*\)
```

## False Positive Indicators

- **Constant concatenation only**: `"SELECT * FROM " + TABLE_CONSTANT` where TABLE_CONSTANT is a constant
- **Logging statements**: `console.log("Query: " + query)` or `logger.debug(sql)`
- **Test files**: `*.test.ts`, `*.spec.js`, `__tests__/*`
- **Comments or documentation**: SQL in markdown or docstrings
- **Column/table whitelisting**: Dynamic column with validation against whitelist

## Reachability Analysis

To confirm exploitability, trace data flow:
1. **Source**: User input (req.body, req.params, req.query, form data)
2. **Sink**: Database query execution function
3. **Sanitization**: Check for parameterization, validation, or escaping

## Remediation

### Immediate Actions
1. Replace string concatenation with parameterized queries
2. Use ORM methods instead of raw SQL
3. Add input validation for expected formats

### Code Examples

**Before (Vulnerable):**
```javascript
app.get('/user/:id', (req, res) => {
  const query = `SELECT * FROM users WHERE id = ${req.params.id}`;
  db.query(query, (err, result) => res.json(result));
});
```

**After (Secure):**
```javascript
app.get('/user/:id', (req, res) => {
  const query = 'SELECT * FROM users WHERE id = $1';
  db.query(query, [req.params.id], (err, result) => res.json(result));
});
```

## Confidence Scoring

| Factor | Score Impact |
|--------|-------------|
| User input flows to query | +0.4 |
| No parameterization found | +0.3 |
| Database function identified | +0.2 |
| In production code | +0.1 |
| Test file | -0.5 |
| Validated input | -0.3 |
| Constant values only | -0.5 |

**Report threshold**: >= 0.7
