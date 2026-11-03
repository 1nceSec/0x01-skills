# Race Conditions Detection Module

Race conditions occur when concurrent operations access shared state without proper synchronization → duplicate state changes, quota bypasses, financial abuse, privilege escalation. Every read-modify-write sequence and multi-step workflow is potentially vulnerable.

## Critical Impact
- **Financial Loss**: Double spend, over-issuance of credits/refunds, duplicate payments
- **Policy Bypass**: Quota violations, single-use token reuse, rate limit evasion
- **Data Integrity**: Negative counters, duplicate records, inconsistent aggregates
- **Privilege Escalation**: Concurrent role updates, permission bypass

---

## Code Pattern Categories

### 1. Read-Modify-Write Without Atomicity

```java
// Java - Non-atomic balance update
int balance = getBalance(userId);
if (balance >= amount) {
    setBalance(userId, balance - amount);  // Race window!
}

// Vulnerable counter increment
int count = cache.get(key);
cache.set(key, count + 1);  // Lost updates possible

// Database read-modify-write without row lock
User user = userRepo.findById(id);
user.setBalance(user.getBalance() - amount);
userRepo.save(user);  // SELECT then UPDATE - race window
```

```python
# Python - File-based counter
with open('counter.txt', 'r') as f:
    count = int(f.read())
with open('counter.txt', 'w') as f:
    f.write(str(count + 1))  # Race between read and write

# Redis non-atomic operations
balance = redis.get(f'balance:{user_id}')
if int(balance) >= amount:
    redis.set(f'balance:{user_id}', int(balance) - amount)  # Race!

# Django ORM update without F()
user = User.objects.get(id=user_id)
user.credits -= cost
user.save()  # SELECT then UPDATE
```

```go
// Go - Map access without mutex
count := counterMap[key]
counterMap[key] = count + 1  // Race condition

// Non-atomic file operations
data, _ := ioutil.ReadFile("state.json")
state := parseState(data)
state.Count++
ioutil.WriteFile("state.json", marshal(state), 0644)  // Race window
```

---

### 2. Multi-Step Operations with Gaps

```java
// Check-then-act pattern
if (couponService.isValid(code)) {
    // Gap - coupon could be used by another thread
    applyDiscount(code);
    couponService.markUsed(code);  // Duplicate usage possible
}

// Inventory reservation
if (inventory.getStock(productId) > 0) {
    // Race window - stock could go negative
    createOrder(productId);
    inventory.decrementStock(productId);
}

// Multi-phase payment
String authId = paymentGateway.authorize(amount);
// Gap - could be captured multiple times
paymentGateway.capture(authId);
updateUserBalance(authId);
```

```python
# Token consumption
if not token_used_set.contains(token):
    # Gap - token could be reused concurrently
    perform_action()
    token_used_set.add(token)

# Seat reservation
if get_available_seats(event_id) > 0:
    # Race - seats could be overbooked
    create_reservation(user_id, event_id)
    decrement_seats(event_id)
```

**Detection Rules:**
- Conditional blocks where state is checked then modified in separate operations
- Time gaps between validation and action (check -> reserve -> commit)
- Sequences: `isValid() -> use()`, `hasBalance() -> deduct()`, `checkStock() -> decrement()`

---

### 3. Idempotency Control Weaknesses

```java
// Inadequate idempotency key scope
String idempKey = request.getHeader("Idempotency-Key");
if (!processedKeys.contains(idempKey)) {
    // Missing principal/user scope - key reusable across users!
    processPayment();
    processedKeys.add(idempKey);
}

// Cache-before-commit window
@Transactional
public void processOrder(String idempKey) {
    cache.set(idempKey, "processing");  // Written before TX commits
    // If multiple requests hit here concurrently...
    createOrder();
    // TX commits later - multiple orders created
}

// Short TTL idempotency
if (!redis.exists(idempKey) || redis.ttl(idempKey) < 0) {
    // TTL too short - key could be reused after expiry
    processRefund();
    redis.setex(idempKey, 60, "done");  // Only 60 seconds
}
```

```python
# Application-level deduplication
if idempotency_key not in processed_cache:
    send_email(user)  # Side effect occurs
    credit_account(user)  # Side effect occurs
    processed_cache[idempotency_key] = True
    return {"status": "success"}
return processed_cache[idempotency_key]  # Returns cached response only!
# Problem: Side effects happened despite duplicate detection
```

**Detection Signals:**
- Idempotency keys without user/principal scoping
- Cache writes before transaction commits
- TTL shorter than reasonable retry windows (< 24 hours for financial ops)
- Deduplication that returns cached responses but doesn't prevent side effects

---

### 4. Optimistic Concurrency Missing or Weak

```java
// No version checking
@Entity
public class Account {
    // Missing @Version annotation!
    private Long id;
    private BigDecimal balance;
}

// Optional version not enforced
public void updateUser(UserDTO dto) {
    User user = repo.findById(dto.getId());
    // dto.version exists but never checked!
    user.setEmail(dto.getEmail());
    repo.save(user);
}

// ETag/If-Match ignored
@PutMapping("/resource/{id}")
public Resource update(@PathVariable Long id,
                       @RequestBody Resource resource,
                       @RequestHeader(value="If-Match", required=false) String etag) {
    // etag parameter exists but never validated!
    return repo.save(resource);
}
```

```python
# Django without select_for_update
user = User.objects.get(id=user_id)
# Concurrent updates will overwrite each other
user.role = 'admin'
user.save()

# Missing version field enforcement
# Model has 'version' field but it's not used in query
User.objects.filter(id=user_id).update(role='admin')  # Bypasses version check
```

---

### 5. Unique Constraint Violations

```java
// Existence check outside database
if (!userRepo.existsByEmail(email)) {
    // Race window - duplicate users possible
    User user = new User(email);
    userRepo.save(user);  // Could fail with constraint violation
}

// Upsert without proper conflict handling
User user = userRepo.findByEmail(email);
if (user == null) {
    user = new User(email);
} else {
    user.setLastLogin(now());
}
repo.save(user);  // Race - duplicate inserts possible
```

```python
# Check-then-create pattern
if not User.objects.filter(email=email).exists():
    # Race window
    User.objects.create(email=email)  # IntegrityError possible under concurrency

# Missing unique constraint
class Coupon(models.Model):
    code = models.CharField(max_length=50)  # No unique=True!
    used = models.BooleanField(default=False)
```

---

### 6. Cross-Service Race Conditions

```java
// Saga without compensation guards
@Transactional
public void createOrder(OrderRequest req) {
    Order order = orderRepo.save(new Order(req));
    // Async event published
    eventBus.publish(new OrderCreatedEvent(order.getId()));
    // If compensation runs before this commits...
}

// Eventual consistency windows
public void transferFunds(Long fromUser, Long toUser, BigDecimal amount) {
    accountServiceA.deduct(fromUser, amount);
    // Network delay / async processing
    // Service B may not see the deduction yet
    accountServiceB.credit(toUser, amount);
    // User could withdraw from B before A's write is visible
}

// At-least-once delivery without idempotent consumers
@RabbitListener(queues = "payment-queue")
public void handlePayment(PaymentMessage msg) {
    // Message could be delivered multiple times
    processPayment(msg.getAmount());  // Duplicate charges!
    sendConfirmationEmail(msg.getUserId());
}
```

**Detection Rules:**
- Async event publishing before transaction commits
- Cross-service calls without idempotency keys
- Message consumers that aren't idempotent
- Sagas/compensations without state machines or locking

---

### 7. Rate Limit & Quota Bypass

```java
// Non-atomic counter updates
int currentCount = rateLimitCache.get(userId);
if (currentCount < LIMIT) {
    // Race - counter could be exceeded
    rateLimitCache.set(userId, currentCount + 1);
    processRequest();
}

// Per-connection enforcement
@RateLimiter(permitsPerSecond = 10, scope = SCOPE.CONNECTION)
public Response apiEndpoint() {
    // User can bypass by opening multiple connections
}

// Sharded counter without coordination
int shard = userId % NUM_SHARDS;
int count = shardedCounters[shard].incrementAndGet();
// Other shards' counts not checked - quota can be exceeded
```

```python
# Cache-based rate limit with race
current = cache.get(f'rate:{user_id}') or 0
if current < RATE_LIMIT:
    cache.set(f'rate:{user_id}', current + 1)  # Race window
    process_request()
else:
    raise RateLimitExceeded()
```

---

## Special Contexts

### GraphQL Concurrent Mutations

```graphql
mutation {
  refund1: processRefund(orderId: 123) { status }
  refund2: processRefund(orderId: 123) { status }
}
```

**Detection:**
- Batch mutations without per-mutation idempotency
- Resolver-level lack of atomicity
- Parallel execution without coordination

### WebSocket Concurrent Messages

```javascript
// Client sends rapid-fire messages
ws.send(JSON.stringify({action: 'buy', itemId: 1}));
ws.send(JSON.stringify({action: 'buy', itemId: 1}));
```

**Detection:**
- Per-connection authorization only (not per-message)
- Message handlers without idempotency keys
- State mutations without synchronization

### File Upload Race

```java
// Multi-part upload finalization
public void completeUpload(String uploadId) {
    List<Part> parts = getUploadedParts(uploadId);
    // Concurrent completeUpload calls can create duplicate files
    String fileKey = mergePartsToFile(parts);
    recordFileInDatabase(fileKey);
}
```

---

## Detection Checklist

### High-Risk Code Patterns
- [ ] Read-modify-write without atomic operations (`SELECT` then `UPDATE`)
- [ ] Check-then-act sequences (balance check -> deduct, stock check -> reserve)
- [ ] Idempotency keys without user/principal scope
- [ ] Missing `@Version` annotations on entities with concurrent updates
- [ ] Existence checks (`exists()`) before insert operations
- [ ] Cache writes before transaction commits
- [ ] Non-atomic counter increments (Redis `GET` then `SET`)
- [ ] Rate limiting without atomic operations
- [ ] Message/event consumers without idempotency
- [ ] Cross-service workflows without compensation guards

### High-Risk Operations
- [ ] Financial transactions (payments, refunds, credits)
- [ ] Coupon/discount application
- [ ] Single-use token consumption (OTP, magic links, password reset)
- [ ] Inventory/quota management
- [ ] Seat/resource reservation systems
- [ ] Role/permission updates
- [ ] File upload finalization
- [ ] Background job state transitions

### Framework-Specific Indicators

**Spring/JPA:**
- Missing `@Version` on entities
- `@Transactional` without proper isolation level
- No `@Lock(LockModeType.PESSIMISTIC_WRITE)` on concurrent updates
- Custom queries without version checks

**Django:**
- `.save()` without `.select_for_update()`
- Update without `F()` expressions
- Missing `unique=True` on fields that should be unique
- No transaction isolation level set

**Go:**
- Map access without `sync.Mutex`
- File operations without `flock`
- Database operations without `FOR UPDATE`
- Channel operations without proper synchronization

**Node.js:**
- Async operations without proper locking (redlock, etc.)
- MongoDB updates without `$inc` or atomic operators
- Cache operations without atomic primitives

---

## Severity Assessment

**Critical:**
- Financial operations without atomicity (payments, refunds, balance updates)
- Single-use token reuse vulnerabilities
- Quota/rate limit bypass allowing unbounded resource consumption
- Inventory systems allowing negative stock or over-booking

**High:**
- Role/permission race conditions
- Coupon/discount duplicate application
- Data integrity violations (duplicate records, lost updates)
- Cross-service race conditions in critical workflows

**Medium:**
- Non-critical counter race conditions
- Audit log ordering issues
- Cache consistency race conditions
- Non-financial resource allocation races

---

## PoC Examples
```bash
# Concurrent deduction/inventory
seq 1 50 | xargs -I{} -P50 curl -s "https://api.example.com/purchase?item=1"

# HTTP/2 concurrent
h2load -n100 -c20 https://api.example.com/checkout

# Redis atomicity gap
redis-cli INCR account:1:balance &
```

---

## References

- OWASP: Time-of-check Time-of-use (TOCTOU)
- CWE-362: Concurrent Execution using Shared Resource with Improper Synchronization
- CWE-366: Race Condition within a Thread
- CWE-367: Time-of-check Time-of-use (TOCTOU) Race Condition
