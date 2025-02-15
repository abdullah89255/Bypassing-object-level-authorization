# Bypassing-object-level-authorization
Bypassing object-level authorization is a security vulnerability that occurs when an application does not properly enforce access control checks for specific resources or objects. This allows attackers to access, modify, or delete resources they are not authorized to interact with.

Here’s a breakdown of **object-level authorization bypass**, examples, and how to mitigate it:

---

### **How It Happens**
1. **Insufficient Authorization Checks**  
   The application fails to check whether the authenticated user has permission to access a specific object.
   
2. **Predictable or Exposed Object Identifiers**  
   Object identifiers (e.g., IDs in URLs or API parameters) are predictable, such as incremental numeric values (`/resource/123`) or easily guessable UUIDs.

3. **Lack of Role-Based Restrictions**  
   Users with lower privileges can access objects meant for administrators or other users due to missing role or privilege checks.

4. **Direct Object References (Insecure)**
   The application uses unvalidated direct references like `/api/data/456` without checking if the user has rights to access `456`.

---

### **Common Attack Scenarios**
1. **URL Manipulation**
   - A user with access to `/user/profile/1001` modifies the URL to `/user/profile/1002` to view another user's data.

2. **API Exploitation**
   - A user sends an API request for a resource they don’t own, like:
     ```
     GET /api/v1/orders/456
     ```
     If no ownership verification is performed, they can access someone else’s order details.

3. **Mass Assignment**
   - Attackers manipulate form inputs or API payloads to include properties they shouldn't have access to, like `isAdmin=true` or setting unauthorized object references.

---

### **Mitigation Techniques**
1. **Implement Proper Object-Level Authorization**
   - Verify that the current user is authorized to access the requested resource.
   - Implement checks based on roles, permissions, or ownership.

2. **Use Indirect Object References**
   - Replace direct identifiers (e.g., `orderID=456`) with opaque, hard-to-guess references (e.g., tokens or hashed IDs).

3. **Least Privilege Principle**
   - Ensure users have access only to the resources they need for their role.

4. **Centralized Authorization Logic**
   - Use a centralized system for handling object-level authorization rather than implementing ad hoc checks in different parts of the code.

5. **Secure API Design**
   - Validate all input parameters, especially those identifying objects.
   - Log access attempts and monitor for anomalies.

6. **Conduct Regular Testing**
   - Use automated tools and manual penetration testing to identify vulnerabilities.
   - OWASP ZAP and Burp Suite can help uncover object-level authorization flaws.

---

### **Example Secure Code**
```python
# Example: Flask API with Ownership Check
@app.route('/user/<int:user_id>', methods=['GET'])
@login_required
def get_user_profile(user_id):
    # Ensure the logged-in user owns the resource
    if user_id != current_user.id:
        abort(403)  # Forbidden
    user = User.query.get_or_404(user_id)
    return jsonify(user.to_dict())
```
Here are **specific examples** of object-level authorization vulnerabilities and corresponding solutions for various scenarios. These examples are tailored to highlight how attackers exploit weak access controls and how you can prevent such vulnerabilities.

---

### **Example 1: URL Manipulation**
**Scenario:**  
An e-commerce application has a user dashboard where users can view their orders via:  
`GET /orders/{order_id}`

**Exploit:**  
An authenticated user with access to `GET /orders/123` modifies the URL to `GET /orders/124` to view another user's order details. If there is no authorization check, the attacker gains unauthorized access.

**Solution:**  
Verify ownership of the resource:  
```python
@app.route('/orders/<int:order_id>', methods=['GET'])
@login_required
def get_order(order_id):
    # Fetch the order
    order = Order.query.get_or_404(order_id)
    
    # Ensure the logged-in user is the owner of the order
    if order.user_id != current_user.id:
        abort(403)  # Forbidden

    return jsonify(order.to_dict())
```

---

### **Example 2: Insecure API**
**Scenario:**  
An API allows users to update their profile via:  
`POST /api/v1/user/update`  
with a payload:
```json
{
  "user_id": 123,
  "email": "newemail@example.com"
}
```

**Exploit:**  
An attacker sends a modified payload:
```json
{
  "user_id": 124,  # Another user's ID
  "email": "hacker@example.com"
}
```

If the API does not verify the `user_id` against the logged-in user, the attacker updates another user's profile.

**Solution:**  
Ignore `user_id` from the payload and use the authenticated user's ID:  
```python
@app.route('/api/v1/user/update', methods=['POST'])
@login_required
def update_user():
    data = request.get_json()
    current_user.email = data.get('email')  # Update only the logged-in user's data
    db.session.commit()
    return jsonify({"message": "Profile updated successfully!"})
```

---

### **Example 3: Predictable Object Identifiers**
**Scenario:**  
A banking application allows users to access their transaction history via:  
`GET /transactions/{transaction_id}`

**Exploit:**  
Transaction IDs are sequential (e.g., `101, 102, 103`). An attacker guesses IDs and accesses transactions belonging to other users.

**Solution 1: Validate Ownership**  
```python
@app.route('/transactions/<int:transaction_id>', methods=['GET'])
@login_required
def get_transaction(transaction_id):
    transaction = Transaction.query.get_or_404(transaction_id)
    
    # Verify the transaction belongs to the logged-in user
    if transaction.user_id != current_user.id:
        abort(403)  # Forbidden

    return jsonify(transaction.to_dict())
```

**Solution 2: Use Indirect Identifiers**  
Instead of exposing `transaction_id`, use opaque tokens or UUIDs:  
```python
transaction_id = generate_uuid()  # Create a random, hard-to-guess identifier
```

---

### **Example 4: Mass Assignment Vulnerability**
**Scenario:**  
A web application allows users to update their profile via:  
```html
<input type="text" name="username" value="current_user">
<input type="text" name="isAdmin" value="false">
```

**Exploit:**  
An attacker modifies the `isAdmin` field in the form to `true`, gaining admin privileges.

**Solution:**  
Whitelist fields and ignore sensitive ones:  
```python
@app.route('/user/update', methods=['POST'])
@login_required
def update_profile():
    data = request.form
    current_user.username = data.get('username')  # Allow safe updates only
    db.session.commit()
    return jsonify({"message": "Profile updated!"})
```

---

### **Example 5: Lack of Role-Based Access Control**
**Scenario:**  
An admin dashboard endpoint exists at `/admin/dashboard`. A user without admin privileges navigates to this endpoint and gains unauthorized access.

**Solution:**  
Enforce role-based access controls (RBAC):  
```python
@app.route('/admin/dashboard')
@login_required
@admin_required  # Custom decorator for admin-only access
def admin_dashboard():
    return render_template('admin_dashboard.html')
```

**Custom Decorator:**  
```python
def admin_required(func):
    @wraps(func)
    def wrapper(*args, **kwargs):
        if not current_user.is_admin:
            abort(403)  # Forbidden
        return func(*args, **kwargs)
    return wrapper
```

---

### **Example 6: File Access via ID**
**Scenario:**  
A file-sharing platform stores files with IDs, e.g., `GET /files/{file_id}`, without verifying ownership.

**Exploit:**  
An attacker sends `GET /files/456`, accessing files they don't own.

**Solution:**  
Check ownership before providing access:  
```python
@app.route('/files/<int:file_id>', methods=['GET'])
@login_required
def get_file(file_id):
    file = File.query.get_or_404(file_id)
    
    # Ensure the user owns the file
    if file.user_id != current_user.id:
        abort(403)  # Forbidden

    return send_file(file.path)
```

---

### **Testing Object-Level Authorization**
- **Automated Tools:**  
  - **Burp Suite**: Use the "Repeater" tool to modify API requests and observe responses.
  - **OWASP ZAP**: Automate scanning for insecure direct object references (IDORs).

- **Manual Testing Steps:**  
  1. Test predictable object identifiers by incrementing/decrementing.
  2. Use low-privilege accounts to attempt access to high-privilege resources.
  3. Inject manipulated parameters in API requests.

Using **Burp Suite** for testing authorization vulnerabilities, including **object-level authorization bypass**, is a common practice. Here’s a step-by-step guide to identify and exploit such issues, along with examples and tips.

---

### **Step 1: Configure Burp Suite**
1. **Set Up Proxy**  
   - Configure Burp Suite as a proxy in your browser to intercept HTTP/HTTPS traffic.
   - Add your application's domain to the **target scope** to limit scanning.

2. **Enable Interception**  
   - Ensure interception is enabled for the requests you want to analyze.

3. **Set Up User Accounts**  
   - Prepare two user accounts:
     - **Low-privileged user** (e.g., regular user)
     - **High-privileged user** (e.g., admin or owner of resources)

---

### **Step 2: Manual Testing for Object-Level Authorization**
1. **Identify Object IDs**  
   - Browse the application as the low-privileged user and look for object identifiers (IDs) in:
     - URLs (`/orders/123`, `/users/456`)
     - Query parameters (`?id=789`)
     - JSON payloads (`{"order_id": 101}`)

2. **Intercept Requests**  
   - Use the **Proxy** tab to capture and modify requests.  
   Example request:  
   ```http
   GET /api/orders/123 HTTP/1.1
   Host: example.com
   Authorization: Bearer <low-privilege-user-token>
   ```

3. **Modify Object IDs**  
   - Change the `123` in the request to a value that you suspect might belong to another user (e.g., `124`).

4. **Send Modified Requests**  
   - Send the modified request to the server.  
   - Observe if unauthorized data is returned.

---

### **Step 3: Automate Testing with Burp Extensions**
1. **Use the Autorize Extension**  
   - **Autorize** automatically tests endpoints for authorization issues by replaying requests with tokens from other users.  
   Steps:
   - Install **Autorize** via the BApp Store.
   - Configure low-privilege and high-privilege tokens:
     - Paste the **low-privilege user token** as the unauthorized token.
     - Set the **high-privilege token** as the authorized token.
   - Enable **Autorize** to monitor requests in real-time.

2. **Analyze Results**  
   - Autorize highlights unauthorized access if a low-privileged user can access or manipulate high-privilege resources.

---

### **Step 4: Advanced Techniques**
1. **Parameter Fuzzing**  
   Use **Intruder** to automate testing for predictable object IDs:
   - Send the request to **Intruder**.
   - Define the parameter to fuzz (e.g., the `order_id` in `/orders/{order_id}`).
   - Use a payload generator (e.g., sequential numbers or wordlists) to test multiple IDs.

   Example fuzzing payload:
   ```
   101
   102
   103
   ...
   ```

2. **Session Hijacking**  
   Test if session tokens from one user work for another user:
   - Intercept requests from both accounts.
   - Replace the session token of the low-privileged user with the high-privileged user's token.
   - Send the modified request to see if unauthorized access is granted.

3. **JWT Manipulation**  
   - Decode JWT tokens using **jwt.io** or Burp's **JSON Web Token Editor**.
   - Test altering the `user_id` or `role` claims:
     - Example before:
       ```json
       { "user_id": 123, "role": "user" }
       ```
     - Example after:
       ```json
       { "user_id": 124, "role": "admin" }
       ```

4. **Mass Assignment**  
   - Send payloads with unexpected parameters to test if sensitive fields can be altered:
     ```json
     {
       "username": "user123",
       "isAdmin": true
     }
     ```

---

### **Example: Burp Suite in Action**
#### Application: Banking App
- Endpoint: `/api/v1/accounts/{account_id}`  
- Low-privilege user has access to `GET /api/v1/accounts/101`.

#### Steps:
1. **Capture and Modify Request**  
   Intercept the request and replace the account ID:
   ```http
   GET /api/v1/accounts/102 HTTP/1.1
   Host: bank.example.com
   Authorization: Bearer <low-privilege-user-token>
   ```

2. **Send the Request**  
   - Check if unauthorized data is returned.
   - Example unauthorized response:
     ```json
     {
       "account_id": 102,
       "balance": 5000,
       "owner": "HighPrivilegeUser"
     }
     ```

3. **Use Autorize**  
   - Configure tokens for low-privilege and high-privilege users.
   - Autorize flags access to `account_id=102` as unauthorized.

---

### **Step 5: Reporting Findings**
When you discover vulnerabilities:
1. Document the exact steps to reproduce the issue.
2. Provide HTTP request/response examples.
3. Highlight the impact (e.g., access to sensitive user data or privilege escalation).
4. Suggest fixes:
   - Enforce object-level authorization checks.
   - Use opaque identifiers (e.g., UUIDs).
   - Log and monitor unauthorized access attempts.

---

Here are additional **examples of Burp Suite techniques** to find and exploit authorization vulnerabilities in various scenarios, including APIs, file uploads, and more. Each example uses Burp Suite's features like **Proxy**, **Intruder**, and **Extensions**.

---

### **Example 18: API Endpoint Authorization Check**
#### Scenario:
A web application has an API endpoint for fetching sensitive financial data:  
```http
GET /api/v1/accounts/{account_id}
```

#### Steps in Burp Suite:
1. **Intercept a Legitimate Request**  
   Use a logged-in low-privilege user to send a request:
   ```http
   GET /api/v1/accounts/101 HTTP/1.1
   Authorization: Bearer <low-privilege-token>
   ```

2. **Modify the `account_id`:**
   Change `101` to `102` to test access to another user's account.

3. **Send Modified Request via Burp Repeater:**
   Send the modified request and observe the response:
   ```json
   {
     "account_id": 102,
     "balance": "5000.00",
     "owner": "other_user"
   }
   ```

4. **Automate Testing with Intruder:**
   - Send the request to **Intruder**.
   - Set the `account_id` as the payload position.
   - Use a sequential payload (e.g., numbers from `100` to `200`).

   **Intruder Response Analysis:**  
   If you receive valid responses for IDs other than your own, the API is vulnerable.

#### Solution:
Enforce ownership validation on the server:
```python
if account.owner_id != current_user.id:
    abort(403)  # Forbidden
```

---

### **Example 19: Hidden Admin Endpoints**
#### Scenario:
A hidden admin page exists at `/admin/panel`.

#### Steps in Burp Suite:
1. **Content Discovery:**
   - Use **Intruder** or **Content Discovery Extensions** like **Burp Buster** or **Content Discovery by BApp**.
   - Test for common admin paths (`/admin`, `/admin/panel`, `/admin/login`).

2. **Access the Endpoint:**
   Attempt to access the endpoint using a low-privilege user's session:
   ```http
   GET /admin/panel HTTP/1.1
   Authorization: Bearer <low-privilege-token>
   ```

3. **Bypass Login Page:**
   If the admin page is accessible without additional authentication, it indicates a serious vulnerability.

#### Solution:
Restrict access to admin endpoints using role-based access control (RBAC).

---

###  File Download Abuse**
#### Scenario:
A file-sharing app allows downloading shared files via:
```http
GET /files/{file_id}/download
```

#### Steps in Burp Suite:
1. **Capture a Download Request:**
   ```http
   GET /files/123/download HTTP/1.1
   Authorization: Bearer <low-privilege-token>
   ```

2. **Modify the `file_id`:**
   Change `123` to `124` and send it through **Burp Repeater**.

3. **Check the Response:**
   If the file belonging to another user is accessible, it indicates a lack of ownership validation.

#### Solution:
Validate file ownership in the backend:
```python
if file.owner_id != current_user.id:
    abort(403)
```

---

### **Example 21: JWT Manipulation**
#### Scenario:
An application uses JSON Web Tokens (JWTs) for authentication:
```http
Authorization: Bearer <jwt_token>
```

#### Steps in Burp Suite:
1. **Capture the JWT:**
   Use Burp Proxy to intercept a request with a valid JWT token.

2. **Decode and Modify the Token:**
   - Decode the JWT using **JWT Editor** in Burp Suite.
   - Modify claims like `user_id` or `role`:
     ```json
     {
       "user_id": 123,
       "role": "admin"
     }
     ```

3. **Re-Encode and Replay:**
   Replace the original JWT with the modified one and send the request:
   ```http
   GET /admin/panel HTTP/1.1
   Authorization: Bearer <modified-jwt-token>
   ```

4. **Check for Authorization Bypass:**
   If the server does not verify the token signature or claims, you may gain unauthorized access.

#### Solution:
- Use strong JWT signing keys.
- Always verify JWT signatures and claims server-side.

---

### **Example 22: Bulk Actions**
#### Scenario:
An admin tool supports bulk user updates via:
```http
POST /admin/users/update
Payload:
{
  "user_ids": [101, 102, 103],
  "role": "admin"
}
```

#### Steps in Burp Suite:
1. **Capture the Request:**
   Intercept the request made by a legitimate admin.

2. **Replay as a Low-Privilege User:**
   Replace the admin's token with a low-privilege token.

3. **Modify the Payload:**
   Add unauthorized user IDs:
   ```json
   {
     "user_ids": [104, 105],
     "role": "admin"
   }
   ```

4. **Send the Request:**
   If the server processes the request, it indicates a mass-assignment or privilege escalation vulnerability.

#### Solution:
Validate all user IDs and roles in the payload:
```python
if not current_user.is_admin:
    abort(403)
```

---

### **Example 23: Bypassing Role Checks**
#### Scenario:
A user with a "user" role accesses endpoints intended for "admin" users:
```http
GET /admin/users HTTP/1.1
Authorization: Bearer <low-privilege-token>
```

#### Steps in Burp Suite:
1. **Modify the Request:**
   Intercept the request and change the role in the payload or token:
   ```json
   { "role": "admin" }
   ```

2. **Replay the Request:**
   If the server grants access, it indicates improper role validation.

#### Solution:
Implement strict role-based access control (RBAC) on all admin endpoints.

---

### **Example 24: IDOR in Account Transfers**
#### Scenario:
A banking application has a transfer endpoint:
```http
POST /api/transfer
Payload:
{
  "from_account": 101,
  "to_account": 102,
  "amount": 100
}
```

#### Steps in Burp Suite:
1. **Intercept and Modify the Request:**
   Change `from_account` to an account ID that doesn’t belong to the logged-in user.

2. **Replay the Request:**
   If the transfer succeeds, the API is vulnerable to IDOR.

#### Solution:
Validate ownership of `from_account`:
```python
if from_account.owner_id != current_user.id:
    abort(403)
```

---

### **Example 25: WebSocket Authorization**
#### Scenario:
A WebSocket API allows subscribing to chat rooms based on `room_id`.

#### Steps in Burp Suite:
1. **Intercept WebSocket Messages:**
   Use Burp Suite's WebSocket support to capture messages:
   ```json
   { "action": "subscribe", "room_id": "private-room-123" }
   ```

2. **Modify `room_id`:**
   Change the room ID to a private room not accessible by the current user.

3. **Send Modified Request:**
   If the user gains unauthorized access to private messages, it indicates a vulnerability.

#### Solution:
Validate room membership on subscription:
```python
if not current_user.is_member_of(room_id):
    abort(403)
```

---

### **Next Steps**
- Use **Burp Extensions** like **Autorize** and **JWT Editor** to automate common tests.
- Combine **Intruder** with fuzzing tools to identify predictable object IDs or roles.
- Document vulnerabilities clearly, including the exact steps to reproduce and suggestions for mitigation. 

By combining these techniques, Burp Suite becomes a powerful tool to uncover authorization vulnerabilities across various scenarios.
