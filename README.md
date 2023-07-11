# spassman


Even username is encrypted

- Every login gets a unique 256 key and nonce
- Every login key is then encrypted with master password, derivced with argon2i
- Randomly padded



## Secure memory wiping:

Memory wiping is used to protect secret data or key material from attackers with access to deallocated memory. This is a defense-in-depth measure against vulnerabilities that leak application memory.

Many cryptography APIs which accept bytes also accept types which implement the buffer interface. Thus, users wishing to do so can pass memoryview or another mutable type to cryptography APIs, and overwrite the contents once the data is no longer needed.

However, cryptography does not clear memory by default, as there is no way to clear immutable structures such as bytes. As a result, cryptography, like almost all software in Python is potentially vulnerable to this attack. The CERT secure coding guidelines assesses this issue as “Severity: medium, Likelihood: unlikely, Remediation Cost: expensive to repair” and we do not consider this a high risk for most users.


