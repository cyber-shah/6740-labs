# Server:
By design the server doesn't know who talks to whom. They are only responsible for auth/reg users.

#### Responsiblities
1. registers/auths users
2. manages user's PK and SK 
3. share a list all online users and their addresses

#### Key components:
- Storing : all PK and SK's are stored along with the username and password. 
- Encryption : entire DB can be encrypted using LUKS
- Security : ALL CONNECTIONS MUST BE WRAPPED AROUND TLS

# CA and Certs:
Cert generation is taken care by CA.
All certificates are signed by the CA and therefore can be verified by all the clients.

#### Responsiblities
Maintain Certificates (create, delete and update)
Store certs and ensure no repitation

#### Key components:
- Storing : Certificates are stored inside the `certs` path, no need to encrypt them.
- Encryption : How to make sure that the CA's SK is not leaked?
- Security : ONLY the server can talk to the CA

certificates are created for 24 hours

# Client:
Use message queues to store messages while someone is away?

Each client trusts only one party and that is the CA.

#### Responsiblities



#### Key components:
- Storing : PK and SK sent by the server is stored using TLS key. MUST be forgotten as the user logs out.
- Security : protect the PK and SK from leaking WHILE the user is using the application?
