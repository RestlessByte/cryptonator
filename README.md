# 🔐 Cryptography function for security request data 
## 🔑 Wee using N - count key for decrypt data witch client on server
### On server encrypt data other crypto function 'server.ts'

# How using?
```bash
#!/bin/bash
path=$(pwd)
cd 
git clone git@github.com:RestlessByte/cryptonator.git
cp -r cryptonator "$path"
```
```ts
/** EXAMPLE DECRYPTION DATA*/
    const body = req.body
    const {data} = body
    const decrypted = await decryptedDataClient(data, DecryptedKeys);
    const {users} = decrypted
    const {id} = users
/** EXAMPLE ENCRYPTINON DATA*/
  const db = await database('SELECT * FROM users WHERE id = $1',[id])
  const encrypted = await decryptedDataClient(dbResult.rows[0].items, serverDecryptedDataKeys)

```

```ts
/** EXAMPLE SERVER DECRYPTION DATA*/
import {  randomUUIDv7 } from 'bun';
    const body = req.body
    const {data} = body
    const decrypted = await quantDecryptedData(data, DecryptedKeys);
    const {users} = decrypted
    const {id, first_name last_name} = users
/** EXAMPLE SERVER ENCRYPTINON DATA*/
  const token = randomUUIDv5()
  const db = await database('INSERT INTO users (first_name,last_name,token) VALUES ($1,$2,$3)',[ await quantEncryptedData(first_name, serverDecryptedDataKeys),await quantEncryptedData(last_name, serverDecryptedDataKeys), token])
  const encrypted = decryptedDataClient(token, serverDecryptedDataKeys)

```
