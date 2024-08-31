# secret-store

Secrets manager for data to share with multiple people on the same machine. Based on SSH Keys.


## Basics

To understand how the secret store works, there are two types of objects to know:
- The **store** which is a container that contains specifics data to keep secret.
- The **Identity** which is an asymmetric keys pair linked to each ssh keys present in the ssh agent.


Stores are encrypted with symmetric encryption (*ChaCha20*) and the encryption key is, for each identity, encrypted with the asymmetric public key.  
For the asymmetric encryption, secret-store uses HPKE (Hybrid Public Key Encryption) and EC (p-256).


When creating a store, all the compatible ssh keys (deterministic signature algorithm needed), will have the store encryption key encrypted with the public key of the linked identity.


## How to use

Do not hesitate to use `-h` for each command to get all the possibilities

### Identity

```shell
$ secret-store identity -h
usage: secret-store identity [-h] {sync,list} ...

positional arguments:
  {sync,list}
    sync       Create missing identities for available ssh keys
    list       List identities

options:
  -h, --help   show this help message and exit
```

First, create identities for ssh keys loaded in the ssh-agent.
```shell
$ secret-store identity sync
Created: SHA256:YdzCBLphCtRGeXboK2kKu6/lnWY/MAyflEunvS8FocQ
Created: SHA256:nUeAjSrgC6XZqTvMqQVg5MTK2DtJ/v11ig/puz7rtww
```

Two compatibles keys were found so two identities where created.
```shell
$ secret-store identity list
SHA256:YdzCBLphCtRGeXboK2kKu6/lnWY/MAyflEunvS8FocQ
SHA256:nUeAjSrgC6XZqTvMqQVg5MTK2DtJ/v11ig/puz7rtww
```


### Store

```shell
$ secret-store store -h
usage: secret-store store [-h] {new,show,list,rm,share} ...

positional arguments:
  {new,show,list,rm,share}
    new                 Create a new store
    show                Show the store data
    list                List owned stores
    rm                  Remove a store
    share               Share the store with an identity

options:
  -h, --help            show this help message and exit
```

Now, a store can be created
```shell
$ secret-store store new api username
Set username value: admin
```
By using `-s`, the input will be considered as secret
```shell
secret-store store new -s api token
Set token value:
```

The store is now created
```shell
$ secret-store store show api
=== api ===
username: admin
token: abc
```

It is possible to share a store with an identity
```shell
$ secret-store store share api 'SHA256:nUeAjSrgC6XZqTvMqQVg5MTK2DtJ/v11ig/puz7rtww'
```
