# All-Ears Mail #

All-Ears Mail is a private email solution. It was designed from the ground up to know the least amount of information about its users, and to keep that information private to the maximum extent. The other design goals are simplicity, reliability, and efficiency.

All-Ears consists of a number of processes, which are divided into three tiers, creating a barrier between the public-facing processes and sensitive data.

The top-tier process, Manager, has full access to all data, but only has one purpose: to start the other processes and give them the data they need at startup.

The middle-tier processes, Account and Storage, have direct access to user data, but are only accessible through a local Unix socket requiring an Access Key.

The bottom-tier processes, API and MTA, are publically accessible, but have no direct access to user data. They are given Access Keys by Manager, which enable them to request the middle-tier processes to perform specific functions needed for their operation.

Manager starts Account and Storage automatically. Web, API, and MTA processes need to be started manually (using ManagerClient), and multiple of them can be run simultaneously.

Logging is kept to a minimum, and is mostly done in case of errors. All log messages are sent to syslog's mail facility.

All-Ears consists of the following parts:
1. [Manager](#allears-manager)
2. [Account](#allears-account)
3. [Storage](#allears-storage)
4. [Web](#allears-web)
5. [API](#allears-api)
6. [MTA](#allears-mta)
7. [Utilities](#utilities)

General information:
* [Users](#users)
* [Addresses](#addresses)
* [Messages](#messages)
* [Files](#files)
* [Signals](#signals)
* [Dependencies](#dependencies)

- - - -

## AllEars-Manager ##

AllEars-Manager is the main server program. It sets up the environment for All-Ears to run, and interacts with `ManagerClient` (see [Utilities](#utilities)) on port 940 to start/stop processes remotely.

At startup, Manager asks for the Master Key, used to decrypt files stored in `/etc/allears`. After this, no further interaction on the console is needed. Manager ignores `SIGHUP`, allowing closing the terminal and disconnecting SSH.

Manager creates a secure environment for each process to run in. Each new process is chrooted to its own tmpfs created for its needs. System resource limits are also set to levels appropriate for the process type. Manager sends each process the data it needs through a temporary one-way pipe, which is closed immediately afterwards.

Manager runs as root, while all other programs are started as the `allears` user. The service port binding capability is kept if needed, and dropped once the port is bound.

Shutting down Manager terminates all other All-Ears processes (see [Signals](#signals)).

## AllEars-Account ##

AllEars-Account manages, serves, and stores all user (see [Users](#users)) and address (see [Addresses](#addresses)) information.

AllEars-API and AllEars-MTA connect to it, each with their own Access Key. Depending on which key was used, only functions relevant to that particular type of process are allowed.

## AllEars-Storage ##

AllEars-Storage handles the storage and retrieval of encrypted message data (see [Messages](#messages)).

AllEars-API and AllEars-MTA connect to it, each with their own Access Key. Depending on which key was used, only functions relevant to that particular type of process are allowed.

Message data is stored in the file `/var/lib/allears/Storage.aem`, encrypted with AES-ECB using the Storage Key. Deleted messages are overwritten with zeroes.

An index of messages is kept, containing the owner's public key, the position/size of the data in Storage.aem. This index is stored in `/var/lib/allears/Stindex.aem`, encrypted with libsodium's Secret Box using the Stindex Key.

With the current design, AllEars-Storage is capable of storing up to 32 GiB of data, with individual messages being 1 to 128 KiB in size.

## AllEars-Web ##

AllEars-Web is a simple, high-security web server. Its use is optional: the open web API provided by AllEars-API is usable by any website or client.

The server is designed for single-page sites, supporting one HTML file in addition to its own static, built-in responses (such as MTA-STS).

All other files are designed to be hosted externally. This makes the client-side code easier to verify, and [SRI](https://en.wikipedia.org/wiki/Subresource_Integrity) protects the integrity of the files.

AllEars-Web is the only process type to run completely isolated with no capability to interact with others.

Invalid requests are dropped without response. Only high-security HTTPS is supported, and clients are required to support Brotli compression.

## AllEars-API ##

AllEars-API provides an open web API to clients, such as websites or dedicated client programs.

API requests and responses are both encrypted with libsodium's Box, which provides [both authentication and confidentiality](https://en.wikipedia.org/wiki/Authenticated_encryption).

All requests use the POST method with the same amount of data, and all API URLs are the same length.

Invalid requests, such as those made without a registered public key, are dropped without response.

AllEars-Account and AllEars-Storage are contacted through Unix sockets.

## AllEars-MTA ##

AllEars-MTA runs the Mail Transfer Agent service, accepting email from other servers on the internet.

Received email is processed for compactness and simplified formatting. The public key of the owner of the receiver address is looked up through AllEars-Account, and the message is stored through AllEars-Storage.

## Utilities ##

The `utils` folder contains miscellaneous utilities:
* `Accgen`: Generates Account.aem
* `Keygen`: Generates key files
* `CertCrypt`: Encrypts the TLS certificate and private key
* `FileCrypt`: Encrypts index.html, compresses and adds the HTTP headers
* `ManagerClient`: A client for AllEars-Manager

- - - -

## Users ##

AllEars-Account allocates 4 KiB for each user, storing:
* The type, flags (settings), and Argon2 hash for each address (see [Addresses](#addresses))
* The user's public key
* The user's membership level
* The `private` data field

The `private` data field can be used by clients to store 3363 bytes of arbitrary data. Its contents are sent with each `account/browse` API request, and it can be updated using the `private/update` API. The server does nothing with the data, and it can technically be used by clients for any purpose. The official clients encrypt it with libsodium's Sealed Box using the user's public key, and use it to store Address/Gatekeeper/Contacts data.

User data is held in memory by AllEars-Account, and written to `/var/lib/allears/Account.aem`. Prior to writing, the data is padded to a multiple of 1024 users (4 MiB), and encrypted with libsodium's Secret Box using the Account Key.

### Addresses ###

All-Ears provides its users with two types of addresses. Normal addresses are 1-23 characters, and are chosen by the user. Shield addresses are 24 characters, and are randomly generated by the server.

All-Ears uses a custom five-bit encoding (Addr32) to fit all addresses into 15 bytes. The Addr32 form is used to create a 13-byte Argon2 hash, which is stored by All-Ears.

Addr32 supports the lowercase letters a-z and the digits 0-9. Because the encoding only has space for 32 characters, the characters `1/i/l`, `0/o`, and `v/w` are treated as equivalent. Uppercase characters are converted to their lowercase equivalents, and all other characters are ignored. Therefore, the canonical form of `johnsmith` is `j0hnsm1th`, and `+j0--#hN..smLt+H+_` is a valid alias for it.

No record is kept of deleted addresses. Once deleted, addresses are immediately available for registration. Shield addresses are randomly generated by the server, and therefore virtually impossible to re-register once deleted.

Normal addresses are created privately client-side. The server only receives the final Argon2 hash.

Updating (changing settings) and deleting addresses is always done with the hash, and do not reveal the actual address to the server.

While the server does not directly know the real address (only its hash), it is easy to hash an address converted to Addr32 to see if a match is found in the records. But because the hashes are only 87% of the size of the original (13/15), collisions (false positives) are guaranteed. This means that while the user receives email sent to that address (if enabled), they did not necessarily register it (it may be an unintended alias).

Because addresses are simple to register and delete, addresses are not strictly tied to accounts. No history is kept, and therefore it can only be learned that the address is _currently_ held by that account.

Overall, the low value of address data and the high cost of large numbers of Argon2 operations discourage snooping. The system is not designed to stop serious, targeted attacks. Nor is there meaningful protection if an address is easily guessed, or is known from outside sources (such as sent emails, or website registrations).

## Messages ##
All-Ears has four types of messages:

* Email
* Internal mail
* Uploaded files
* Textual notes

All messages are encrypted with libsodium's Sealed Box using the user's public key. Email is encrypted by the server at reception, while all others are encrypted by the client prior to sending. All are indistinguishable--it is impossible to tell what type a message is (or what its contents are) without the user's Secret Key.

All messages are padded to the nearest 1 KiB prior to encryption, making message sizes only approximate. No timestamps or other metadata are available without the user's Secret Key.

On a technical level, messages are split into two parts: the headers (HeadBox) and the body (BodyBox). The HeadBox is always generated by the server, and contains varying amounts of metadata depending on the type. The BodyBox contains the actual data, and is generated by the client for all types except email.

## Files ##

Manager loads the following files from `/etc/allears`. Each is encrypted with libsodium's Secret Box using the Master Key, and needs to be generated by the relevant utility in `utils` (see [Utilities](#utilities)).

Server keys:
* API.key: Asymmetric key used by allears-api to securely communicate with API clients
* Account.key: Symmetric key used to encrypt user data prior to storage
* Manager.key: Symmetric key used to communicate with allears-manager
* Stindex.key: Symmetric key used to encrypt the message index prior to writing on disk
* Storage.key: Symmetric key used to encrypt message data prior to writing on disk

Salts:
* Normal.slt: Public salt for hashing Normal addresses
* Shield.slt: Secret salt for hashing Shield addresses
* Fake.slt: Secret salt for generating deterministic fake responses

TLS:
* TLS.crt: The TLS certificate
* TLS.key: The TLS private key

Web:
* index.html: The HTML file for the web interface

## Signals ##

Shutting down All-Ears should be done by sending a signal, either `SIGUSR1` or `SIGUSR2`, to AllEars-Manager.

`SIGUSR1` is the normal shutdown signal, allowing for a 'clean' exit. This tells the processes to shut down after dealing with any currently connected clients, which may take some time.

`SIGUSR2` is the fast shutdown signal, asking for an immediate shutdown. This should be used with caution, as it may cause corruption in some cases.

In both cases, any keys held in memory are wiped prior to exiting.

Other signals:
* `SIGINT`, `SIGQUIT`, and `SIGTERM` are treated by Manager as `SIGUSR1`, and as `SIGUSR2` by all other processes
* `SIGHUP` is ignored by Manager, and treated as `SIGUSR2` by all other processes
* `SIGKILL` prevents running the normal exit routines, such as wiping keys from memory, and as such should not be used

## Dependencies ##

Several of the programs make use of:
* [mbed TLS](https://tls.mbed.org) for TLS
* [libsodium](https://libsodium.org) for cryptography
* [Brotli](https://github.com/google/brotli) for compression

AllEars-MTA:
* Geolocates email senders thanks to [MaxMind](https://dev.maxmind.com/geoip/geoip2/downloadable/).
* Converts text to Unicode with [ICU](http://site.icu-project.org/home)
