# All-Ears Mail #

## Status ##

[![Total alerts](https://img.shields.io/lgtm/alerts/g/emp-code/aem-server.svg?logo=lgtm&logoWidth=18)](https://lgtm.com/projects/g/emp-code/aem-server/alerts/)

[![CodeFactor](https://www.codefactor.io/repository/github/emp-code/aem-server/badge)](https://www.codefactor.io/repository/github/emp-code/aem-server)

[![Codacy Badge](https://app.codacy.com/project/badge/Grade/4e8af7693f564192a9570cc6e8ee076f)](https://www.codacy.com/gh/emp-code/aem-server/dashboard?utm_source=github.com&amp;utm_medium=referral&amp;utm_content=emp-code/aem-server&amp;utm_campaign=Badge_Grade)

[![Code Inspector](https://www.code-inspector.com/project/5719/score/svg)](https://frontend.code-inspector.com/public/project/5719/aem/dashboard)

## Introduction ##

All-Ears Mail is a private email solution. It was designed from the ground up to know the least amount of information about its users, and to keep that information private to the maximum extent. The other design goals are simplicity, reliability, and efficiency.

All-Ears uses several process types, divided into three tiers. The design minimizes the power of public-facing processes, isolating them from sensitive data.

The top-tier process, Manager, has full access to all data, but only has one purpose: to start the other processes and give them the data they need at startup.

The middle-tier processes, Account and Storage, have direct access to user data, but are only accessible through a local Unix socket requiring an Access Key. Enquiry functions similarly, but doesn't deal with user data.

The bottom-tier processes, API and MTA, are publically accessible, but have no direct access to user data. They can only request the middle-tier processes to perform specific functions needed for their operation. The final process type of this tier is Web, which is completely isolated from all other processes.

Manager starts Account and Storage automatically. API, MTA, and Web processes need to be started manually using ManagerClient, and multiple of them can be run simultaneously.

Logging is kept to a minimum, and is mostly done in case of errors. All log messages are sent to syslog's mail facility.

All-Ears consists of the following parts:
1. [Manager](#manager)
2. [Account](#account)
3. [Storage](#storage)
4. [Enquiry](#enquiry)
5. [Web](#web)
6. [API](#api)
7. [MTA](#mta)
8. [Utilities](#utilities)

General information:
* [Users](#users)
* [Addresses](#addresses)
* [Messages](#messages)
* [Files](#files)
* [Signals](#signals)
* [Dependencies](#dependencies)

- - - -

## Manager ##

Manager is the main server program. It sets up the environment for All-Ears to run, and interacts with ManagerClient (see [Utilities](#utilities)) on port 940 to start/stop processes remotely.

At startup, Manager asks for the Master Key, used to decrypt files stored in `/etc/allears`. After this, no further interaction on the console is needed.

Manager creates a secure environment for each process to run in. Processes are isolated through a variety of methods, including pivot_root, namespaces, cgroups, resource limits, and minimizing privileges. Manager sends each process the data it needs through a temporary one-way pipe, which is closed immediately afterwards.

Manager runs as root, while all other programs are started as the `allears` user.

Shutting down Manager terminates all other All-Ears processes (see [Signals](#signals)).

## Account ##

Account manages, serves, and stores all user (see [Users](#users)) and address (see [Addresses](#addresses)) information.

API and MTA connect to it, each with their own Access Key. Depending on which key was used, only functions relevant to that particular type of process are allowed.

## Storage ##

Storage handles the storage and retrieval of encrypted message data (see [Messages](#messages)).

API and MTA connect to it, each with their own Access Key. Depending on which key was used, only functions relevant to that particular type of process are allowed.

Message data is stored in `/var/lib/allears/MessageData`, encrypted with AES-256. All users have their own file; the file names are encrypted public keys.

An index of messages is kept, containing the owner's public key and message sizes. This index is stored in `/var/lib/allears/Stindex.aem`, encrypted with libsodium's Secret Box using a key derived from the Storage Key.

## Enquiry ##

Enquiry retrieves and stores information for API and MTA.

## Web ##

Web is a simple, high-security web server. Its use is optional: the API is usable by any website or client.

The server is designed for single-page sites, supporting one HTML file in addition to its own static, built-in responses (such as MTA-STS).

All other files are designed to be hosted externally. This makes the client-side code easier to verify, and [SRI](https://en.wikipedia.org/wiki/Subresource_Integrity) protects the integrity of the files.

Web is the only process type to run completely isolated with no capability to interact with others.

`web-clr` is the clearnet variant. Only high-security HTTPS is supported, and clients are required to support Brotli compression. It doesn't respond to invalid requests.

`web-oni` is the onion service variant using HTTP with Zopfli Deflate compression. It doesn't read requests at all, and simply responds to all connections with the HTML page.

## API ##

API serves an open web API, usable by any website or client.

Both requests and responses are encrypted with libsodium's Box, which provides [both authentication and confidentiality](https://en.wikipedia.org/wiki/Authenticated_encryption).

Both requests and responses use a custom binary format. Short responses and requests are designed to be the same size.

Invalid requests, such as those made without a registered public key, are dropped without response.

`api-clr` is the HTTPS clearnet variant, `api-oni` is the HTTP onion service variant.

## MTA ##

MTA receives email. It converts the received email into a custom binary format, including additional data.

## Utilities ##

The `Data` folder contains header files which supply data to various parts of All-Ears. They must be carefully configured/generated before compilation.

The `utils` folder contains:
* `Accgen`: Generates Account.aem
* `Keygen`: Generates key files
* `BinCrypt`: Encrypts the All-Ears executable files for Manager
* `ManagerClient`: Connects to Manager to get information about processes, and start or stop them

- - - -

## Users ##

aem-account allocates 4 KiB for each user, storing:
* The type, flags (settings), and hash for each address (see [Addresses](#addresses))
* The user's public key
* The user's membership level
* The `private` data field

The `private` data field can be used by clients to store up to 3,784 bytes. Its contents are sent with each `account/browse` API request, and it can be updated using the `private/update` API. Encrypted client-side, it stores data useful to the client but not needed by the server, such as the address relating to each hash.

Account holds the user data in memory, and writes it to `/var/lib/allears/Account.aem`. Prior to writing, it pads the data to a multiple of 1024 users (4 MiB), and encrypts it with libsodium's Secret Box using the Account Key.

### Addresses ###

All-Ears provides its users with two types of addresses. Normal addresses consist of 1 to 15 alphanumerics, and are chosen by the user. Shield addresses consist of 16 random alphanumerics, and are generated by the server.

All-Ears uses a custom five-bit encoding (Addr32) to fit all addresses into 10 bytes. The Addr32 form is used to create an 8-byte hash which the server stores. On receiving mail, the address is hashed, and the hash is checked to see if a user owns it.

The address encoding treats the characters `1/i/l`, `0/o`, and `v/w` as equivalent. Addresses are case-insensitive, and non-alphanumerical characters are ignored. Therefore, the canonical form of `johnsmith` is `j0hnsm1th`, and `+j0--#hN..smLt+H+_` is a valid alias for it.

Normal addresses are created privately client-side. They use a computationally-expensive Argon2 hash to make it difficult to reverse the hash back into the address.

Shield addresses are randomly generated by the server. Because they're impossible to guess, they use a fast and weak hash.

Updating (changing settings) and deleting addresses is always done with the hash, and do not reveal the actual address to the server.

No record is kept of deleted addresses. Once deleted, addresses are immediately available for registration.

| Normal                              | Shield           |
| ----------------------------------- | ---------------- |
| 1-15 alphanumerics                  | 16 alphanumerics |
| Expensive to guess                  | Impossible to guess |
| Unknown to the server until used    | Randomly generated by the server |
| Immediately available after deleted | Virtually impossible to re-register |
| All addresses act as if existing    | Non-existing addresses reject mail |
| High resource usage                 | Low resource usage |

## Messages ##
All-Ears has four types of messages:

* Email
* Internal mail
* Sent mail
* Uploaded files

Messages are stored in a custom binary format, padded and signed, and encrypted into a libsodium Sealed Box using the user's public key.

Received email is processed into a custom binary format. Information is converted, added, and deleted, with the goal of preserving useful information in the most compact form.

Internal mail includes options with, and without client-side encryption.

Uploaded files are encrypted client-side using the user's secret symmetric key, before further encryption by the server as with all messages.

All messages are encrypted one more time by Storage before being written to disk.

## Files ##

Manager loads these files from `/etc/allears`. All are encrypted with libsodium's Secret Box using the Master Key.

* bin: Folder containing the encrypted All-Ears binaries
* API.key: Asymmetric key used by API to securely communicate with clients
* Account.key: Symmetric key used by Account to encrypt user data prior to storage
* Manager.key: Symmetric key used by Manager to communicate with ManagerClient
* Shield.slt: Secret salt for hashing Shield addresses
* Signing.key: Key used for signing messages
* Storage.key: Key used for encrypting message data prior to writing on disk

## Signals ##

Shutting down All-Ears should be done by sending a signal, either `SIGUSR1` or `SIGUSR2`, to aem-manager.

`SIGUSR1` is the normal shutdown signal, allowing for a 'clean' exit. This tells the processes to shut down after dealing with any currently connected clients, which may take some time.

`SIGUSR2` is the fast shutdown signal, asking for an immediate shutdown. This should be used with caution, as it may cause corruption in some cases.

In both cases, any keys held in memory are wiped prior to exiting.

Other signals:
* `SIGINT`, `SIGQUIT`, and `SIGTERM` are treated by Manager as `SIGUSR1`, and as `SIGUSR2` by all other processes
* `SIGHUP` is ignored by Manager, and treated as `SIGUSR2` by all other processes
* `SIGKILL` prevents running the normal exit routines, such as wiping keys from memory, and as such should not be used

## Dependencies ##

* [mbed TLS](https://tls.mbed.org) for TLS
* [libsodium](https://libsodium.org) for cryptography
* [Brotli](https://github.com/google/brotli) and [Zopfli](https://github.com/google/zopfli) for compression
* [MaxMind GeoIP2](https://dev.maxmind.com/geoip/geoip2/downloadable/) for IP geolocation and ASN data
* [ICU](http://site.icu-project.org/home) for converting text to UTF-8
