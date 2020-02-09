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
8. [Web front-end](#webfront-end)

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

Message data is stored in the file `/var/lib/allears/Message.aem`, encrypted using the Storage Key. Deleted messages are overwritten with zeroes.

An index of messages is kept, containing the owner's public key, the position/size of the data in Message.aem. This index is stored in `/var/lib/allears/Stindex.aem`, encrypted with the Stindex Key.

With the current design, AllEars-Storage is capable of storing up to 32 GiB of data, with individual messages being 1 to 128 KiB in size.

## AllEars-Web ##

AllEars-Web delivers the web interface assets: index.html, all-ears.js, main.js, and main.css. Its use is optional: the open web API provided by AllEars-API is usable by any website or client.

The files, stored in encrypted containers in `/etc/allears`, are received from Manager at startup. The files include all headers, and their contents are simply placed in read-only memory protected by libsodium and served to visitors.

AllEars-Web is the only process type to run completely isolated with no capability to interact with others.

Invalid requests are dropped without response. Clients are required to support Brotli compression.

## AllEars-API ##

AllEars-API provides an open web API to clients, such as websites or dedicated client programs.

All requests use authenticated encryption (libsodium's Box), which is used to verify the user.

AllEars-Account and AllEars-Storage are contacted through Unix sockets.

Invalid requests are dropped without response.

## AllEars-MTA ##

AllEars-MTA runs the Mail Transfer Agent service, accepting email from other servers on the internet.

Received email is processed for compactness and simplified formatting. The public key of the owner of the receiver address is looked up through AllEars-Account, and the message is stored through AllEars-Storage.

## Utilities ##

The `utils` folder contains miscellaneous utilities:
* `Accgen`: Generates User.aem
* `Keygen`: Generates key files
* `CertCrypt`: Encrypts the TLS certificate and private key
* `FileCrypt`: Encrypts the web interface files (index.html, all-ears.js, main.js, main.css), compresses them and adds the HTTP headers
* `ManagerClient`: A client for AllEars-Manager

## Web front-end ##

The `web-files` directory contains the official web front-end, including the client library `all-ears.js`.

- - - -

## Users ##
The following information is stored about users:
* The Argon2 hashes of registered addresses (see [Addresses](#addresses))
* The user's public key
* A randomly generated 16-bit user ID
* The user's membership level
* Normal address count
* Shield address count
* The `private` data field

The `private` data field can be used by clients to store 4059 bytes of arbitrary data. Its contents are sent with each `account/browse` API request, and it can be updated using the `private/update` API. The server does nothing with the data, and it can technically be used by clients for any purpose. The official clients encrypt it with the user's public key using libsodium's Sealed Box, and use it to store Address/Gatekeeper/Contacts data.

## Addresses ##

All-Ears provides its users with two types of addresses. Normal addresses are 1-23 characters, and are chosen by the user. Shield addresses are 24 characters, and are randomly generated by the server.

All-Ears uses a custom five-bit encoding (Addr32) to fit all addresses into 15 bytes. The Addr32 form is used to create a 13-byte Argon2 hash, which is stored by All-Ears.

Addr32 supports the lowercase letters a-z and the digits 0-9. Because the encoding only has space for 32 characters, the characters `1/i/l`, `0/o`, and `v/w` are treated as equivalent. Uppercase characters are converted to their lowercase equivalents, and all other characters are ignored. Therefore, the canonical form of `johnsmith` is `j0hnsm1th`, and `+j0--#hN..sm1t+H+_` is a valid alias for it.

No record is kept of deleted addresses. Once deleted, addresses are immediately available for registration. Shield addresses are randomly generated by the server, and therefore virtually impossible to re-register once deleted.

Normal addresses are created privately client-side. The server only receives the final Argon2 hash.

Updating (changing settings) and deleting addresses is always done with the hash, and do not reveal the actual address to the server.

While the server does not directly know the real address (only its hash), it is easy to hash an address converted to Addr32 to see if a match is found in the records. But because the hashes are only 87% of the size of the original (13/15), collisions (false positives) are guaranteed. This means that while the user receives email sent to that address (if enabled), they did not necessarily register it (it may be an unintended alias).

Because addresses are simple to register and delete, addresses are not strictly tied to accounts. No history is kept, and therefore it can only be learned that the address is _currently_ held by that account.

Overall, the low value of address data and the high cost of large numbers of Argon2 operations discourage snooping. The system is not designed to stop serious, targeted attacks. Nor is there meaningful protection if an address is easily guessed, or is known from outside sources (such as sent emails, or website registrations).

Address data is held in memory by AllEars-Account, and written to `/var/lib/allears/Addr.aem` encrypted with libsodium's Secret Box using the Account Key.

## Messages ##
All-Ears has four types of messages:

* Email
* Internal mail
* Uploaded files
* Textual notes

All messages are encrypted with the user's public key using libsodium's Sealed Boxes. Email is encrypted by the server at reception, while all others are encrypted by the client prior to sending. All are indistinguishable--it is impossible to tell what type a message is (or what its contents are) without the user's Secret Key.

All messages are padded to the nearest 1 KiB prior to encryption. Because of this, even message sizes are only approximate. No timestamps are kept other than those in the encrypted headers (HeadBox, see below).

On a technical level, messages are split into two parts: the headers (HeadBox) and the body (BodyBox). The HeadBox is always generated by the server, and contains varying amounts of metadata depending on the type. The BodyBox contains the actual data, and is generated by the client for all types except email.

## Files ##

All files stored in `/etc/allears` are encrypted with the Master Key, and need to be generated by the relevant utility in `utils` (see [Utilities](#utilities)).

Server keys:
* API.key: Asymmetric key used by allears-api to securely communicate with API clients
* Account.key: Symmetric key used to encrypt user data prior to storage
* Address.key: Salt provided to Argon2 for hashing users' email addresses
* Manager.key: Symmetric key used to communicate with allears-manager
* Stindex.key: Symmetric key used to encrypt the message index prior to writing on disk
* Storage.key: Symmetric key used to encrypt message data prior to writing on disk

Other files:
* TLS.crt: The TLS certificate
* TLS.key: The TLS private key
* all-ears.js: The client library for All-Ears
* index.html: The HTML file for the web interface
* main.css: The CSS file for the web interface
* main.js: Javascript for the web interface

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
