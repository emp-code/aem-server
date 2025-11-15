# All-Ears Mail #

[![CodeFactor](https://www.codefactor.io/repository/github/emp-code/aem-server/badge)](https://www.codefactor.io/repository/github/emp-code/aem-server) [![Codacy Badge](https://app.codacy.com/project/badge/Grade/9266bf412f484c5abe967883146ad3b3)](https://www.codacy.com/gh/emp-code/aem-server/dashboard?utm_source=github.com&amp;utm_medium=referral&amp;utm_content=emp-code/aem-server&amp;utm_campaign=Badge_Grade)

## Introduction ##

All-Ears Mail is a private email solution. The server was designed from the ground up to minimize how much it knows about its users, and to keep what it knows as private as it can.

All-Ears Mail consists of:
1. [Manager](#manager)
2. [Account](#account)
3. [Deliver](#deliver)
4. [Enquiry](#enquiry)
5. [Storage](#storage)
6. [API](#api)
7. [MTA](#mta)
8. [Reg](#reg)
9. [Web](#web)
10. [Utilities](#utilities)

General information:
* [Addresses](#addresses)
* [Messages](#messages)
* [Users](#users)
* [Dependencies](#dependencies)

- - - -

## Manager ##

AEM-Manager is the main server program. It starts and manages all other process types.

AEM-Manager creates a safe environment for each process to run in, isolating them through a variety of methods including pivot_root, namespaces, cgroups, resource limits, and minimizing capabilities. Once started, AEM-Manager sends the process the data it needs through a temporary one-way pipe.

AEM-Manager reads encrypted binaries from the `/var/lib/allears/bin` folder. These must be created through the BinCrypt utility.

At startup, AEM-Manager asks for the Manager Protocol Key. Following this, it listens on the abstract Unix domain socket named `AEM_Mng` for Manager Protocol clients.

## Account ##

AEM-Account authenticates and responds to API requests from [AEM-API](#api) and [AEM-Reg](#reg). It also tells [AEM-MTA](#mta) which user (if any) owns an address, and provides necessary account information to [AEM-Storage](#storage).

For each user, AEM-Account stores:
* The type, flags (settings), and hash for each [Address](#addresses)
* The User API Key (UAK), used to authenticate and encrypt API requests
* The Envelope Public Key (EPK), used by [AEM-Storage](#storage) to convert plain [Messages](#messages) into encrypted Envelopes
* The user's membership level
* The time of the last successful request, to protect against replay attacks
* The `private` data field: a few kilobytes intended for client-side encrypted information such as addresses, notes, etc.

Account holds the user data in memory, and stores the encrypted data in `/var/lib/allears/Account.aem`.

## Deliver ##

AEM-Deliver receives email from [AEM-MTA](#mta) processes. It converts any HTML to the custom Control-Enriched Text (CET) format, and converts the email to the ExtMsg [Message](#messages) format with additional data such as DKIM results. It then sends the Message to [AEM-Storage](#storage) for encryption and storage.

## Enquiry ##

AEM-Enquiry takes requests from the other processes to retrieve information such as IP/DNS data. It has no access to user data.

## Storage ##

AEM-Storage takes requests from [AEM-API](#api) and [AEM-Deliver](#deliver) to store Messages, and from AEM-API to retrieve Envelopes.

An Envelope is an encrypted container for a Message, openable only by the recipient. For more, see [Messages](#messages).

The size of each Envelope is kept in the Storage Index, or Stindex. AEM-Storage holds this index in memory, and keeps an encrypted copy at `/var/lib/allears/Stindex.aem`.

Envelope data is stored in `/var/lib/allears/Msg/`. Each user has one file containing all their Envelopes. The filename is the user's UserID encoded with a secret Base64-like encoding generated based on the Server Master Key (SMK).

## API ##

AEM-API serves an open web API, usable by any website or client.

The API is authenticated and encrypted using the User API Key (UAK), shared with the server during registration. A passive observer can only see a timestamp, and any modification to the request or response will invalidate it.

AEM-API processes do not hold the UAK, but rather forward all requests to [AEM-Account](#account) which authenticates and decrypts the request, and passes relevant information back to the AEM-API process as necessary.

AEM-API listens on an abstract UNIX domain socket: AEM_API_00 to AEM_API_FF.

## MTA ##

AEM-MTA (Mail Transfer Agent) receives email from other servers and forwards it to [Deliver](#deliver) for processing and delivery.

AEM-MTA listens on TCP port 25 (SMTP).

## Reg ##

AEM-Reg receives registration requests and forwards them to [AEM-Account](#account).

AEM-Reg listens on an abstract UNIX domain socket: AEM_Reg.

## Web ##

AEM-Web is a simple web server. Its use is optional: the API is usable by any website or client.

The server is designed for single-page sites, supporting one HTML file in addition to its own static, built-in responses (such as MTA-STS).

All other files are designed to be hosted externally. This makes the client-side code easier to verify, and [SRI](https://en.wikipedia.org/wiki/Subresource_Integrity) protects the integrity of the files.

AEM-Web is the only process type to run completely isolated with no ability to interact with other processes.

AEM-Web listens on an abstract UNIX domain socket: AEM_Web.

## Utilities ##

The `utils` folder contains:
* `BinCrypt`: Encrypts the All-Ears Mail executables for Manager
* `Creator`: Generates a new Server Master Key (SMK) and `allears` folder
* `DataCrypt`: Encrypts additional files for Manager
* `WebMaker`: Creates and encrypts the response for the AEM-Web process

- - - -

## Addresses ##

All-Ears provides its users with two types of addresses. Normal addresses consist of 1 to 15 alphanumerics, and are chosen by the user. Shield addresses consist of 16 random alphanumerics, and are generated by the server.

All addresses are converted to a 10-byte binary format using a custom five-bit encoding (Addr32). This encoding is case-insensitive, disregards all non-alphanumeric characters, and treats some similar-looking characters (`1/i/l`, `0/o`, `v/w`) as equivalent.

To preserve user privacy, the server stores the addresses as 8-byte hashes. This allows testing the ownership of a specific address without directly revealing what addresses any user has registered. Additionally, the shorter size virtually guarantees each registered address has a large number of equally valid aliases. For normal addresses, these are overwhelmingly likely to be nonsensical. Shield addresses however are all random, making it impossible to determine which is the 'real' one.

Normal addresses are created privately client-side. They use a computationally-expensive Argon2 hash to make it difficult to reverse the hash back into the address.

Shield addresses are randomly generated by the server. Because they're impossible to guess, they use the fast and simple SipHash.

No record is kept of deleted addresses. Once deleted, an address becomes immediately available for registration.

| Normal                              | Shield           |
| ----------------------------------- | ---------------- |
| 1-15 alphanumerics                  | 16 alphanumerics |
| Expensive to guess                  | Impossible to guess |
| Unknown to the server until used    | Randomly generated by the server |
| Immediately available after deleted | Virtually impossible to re-register |
| All addresses act as if existing    | Non-existing addresses reject mail |
| High resource usage                 | Low resource usage |

## Messages ##

A _Message_ in All-Ears Mail is a custom binary format, and may be one of four types:
* ExtMsg: Email, in the custom Control-Enriched Text (CET) format
* IntMsg: Internal mail from other users, or from the system
* OutMsg: Delivery report of a sent message
* UplMsg: A file: either an email attachment, or one uploaded by the user

Messages originate from either [AEM-MTA](#mta) (incoming email) or [AEM-API](#api) (others). Each Message is sent to [AEM-Storage](#storage), which places the Message into an Envelope.

In All-Ears Mail, an _Envelope_ is an encrypted container for a Message.

An Envelope can only be opened by the recipient. To accomplish this, AEM-Storage:
1. Generates a temporary X25519 keypair.
2. Adds the public key from Step 1 to the Message.
3. Uses the user's Envelope Public Key (EPK) and its own secret key from Step 1 to generate the X25519 shared secret.
4. Generates a BLAKE2b hash based on the shared secret, the user's EPK, and the size of the message.
5. Uses the hash as the key to encrypt the Message with ChaCha20.
6. Erases its keypair.

Because the server doesn't have either of the secret keys, it cannot generate the shared secret and therefore cannot open the Envelope.

Additional factors of protection:
* The user's EPK is never shared or used for any purpose other than creating the Envelopes
* The size of each Envelope is stored in the Stindex, only known by AEM-Storage and encrypted on disk
* A user's Envelopes are all stored in one file; the filename is the UserID encoded with a secret Base64-like encoding known only by AEM-Storage, derivable only by knowing the Server Master Key

Envelopes are fully encrypted. They provide no information without knowing the key.

In short, the server knows only the number of Envelopes a user has, and their size. Additionally, filesystem data can be used to determine when a user's file was last updated.

## Users ##

An All-Ears Mail server supports up to 4096 users. Users are identified by their UserID (0-4095), which may be presented as a three-letter username (aaa-ppp) for display purposes. This username has no relation to [addresses](#addresses).

Each user has a 360-bit User Master Key (UMK). This key must be kept safe by the user. If lost, recovery is impossible.

## Dependencies ##

* [wolfSSL](https://www.wolfssl.com) for TLS
* [libsodium](https://libsodium.org) for cryptography
* [Brotli](https://github.com/google/brotli) for compression
* [MaxMind GeoIP2](https://dev.maxmind.com/geoip/geoip2/downloadable/) for IP geolocation and ASN data
* [ICU](https://icu.unicode.org) for converting text to UTF-8
