# All-Ears Mail #

## Status ##

[![Total alerts](https://img.shields.io/lgtm/alerts/g/emp-code/aem-server.svg?logo=lgtm&logoWidth=18)](https://lgtm.com/projects/g/emp-code/aem-server/alerts/)

[![CodeFactor](https://www.codefactor.io/repository/github/emp-code/aem-server/badge)](https://www.codefactor.io/repository/github/emp-code/aem-server)

[![Codacy Badge](https://app.codacy.com/project/badge/Grade/9266bf412f484c5abe967883146ad3b3)](https://www.codacy.com/gh/emp-code/aem-server/dashboard?utm_source=github.com&amp;utm_medium=referral&amp;utm_content=emp-code/aem-server&amp;utm_campaign=Badge_Grade)

[![Codiga](https://api.codiga.io/project/5719/score/svg)](https://app.codiga.io/public/project/5719/aem/dashboard)

## Introduction ##

All-Ears Mail is a private email solution. It was designed from the ground up to know the least amount of information about its users, and to keep that information private to the maximum extent. Other goals include simplicity, robustness, and performance.

All-Ears consists of several processes types, divided into three tiers. The intent is to minimize the power of public-facing processes, thereby safeguarding user data even in worst-case scenarios.

The top-tier process—Manager—handles the creation and ending of the other processes. It can only be reached through a custom encrypted protocol.

The middle-tier processes—Account, Deliver, Enquiry, and Storage—are trusted with direct access to relevant user data, but are only reachable through a secure internal communication system (IntCom). Manager automatically creates one of each at startup.

The bottom-tier processes—API, MTA, and Web—are internet-facing, but can only access user data by requesting the middle-tier processes to perform specific actions needed for their operation. Any number of these may be started through Manager.

All-Ears consists of the following parts:
1. [Manager](#manager)
2. [Account](#account)
3. [Deliver](#deliver)
4. [Enquiry](#enquiry)
5. [Storage](#storage)
6. [API](#api)
7. [MTA](#mta)
8. [Web](#web)
9. [Utilities](#utilities)

General information:
* [Addresses](#addresses)
* [Messages](#messages)
* [Dependencies](#dependencies)

- - - -

## Manager ##

Manager is the main server program. It sets up the environment for All-Ears to run, and interacts with ManagerClient (see [Utilities](#utilities)) on port 940 to start/stop processes remotely.

At startup, Manager asks for the Master Key, used to decrypt files stored in `/etc/allears`. After this, no further interaction on the console is needed.

Manager creates an environment for the process to run in, isolating them through a variety of methods including pivot_root, namespaces, cgroups, resource limits, and minimizing capabilities. Once started, Manager sends the process the data it needs through a temporary one-way pipe.

Shutting down Manager terminates all other All-Ears processes.

## Account ##

Account takes requests from [API](#api) and [MTA](#mta) for user data.

For each user, the following is stored:
* The type, flags (settings), and hash for each address (see [Addresses](#addresses))
* The user's public key (UPK)
* The user's membership level
* The `private` data field

The `private` data field can be used by clients to store up to 3,784 bytes. Its contents are sent with each `account/browse` API request, and it can be updated using the `private/update` API. The intent is to provide a client-side encrypted storage for data needed by clients (such as the corresponding address for each hash).

Account holds the user data in memory, and writes it to `/var/lib/allears/Account.aem`. Prior to writing, it pads the data to a multiple of 1024 users (4 MiB), and encrypts it with libsodium's Secret Box.

## Deliver ##

Deliver receives email from the [MTA](#mta) processes. It converts any HTML to the custom Control-Enriched Text (CET) format, and forms the message into the custom ExtMsg format with additional data such as DKIM results. It then encrypts the message with the user's public key (UPK), before sending it to [Storage](#storage).

## Enquiry ##

Enquiry takes requests from the other processes to retrieve information such as IP/DNS data. It has no access to user data.

## Storage ##

Storage takes requests from [API](#api) and [Deliver](#deliver) to store and retrieve message data (see [Messages](#messages)).

The size of each message is kept in an index, called the Stindex (storage index). Storage holds this index in memory, and writes it to `/var/lib/allears/Stindex.aem`, encrypted with libsodium's Secret Box.

Message data is held in `/var/lib/allears/MessageData/`. Each user has one file where all their messages are stored, with filenames based on encrypting the user's public key (UPK). The message data is encrypted with AES-256. Each unique combination of user and message size uses its own key, making the file virtually undecipherable without data from the Stindex.

## API ##

API serves an open web API, usable by any website or client.

Both requests and responses are encrypted using libsodium's Box, which provides [both authentication and confidentiality](https://en.wikipedia.org/wiki/Authenticated_encryption).

Both requests and responses use a custom binary format. Short-form responses and requests are always the same size, preventing identifying their type by their size.

`api-clr` is the HTTPS clearnet variant, `api-oni` is the HTTP onion service variant.

## MTA ##

MTA receives email from other servers, and sends it to [Deliver](#deliver) for processing and delivery.

## Web ##

Web is a simple, high-security web server. Its use is optional: the API is usable by any website or client.

The server is designed for single-page sites, supporting one HTML file in addition to its own static, built-in responses (such as MTA-STS).

All other files are designed to be hosted externally. This makes the client-side code easier to verify, and [SRI](https://en.wikipedia.org/wiki/Subresource_Integrity) protects the integrity of the files.

Web is the only process type to run completely isolated with no capability to interact with others.

`web-clr` is the clearnet variant. Only high-security HTTPS is supported, and clients are required to support Brotli compression. It doesn't respond to invalid requests.

`web-oni` is the onion service variant using HTTP with Zopfli Deflate compression. It doesn't read requests at all, and simply responds to all connections with the HTML page.

## Utilities ##

The `Data` folder contains header files which supply data to various parts of All-Ears. They must be carefully configured/generated before compilation.

The `utils` folder contains:
* `Accgen`: Generates Account.aem
* `Keygen`: Generates key files
* `BinCrypt`: Encrypts the All-Ears executable files for Manager
* `ManagerClient`: Connects to Manager to get information about processes, and start or stop them

- - - -

### Addresses ###

All-Ears provides its users with two types of addresses. Normal addresses consist of 1 to 15 alphanumerics, and are chosen by the user. Shield addresses consist of 16 random alphanumerics, and are generated by the server.

All addresses are converted to a 10-byte binary format using a custom five-bit encoding (Addr32). This encoding is case-insensitive, disregards all non-alphanumeric characters, and treats some similar-looking characters (`1/i/l`, `0/o`, `v/w`) as equivalent.

To preserve user privacy, the server stores the addresses as 8-byte hashes. This allows testing the ownership of a specific address without directly revealing what addresses any user has registered. Additionally, the shorter size virtually guarantees each registered address has a large number of equally valid aliases. For normal addresses, these are overwhelmingly likely to be nonsensical. Shield addresses however are all random, making it impossible to determine which one is the 'real' one.

Normal addresses are created privately client-side. They use a computationally-expensive Argon2 hash to make it difficult to reverse the hash back into the address.

Shield addresses are randomly generated by the server. Because they're impossible to guess, they use the fast and simple SipHash.

No record is kept of deleted addresses. Once deleted, an address becomes immediately available for registration.

The addresses _system_ and _public_ are reserved for internal use, and cannot be registered by anyone.

The file `Data/Admin.adr.txt` lists addresses which can only be registered by Level 3 (administrator) accounts. A lower-level user attempting to register such an address receives an error claiming that the address is already in use.

| Normal                              | Shield           |
| ----------------------------------- | ---------------- |
| 1-15 alphanumerics                  | 16 alphanumerics |
| Expensive to guess                  | Impossible to guess |
| Unknown to the server until used    | Randomly generated by the server |
| Immediately available after deleted | Virtually impossible to re-register |
| All addresses act as if existing    | Non-existing addresses reject mail |
| High resource usage                 | Low resource usage |

## Messages ##

Messages in All-Ears Mail use a custom binary format. The entire message is encrypted: the server knows nothing about it beyond its size. Messages also include a digital signature, proving the server created them and that they haven't been modified.

There are four types of messages:
* ExtMsg: email, using the custom Control-Enriched Text (CET) format
* IntMsg: internal mail, with optional end-to-end encryption
* OutMsg: sent mail, with additional delivery information
* UplMsg: uploaded files, which benefit from additional client-side encryption

By design, the server knows nothing except the total number of messages stored by a user, and the size of each message. Due to external limitations, it is also possible to determine the last time a user received a message.

## Dependencies ##

* [mbed TLS](https://tls.mbed.org) for TLS
* [libsodium](https://libsodium.org) for cryptography
* [Brotli](https://github.com/google/brotli) and [Zopfli](https://github.com/google/zopfli) for compression
* [MaxMind GeoIP2](https://dev.maxmind.com/geoip/geoip2/downloadable/) for IP geolocation and ASN data
* [ICU](https://icu.unicode.org) for converting text to UTF-8
