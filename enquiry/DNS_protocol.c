// https://www.iana.org/assignments/dns-parameters/dns-parameters.xhtml

#include <arpa/inet.h>
#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <syslog.h>

#include <sodium.h>

#include "DNS_protocol.h"

static uint32_t validIp(const uint32_t ip) {
	const uint8_t b1 = ip & 0xFF;
	const uint8_t b2 = (ip >>  8) & 0xFF;
	const uint8_t b3 = (ip >> 16) & 0xFF;
//	const uint8_t b4 = (ip >> 24) & 0xFF;

	return (
	   (b1 == 0)
	|| (b1 == 10)
	|| (b1 == 100 && b2 >= 64 && b2 <= 127)
	|| (b1 == 127)
	|| (b1 == 169 && b2 == 254)
	|| (b1 == 172 && b2 >= 16 && b2 <= 31)
	|| (b1 == 192 && b2 == 0  && b3 == 0)
	|| (b1 == 192 && b2 == 0  && b3 == 2)
	|| (b1 == 192 && b2 == 88 && b3 == 99)
	|| (b1 == 192 && b2 == 168)
	|| (b1 == 198 && b2 >= 18 && b2 <= 19)
	|| (b1 == 198 && b2 == 51 && b3 == 100)
	|| (b1 == 203 && b2 == 0  && b3 == 113)
	|| (b1 >= 224 && b1 <= 239)
	|| (b1 >= 240)
	) ? 0 : ip;
}

static void domainToQuestion(unsigned char * const question, const unsigned char * const domain, const size_t lenDomain, const uint16_t queryType) {
	const unsigned char *dom = domain;

	size_t copied = 0;
	while(1) {
		bool final = false;

		const unsigned char *dot = memchr(dom, '.', (domain + lenDomain) - dom);
		if (dot == NULL) {
			dot = domain + lenDomain;
			final = true;
		}

		const size_t sz = dot - dom;

		question[copied] = sz;
		memcpy(question + copied + 1, dom, sz);

		copied += sz + 1;

		if (final) break;
		dom += sz + 1;
	}

	question[lenDomain + 1] = '\0';
	memcpy(question + lenDomain + 2, &queryType, 2);
	memcpy(question + lenDomain + 4, (unsigned char[]){0,1}, 2); // Internet class
}

int dnsCreateRequest(const uint16_t id, unsigned char * const rq, const unsigned char * const domain, const size_t lenDomain, const uint16_t queryType) {
	memcpy(rq + 2, &id, 2);

	// 16-bit flags field, entry counts
	memcpy(rq + 4, (unsigned char[]){1,0,0,1,0,0,0,0,0,0}, 10);
	/*	00000001
		[1] QR (Query/Response). 0 = Query, 1 = Response.
		[4] OPCODE (kind of query). 0000 = Standard query.
		[1] Authoritative answer. N/A.
		[1] Truncated message. No.
		[1] Recursion desired. Yes.

		00000000
		[1] Recursion available. N/A.
		[1] Reserved
		[1] Authentic Data
		[1] Checking Disabled
		[4] Response code. N/A.

		[16] QDCOUNT: One question entry (00000000 00000001).
		[16] ANCOUNT: Zero.
		[16] NSCOUNT: Zero.
		[16] ARCOUNT: Zero.
	*/

	domainToQuestion(rq + 14, domain, lenDomain, queryType);

	// TCP DNS messages start with a uint16_t indicating the length of the message (excluding the uint16_t itself)
	rq[0] = 0;
	rq[1] = 20 + lenDomain;

	return 22 + lenDomain;
}

static int rr_getName(const unsigned char * const msg, const int lenMsg, const int rrOffset, unsigned char * const name, int * const lenName, bool allowPointer) {
	int offset = rrOffset;

	while (offset < lenMsg) {
		switch (msg[offset] & 192) {
			case 192: { // Pointer (ends label)
				if (!allowPointer) {syslog(LOG_ERR, "DNS: Pointer-to-pointer"); return -1;}
				rr_getName(msg, lenMsg, *(uint16_t*)(uint8_t[]){msg[offset + 1], msg[offset] & 63}, name, lenName, false); // rrOffset = pointer location
				return offset + 2;
			}
			case 0: { // Normal
				allowPointer = true;
				if (msg[offset] == 0) return offset + 1; // Label end

				if (*lenName + msg[offset] + 1 > 127) return -1;

				// Label part
				if (*lenName > 0) {
					name[*lenName] = '.';
					(*lenName)++;
				}

				memcpy(name + *lenName, msg + offset + 1, msg[offset]);
				*lenName += msg[offset];
				offset += msg[offset] + 1;
				continue;
			}
			default: // 128, 64: reserved
				syslog(LOG_ERR, "Unsupported DNS label type: %u", msg[offset]);
				return -1;
		}
	}

	syslog(LOG_ERR, "No_End");
	return -1;
}

static int getNameRecord(const unsigned char * const msg, const int lenMsg, int rrOffset, const int answerCount, unsigned char * const result, int * const lenResult, const uint16_t recordType) {
	uint16_t prio = UINT16_MAX;

	for (int i = 0; i < answerCount; i++) {
		unsigned char name[255];
		int lenName = 0;

		const int offset = rr_getName(msg, lenMsg, rrOffset, name, &lenName, true);
		if (offset < 1) {syslog(LOG_ERR, "rr_getName failed"); return -1;}
		// TODO: Compare name to requestedName

		if (*(uint16_t*)(msg + offset) != recordType) {syslog(LOG_ERR, "Record type mismatch: %.2x", msg[offset + 1]); return -1;}
		if (memcmp(msg + offset + 2, (unsigned char[]){0,1}, 2) != 0) {syslog(LOG_ERR, "Record not internet class"); return -1;}
		// +4 TTL (32 bits) ignored

		uint16_t rdLen;
		memcpy((unsigned char*)&rdLen + 0, msg + offset + 9, 1);
		memcpy((unsigned char*)&rdLen + 1, msg + offset + 8, 1);
		if (rdLen < 1) {syslog(LOG_ERR, "rdLen"); return -1;}

		if (recordType == AEM_DNS_RECORDTYPE_MX) {
			uint16_t newPrio;
			memcpy((unsigned char*)&newPrio + 0, msg + offset + 11, 1);
			memcpy((unsigned char*)&newPrio + 1, msg + offset + 10, 1);

			if (newPrio < prio) {
				*lenResult = 0;
				const int o2 = rr_getName(msg, lenMsg, offset + 12, result, lenResult, true);
				if (o2 < 1) return -1;
				prio = newPrio;
			}

			rrOffset = offset + 10 + rdLen; // offset is at byte after name-section
		} else if (recordType == AEM_DNS_RECORDTYPE_PTR) {
			rr_getName(msg, lenMsg, offset + 10, result, lenResult, true);
			return 0;
		} else return -1;
	}

	return 0;
}

static uint32_t dnsResponse_GetIp_get(const unsigned char * const rr, const int rrLen) {
	int offset = 0;
	bool pointer = false;

	while (offset < rrLen) {
		uint8_t lenLabel = rr[offset];

		if (pointer || lenLabel == 0) {
			if (!pointer) offset++;
			pointer = false;

			uint16_t lenRecord;
			memcpy((unsigned char*)&lenRecord + 0, rr + offset + 9, 1);
			memcpy((unsigned char*)&lenRecord + 1, rr + offset + 8, 1);

			if (memcmp(rr + offset, (unsigned char[]){0,1,0,1}, 4) == 0 && lenRecord == 4) { // A Record
				uint32_t ip;
				memcpy(&ip, rr + offset + 10, 4);
				return ip;
			} else {
				offset += 10 + lenRecord;
				continue;
			}
		} else if ((lenLabel & 192) == 192) {
			offset += 2;
			pointer = true;
			continue;
		}

		offset += 1 + lenLabel;
	}

	return 0;
}

static int getAnswerCount(const uint16_t reqId, const unsigned char * const res, const int lenRes, const unsigned char * const domain, const size_t lenDomain, const uint16_t queryType) {
	if (lenRes < 18 + (int)lenDomain) {syslog(LOG_ERR, "DNS answer too short"); return 0;}
	if (memcmp(res, &reqId, 2) != 0) {syslog(LOG_ERR, "ID mismatch"); return 0;}

	// 2: 128=QR: Answer (1); 64+32+16+8=120 OPCODE: Standard query (0000); 4=AA: Authorative Answer; 2=TC: Truncated; 1=RD: Recursion Desired
	// 3: 128=RA: Recursion Available; 64=Z: Zero (Reserved); 32=AD: Authentic Data; 16=CD: Checking Disabled; 15=RCODE: No Error (0000)
	if (res[2] != 129 || (res[3] & 192) != 128) {syslog(LOG_ERR, "Invalid DNS answer"); return 0;}
	if ((res[3] & 15) != 0) {syslog(LOG_ERR, "DNS Error: %u", res[3] & 15); return 0;}

	if (memcmp(res +  4, (unsigned char[]){0,1}, 2) != 0) {syslog(LOG_ERR, "QDCOUNT mismatch"); return 0;}
	// 6,7 ANCOUNT
	if (memcmp(res +  8, (unsigned char[]){0,0}, 2) != 0) {syslog(LOG_ERR, "NSCOUNT mismatch"); return 0;}
	if (memcmp(res + 10, (unsigned char[]){0,0}, 2) != 0) {syslog(LOG_ERR, "ARCOUNT mismatch"); return 0;}

	unsigned char question[lenDomain + 6];
	domainToQuestion(question, domain, lenDomain, queryType);
	if (memcmp(res + 12, question, lenDomain + 6) != 0) {syslog(LOG_ERR, "Question mismatch"); return 0;}

	uint16_t answerCount;
	memcpy((unsigned char*)&answerCount + 0, res + 7, 1);
	memcpy((unsigned char*)&answerCount + 1, res + 6, 1);
	return answerCount;
}

uint32_t dnsResponse_GetIp(const uint16_t reqId, const unsigned char * const res, const int lenRes, const unsigned char * const domain, const size_t lenDomain, const uint16_t queryType) {
	const int answerCount = getAnswerCount(reqId, res, lenRes, domain, lenDomain, queryType);
	if (answerCount <= 0) return 0;

	return validIp(dnsResponse_GetIp_get(res + 18 + lenDomain, lenRes - 18 - lenDomain));
}

int dnsResponse_GetNameRecord(const uint16_t reqId, const unsigned char * const res, const int lenRes, const unsigned char * const domain, const size_t lenDomain, unsigned char * const result, int * const lenResult, const uint16_t queryType) {
	const int answerCount = getAnswerCount(reqId, res, lenRes, domain, lenDomain, queryType);
	if (answerCount <= 0) return -1;

	return getNameRecord(res, lenRes, 18 + lenDomain, answerCount, result, lenResult, queryType);
}
