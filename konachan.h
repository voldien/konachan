/**
    Konachan is command search tool.
    Copyright (C) 2017  Valdemar Lindberg

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.

*/
#ifndef _KONACHAN_H_
#define _KONACHAN_H_
#include <unistd.h>
#include <assert.h>
#include <stdio.h>
#include <json-c/json.h>
#include <string.h>
#include <openssl/ossl_typ.h>
#include <openssl/ssl.h>
#include <openssl/crypto.h>
#include <openssl/err.h>

/**
 *	Forward declaration of
 *	global constant variables.
 */
extern const char* flag_name_table[];
extern const unsigned int flag_value_table[];
extern const char* flag_name_key_table[];

/**
 *	Global constant variables.
 */
extern const char* post_tag_json;
extern const char* tags_tag_json;

/**
 *	Global variables.
 */
extern char* g_host;                      /*	host. (Default konachan.com )	*/
extern char* g_limit;                     /*	limit. ( 1 result by default)	*/
extern int g_page;                        /*	page.	*/
extern char* g_tags;                      /*	tags.	*/
extern unsigned int g_verbose;            /*	verbose mode.	*/
unsigned int kcg_debug;                   /*	debug mode.	*/
extern unsigned int g_port;               /*	port to connect to. (Default HTTPS port).*/
extern unsigned int g_secure;             /*	security mode. (Default enabled.)	*/
extern unsigned int g_ratingmode;         /*	Search rating. (Safe by default.).	*/
extern unsigned int g_compression;        /*	Use compression.	*/
extern unsigned int g_randorder;          /*	random order.	*/
extern unsigned int g_mode;               /*	*/

/**
 *	Konachan mode.
 */
#define MODE_POST       0x1	/*	Get post information.	*/
#define MODE_TAG        0x2	/*	Get tag information.	*/

/**
 *	Option flags.
 */
#define FLAG_URL                0x1	/*	Get url.	*/
#define FLAG_URL_SIZE           0x2	/*	Get url size in bytes.	*/
#define FLAG_PREVIEW            0x4	/*	Get preview.*/
#define FLAG_PREVIEW_SIZE       0x8	/*	Not supported.	*/
#define FLAG_SAMPLE_URL         0x10	/*	Get sample url.	*/
#define FLAG_SAMPLE_URL_SIZE    0x20	/*	Get sample size in bytes.	*/
#define FLAG_TAGS               0x40	/*	Get tags associated with result.	*/
#define FLAG_ID                 0x80	/*	Get the ID of the object.	*/
#define FLAG_JPEG_URL           0x100	/*	Get JPEG url if exists.	*/
#define FLAG_JPEG_SIZE          0x200	/*	Get JPEG size in bytes if exits.	*/
#define FLAG_PNG_URL            0x400	/*	Not supported.	*/
#define FLAG_PNG_SIZE           0x800	/*	Not supported.	*/
#define FLAG_SCORE              0x1000	/*	Get source as a numeric digit.*/
#define FLAG_MD5                0x2000	/*	Get hashed MD5 for the  .	*/
#define FLAG_SOURCE             0x4000	/*	Get source of the object.	*/
#define FLAG_NAME               0x8000	/*	Get tag name.	*/

/**
 *	Flag keyword.
 */
#define FLAG_KEY_URL "url"                      /*	The full size image URL.*/
#define FLAG_KEY_URL_SIZE "size"                /*	The full sized image size in bytes.	*/
#define FLAG_KEY_PREVIEW_URL "preview"          /*	The preview image URL.	*/
#define FLAG_KEY_PREVIEW_SIZE "preview_size"    /*	The preview image size in bytes.	*/
#define FLAG_KEY_SAMPLE_URL "sample"            /*	*/
#define FLAG_KEY_SAMPLE_SIZE "sampe_size"       /*	*/
#define FLAG_KEY_TAGS "tags"                    /*	*/
#define FLAG_KEY_ID "id"                        /*	*/
#define FLAG_KEY_JPEG_URL "jpeg_url"            /*	*/
#define FLAG_KEY_JPEG_SIZE "jpeg_size"          /*	*/
#define FLAG_KEY_PNG_URL "png_url"              /*	*/
#define FLAG_KEY_PNG_SIZE "png_size"            /*	*/
#define FLAG_KEY_SCORE "score"                  /*	Get the current score of the entry.	*/
#define FLAG_KEY_MD5 "md5"                      /*	Get the MD5 checksum.*/
#define FLAG_KEY_SOURCE "source"                /*	*/
#define FLAG_KEY_NAME "name"                    /*	*/

/**
 *	Rating mode
 */
#define MODE_SAFE               0x1	/*	Safe mode.	*/
#define MODE_EXPLICIT           0x2	/*	Explicit mode.	*/

/**
 *	JSON attribute key name.
 */
#define KEY_URL "file_url"                          /*	JSON attribute name for file URL.	*/
#define KEY_URL_SIZE "file_size"                    /*	JSON attribute name*/
#define KEY_PREVIEW "preview_url"                   /*	JSON attribute name*/
#define KEY_PREVIEW_SIZE "preview_url"              /*	Not supported.	*/
#define KEY_SAMPLE_URL "sample_url"                 /*	*/
#define KEY_SAMPLE_URL_SIZE "sample_file_size"		/*	*/
#define KEY_TAGS "tags"                             /*	*/
#define KEY_ID "id"                                 /*	*/
#define KEY_JPEG_URL "jpeg_url"                     /*	*/
#define KEY_JPEG_SIZE "jpeg_file_size"              /*	*/
#define KEY_PNG_URL "png_url"                       /*	*/
#define KEY_PNG_SIZE "png_file_size"                /*	*/
#define KEY_SCORE "score"                           /*	*/
#define KEY_MD5 "md5"                               /*	*/
#define KEY_SOURCE "source"                         /*	*/
#define KEY_NAME "name"                             /*	*/

/**
 *
 */
struct kc_connection_t;
typedef int (*PWRITE)(struct kc_connection_t* __restrict__ connection, const void* __restrict__ pbuf, int l);
typedef int (*PREAD)(struct kc_connection_t* __restrict__ connection, void* __restrict__ pbuf, int l);

/**
 *
 */
typedef struct kc_connection_t{
	int sock;       /*	file descriptor socket.	*/
	int af;         /*	Address family.	*/
	int secure;     /*	Secure connection.	*/
	/*	Secure Socket layer for HTTP/S (Secure).	*/
	SSL *conn;
	SSL_CTX *ssl_ctx;
	/*	Read and write function pointers.	*/
	PWRITE write;
	PREAD read;

}KCConection;

/**
 *	Get version of the program.
 *	@Return non-null terminated string.
 */
extern const char* kcGetVersion(void);

/**
 *	Read option argument from command line.
 */
extern void kcReadArgument(int argc, const char** argv);

/**
 *	Print debug information.	
 */
extern void kcDebugPrintf(const char* format, ...);

/**
 *	Remove escape character from strings.
 */
extern void kcSimpleRemoveEscapeStr(char* str);

/**
 *	Get value associated with attribute key.
 *	@Return value as non-null terminated string.
 */
extern const char* kcGetJSONValueByKey(struct json_object* __restrict__ json,
		const char* __restrict__ key);
/**
 *	Extract json from HTTP response.
 *	@Return non-null terminated string if successful.
 */
extern char* kcSimpleExtractJSONBody(char* str);

/**
 *	Extract html code from response packets.
 *
 *	@Return non-terminated string of beginning of the
 *	html code if successfully.
 */
extern char* kcSimpleExtractHtmlHeader(char* __restrict__ str,
		int* __restrict__ headerlen);
/**
 *	Check if HTTP response body uses
 *	GZIP compression.
 *
 *	@Return non-zero if using compression, 0 otherwise.
 */
extern int kcUseHTTPGZipEncoding(const char* header);

/**
 *	Allocate tag.
 *	@Return
 */
extern char* kcAllocateTagHeader(size_t size);

/**
 *	@Return
 */
extern char* kcConstructTagLValue(const char* opts, unsigned int rating);

/**
 *	Read the flag options for which informatio to be extracted
 *	from the JSON result.
 */
extern void kcReadFlagOptions(const char* __restrict__ optarg,
		unsigned int** __restrict__ lorder, unsigned int* count);
/**
 *	@Return
 */
extern unsigned int kcGetStrValueToEnum(const char* opt);

/**
 *	\mode
 *
 *	@Return non-null terminated string.
 */
extern const char* kcGetHTTPFilename(unsigned int mode);


/**
 *
 */
extern int kcSendRecv(KCConection* __restrict__ connection, void** __restrict__ recv);

/**
 *
 */
extern int kcDecodeInput(char* body, int json_len, const unsigned int* forder, int nflags);

/**
 *	Connect to the server with a TCP conncetion
 *	on specified port.
 *	@Return
 */
extern int kcConnect(KCConection* connection, unsigned int mode, int af,
		const char* address, unsigned int port);

/**
 *	Disconnect socket.
 */
extern void kcDisconnect(KCConection* connection);

/**
 *	Write to currently connected socket. Where it handle if
 *	TLS/SSL is enabled or not.
 *	@Return
 */
extern int kcSecWrite(KCConection* __restrict__ connection,
		const void* __restrict__ buffer, unsigned int len);
extern int kcNSecWrite(KCConection* __restrict__ connection,
		const void* __restrict__ buffer, unsigned int len);

/**
 *	Read from the currently connected socket. Where it handle
 *	if TLS/SSL is enabled or not.
 *	@Return
 */
extern int kcSecRead(KCConection* __restrict__ connection,
		void* __restrict__ buffer, unsigned int len);
extern int kcNSecRead(KCConection* __restrict__ connection,
		void*__restrict__ buffer, unsigned int len);

#endif
