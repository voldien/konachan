#include "konachan.h"
#include <stdlib.h>
#include <errno.h>
#include <getopt.h>
#include <netdb.h>
#include <netinet/in.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>
#include <assert.h>
#include <json-c/json.h>
#include <json-c/json_object.h>
#include <json-c/json_tokener.h>
#include <zlib.h>
#include <openssl/ossl_typ.h>
#include <openssl/ssl.h>
#include <openssl/crypto.h>
#include <openssl/err.h>

/**
 *	Global constant variables.
 */
const char* post_tag_json = "post.json";
const char* tags_tag_json = "tag.json";

/**
 *	Global variables.
 */
char* g_host = "konachan.com";
char* g_limit = "1";
int g_page = 0;
char* g_tags = NULL;
unsigned int g_verbose = 1;
unsigned int kcg_debug = 0;
unsigned int g_port = 443;
unsigned int g_secure = 1;
unsigned int g_ratingmode = 1;
unsigned int g_compression = 0;
unsigned int g_randorder = 0;
unsigned int g_mode = MODE_POST;



const char* flag_name_table[] = {
	FLAG_KEY_URL,
	FLAG_KEY_URL_SIZE,
	FLAG_KEY_PREVIEW_URL,
	FLAG_KEY_PREVIEW_SIZE,
	FLAG_KEY_SAMPLE_URL,
	FLAG_KEY_SAMPLE_SIZE,
	FLAG_KEY_TAGS,
	FLAG_KEY_ID,
	FLAG_KEY_JPEG_URL,
	FLAG_KEY_JPEG_SIZE,
	FLAG_KEY_PNG_URL,
	FLAG_KEY_PNG_SIZE,
	FLAG_KEY_SCORE,
	FLAG_KEY_MD5,
	FLAG_KEY_SOURCE,
	FLAG_KEY_NAME,
	NULL
};

const unsigned int flag_value_table[] = {
	FLAG_URL,
	FLAG_URL_SIZE,
	FLAG_PREVIEW,
	FLAG_PREVIEW_SIZE,
	FLAG_SAMPLE_URL,
	FLAG_SAMPLE_URL_SIZE,
	FLAG_TAGS,
	FLAG_ID,
	FLAG_JPEG_URL,
	FLAG_JPEG_SIZE,
	FLAG_PNG_URL,
	FLAG_PNG_SIZE,
	FLAG_SCORE,
	FLAG_MD5,
	FLAG_SOURCE,
	FLAG_NAME,
};

const char* flag_name_key_table[] = {
	KEY_URL,
	KEY_URL_SIZE,
	KEY_PREVIEW,
	KEY_PREVIEW_SIZE,
	KEY_SAMPLE_URL,
	KEY_SAMPLE_URL_SIZE,
	KEY_TAGS,
	KEY_ID,
	KEY_JPEG_URL,
	KEY_JPEG_SIZE,
	KEY_PNG_URL,
	KEY_PNG_SIZE,
	KEY_SCORE,
	KEY_MD5,
	KEY_SOURCE,
	KEY_NAME,
	NULL
};

const char* kcGetVersion(void){
	return KONACHAN_STR_VERSION;
}

void kc_readargument(unsigned int argc, const char** argv){

}

void kcDebugPrintf(const char* format, ...){
	va_list vl;

	if(kcg_debug){
		va_start(vl,format);
		vfprintf(stderr, format, vl);	/*	TODO resolve file descriptor.	*/
		va_end(vl);
	}
}

void kcSimpleRemoveEscapeStr(char* str){
	char* pstr;

	/*	Convert \\/ to a / */
	pstr = str;
	while(( pstr = strstr(pstr, "\\/")) != NULL){
		*pstr = '/';
		memmove(pstr, pstr + 1, strlen(pstr));
		pstr++;
	}

	/*	remove quote around the string.	*/
	pstr = str;
	while(( pstr = strstr(pstr, "\"")) != NULL){
		*pstr = '"';
		memmove(pstr, pstr + 1, strlen(pstr));
		pstr++;
	}

	/*	Remove double forward slash if exists.	*/
	pstr = str;
	while(( pstr = strstr(pstr, "//")) != NULL){
		memmove(pstr, pstr + 2, strlen(pstr));
		pstr++;
	}
}

const char* kcGetJSONValueByKey(struct json_object* json, const char* key){

	struct json_object* pvalue;
	char* strvalue;
	json_bool ret;

	/*	*/
	ret = json_object_object_get_ex(json, key, &pvalue);
	if(ret){
		strvalue = json_object_to_json_string(pvalue);
		kcSimpleRemoveEscapeStr(strvalue);
		return strvalue;
	} else{
		return "";
	}
}


char* kcSimpleExtractJSONBody(char* str){

	char* b = strchr(str, '[');
	char* e = strrchr(str, ']');

	/*	Terminate string.	*/
	e++;
	*e = '\0';

	return b;
}


char* kcSimpleExtractHtmlHeader(char* str, int* headerlen){

	const char* bc = "\r\n\r\n";
	char* headerend;
	int len;
	char* header;

	/*	Find end of HTTP response header.	*/
	headerend = strstr(str, bc);
	headerend += sizeof(bc);
	len = (headerend - str);

	/*	Allocate string.	*/
	header = malloc(len + 1);
	memcpy(header, str, len + 1);
	header[len] = '\0';

	*headerlen = len;

	return header;
}

/**
 *	Check if content encoding set to gzip.
 */
int kcUseHTTPGZipEncoding(const char* header){

	char buf[128];
	char* res = strstr(header, "Content-Encoding:");
	char* end;

	if(res){
		end = strstr(res, "\n");
		memcpy(buf, res, end - res);
		return strstr(buf, "gzip") != NULL ? 1 : 0;
	}
	return 0;
}

/**
 *	Allocate tag header.
 *
 *	@Return
 */
char* kcAllocateTagHeader(size_t size){
	g_tags = realloc(g_tags, size);
	assert(g_tags);
	return g_tags;
}

/**
 *	Construct tag string for HTTP can
 *	interpret.
 */
char* kcConstructTagLValue(const char* opts, unsigned int rating){

	char* tag;

	/*	*/
	tag = kcAllocateTagHeader(strlen(opts) + 1024);
	memcpy(tag, opts, strlen(opts) + 1);
	char* tmp = tag;
	while( ( tmp = strstr(tmp, " ") ) ){
		*tmp = '+';
		tmp++;
	}

	if(rating > 0 || g_randorder > 0){
		strcat(tag, "+");
	}

	/*	Rating.	*/
	if(rating == MODE_SAFE){
		strcat(tag, "%20rating:safe" );
	}
	else if(rating == MODE_EXPLICIT){
		strcat(tag, "%20rating:explicit" );
	}

	if(g_randorder == 1){
		strcat(tag, "+order%3Arandom" );
	}


	return tag;
}


/**
 *	Read flag options.
 */
void kcReadFlagOptions(const char* optarg, unsigned int** lorder,
		unsigned int* count){

	const int tmplen = 128;
	char* tmpstr;
	int tmpstrlen;
	const char* hstr;
	char* whstr;

	int optcount = 0;
	unsigned int* porder = NULL;

	/*	Iterate through each flag*/
	hstr = optarg;
	tmpstr = malloc(tmplen);
	memset(tmpstr, 0, 128);
	while(hstr){
		if(*hstr == ' '){
			hstr++;
		}else{
			whstr = strstr(hstr, " ");
			tmpstrlen = whstr ? whstr - hstr : (strlen(hstr));
			memcpy(tmpstr, hstr, tmpstrlen);
			tmpstr[tmpstrlen + 1] = '\0';

			porder = (unsigned int*)realloc(porder, (optcount+ 1) * sizeof(unsigned int));
			porder[optcount] = kcGetStrValueToEnum(tmpstr);
			optcount++;

			hstr = whstr;
		}
	}

	free(tmpstr);
	*lorder = porder;
	*count = optcount;
}

unsigned int kcGetStrValueToEnum(const char* opt){

	int i = 0;

	do{
		if(strstr(opt,flag_name_table[i])){
			return flag_value_table[i];
		}
		i++;
	}while(flag_name_table[i]);

	return 0;
}


const char* kcGetHTTPFilename(unsigned int mode){
	switch(mode){
	case MODE_POST:
		return post_tag_json;
	case MODE_TAG:
		return tags_tag_json;
	default:
		return "";
	}
}


int kcSendRecv(KCConection* connection, void** recv){

	int len;
	int resp_len = 0;
	char* json_serv = NULL;
	char cmd[2048];
	char inbuf[2048];

	/*	Generate HTTP request.	*/
	memset(cmd, 0, sizeof(cmd));
	sprintf(cmd,
			"GET /%s?%s=%s&page=%d&limit=%s HTTP/1.1 \r\n"
			"Host: %s \r\n"
			"%s"
			"Connection:close\r\n"
			"Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8\r\n"
			"Accept-Encoding: %s\r\n"
			"Accept-Language:en-US,en;q=0.8\r\n"
			"\r\n",
			kcGetHTTPFilename(g_mode),
			(g_mode == MODE_POST ? "tags" : "name"),
			g_tags, g_page, g_limit, g_host,
			g_secure ? "Referer:https://konachan.com/post \r\n" : "",
			g_compression ? "gzip, deflate, sdch"  : "");

	/*	Send HTTP request.	*/
	kcDebugPrintf(cmd);

	/*	*/
	if(connection->write(connection, cmd, strlen(cmd) +1) < 0){
		return -1;
	}

	/*	Fetch HTTP response.	*/
	while((len = connection->read(connection, inbuf, sizeof(inbuf))) > 0){
		resp_len += len;
		json_serv = realloc(json_serv, resp_len);
		memcpy(json_serv + ( resp_len - len ), inbuf, len);
	}

	/*	*/
	*recv = json_serv;

	return resp_len;
}


int kcDecodeInput(char* json_serv, int json_len, const unsigned int* forder, int nflags){

	/*	*/
	int status  = 0;
	int len;
	int comlen;
	char inbuf[4096];
	char* json_str;

	/*	JSON response.	*/
	struct json_object* j1 = NULL;
	struct json_object* j2 = NULL;
	enum json_tokener_error json_error;
	int i = 0;
	int j;
	int g_flag;

	/*	Reponse.	*/
	int httphlen;
	char* httpheader = NULL;

	assert(json_serv);

	/*	Add string terminator.	*/
	json_serv = realloc(json_serv, json_len + 1);
	json_serv[json_len] = '\0';

	/*	Parse HTTP's response header.	*/
	httpheader = kcSimpleExtractHtmlHeader(json_serv, &httphlen);
	if(httpheader == NULL){
		status = EXIT_FAILURE;
		goto error;
	}
	kcDebugPrintf(httpheader);


	/*	Extract html body.	*/
	if(kcUseHTTPGZipEncoding(httpheader)){
		comlen = 0;
		while((len = uncompress(inbuf, sizeof(inbuf), (const Bytef*)(json_serv + httphlen),
				(uLong)(json_len - httphlen))) > 0){

			json_str = realloc(json_str, comlen + len);
			memcpy(json_str + comlen, inbuf, len);
			comlen += len;
		}
	}else{
		json_str = json_serv + httphlen;
	}

	/*	Extract JSON.	*/
	json_str = kcSimpleExtractJSONBody(json_str);

	/*	Parse extracted JSON data.	*/
	j1 = json_tokener_parse_verbose(json_str, &json_error);

	/*	Check parsing errors.	*/
	if(is_error(j1)){
		fprintf(stderr, "%s\n", json_tokener_error_desc(json_error));
		status = EXIT_FAILURE;
		goto error;
	}

	/*	Extract value for each element in JSON array.	*/
	while((j2 = json_object_array_get_idx(j1, i)) != NULL){
		for(j = 0; j < nflags; j++){
			g_flag = forder[j];

			if(g_flag & FLAG_URL){
				printf("%s ", kcGetJSONValueByKey(j2, KEY_URL) );
			}
			if(g_flag & FLAG_URL_SIZE){
				printf("%s ", kcGetJSONValueByKey(j2, KEY_URL_SIZE) );
			}
			if(g_flag & FLAG_PREVIEW){
				printf("%s ", kcGetJSONValueByKey(j2, KEY_PREVIEW) );
			}
			if(g_flag & FLAG_SAMPLE_URL){
				printf("%s ", kcGetJSONValueByKey(j2, KEY_SAMPLE_URL) );
			}
			if(g_flag & FLAG_SAMPLE_URL_SIZE){
				printf("%s ", kcGetJSONValueByKey(j2, KEY_SAMPLE_URL_SIZE) );
			}
			if(g_flag & FLAG_TAGS){
				printf("%s ", kcGetJSONValueByKey(j2, KEY_TAGS) );
			}
			if(g_flag & FLAG_ID){
				printf("%s ", kcGetJSONValueByKey(j2, KEY_ID) );
			}
			if(g_flag & FLAG_JPEG_URL){
				printf("%s ", kcGetJSONValueByKey(j2, KEY_JPEG_URL) );
			}
			if(g_flag & FLAG_JPEG_SIZE){
				printf("%s ", kcGetJSONValueByKey(j2, KEY_JPEG_SIZE) );
			}
			if(g_flag & FLAG_PNG_URL){
				printf("%s ", kcGetJSONValueByKey(j2, KEY_PNG_URL) );
			}
			if(g_flag & FLAG_PNG_SIZE){
				printf("%s ", kcGetJSONValueByKey(j2, KEY_PNG_SIZE) );
			}
			if(g_flag & FLAG_SCORE){
				printf("%s ", kcGetJSONValueByKey(j2, KEY_SCORE) );
			}
			if(g_flag & FLAG_MD5){
				printf("%s ", kcGetJSONValueByKey(j2, KEY_MD5) );
			}
			if(g_flag & FLAG_SOURCE){
				printf("%s ", kcGetJSONValueByKey(j2, KEY_SOURCE) );
			}
			if(g_flag & FLAG_NAME){
				printf("%s ", kcGetJSONValueByKey(j2, KEY_NAME) );
			}
		}
		i++;
	}

	error:	/*	Error.	*/

	/*	Cleanup code.	*/
	json_object_put(j1);
	free(g_tags);
	free(json_serv);
	free(httpheader);


	return status;
}

int kcConnect(KCConection* connection, unsigned int mode, int af,
		const char* address, unsigned int port){

	/*	Sockets.	*/
	int status = 1;
	int s;
	struct sockaddr_in addr4;
	socklen_t soclen;
	struct sockaddr_in6 addr6;
	struct sockaddr* addr;
	int sslcode;
	struct addrinfo hints;
	struct addrinfo *result, *rp;

	/*	*/
	hints.ai_family = af;
	hints.ai_socktype = SOCK_STREAM;/* Datagram socket */
	hints.ai_flags = AI_PASSIVE;	/* For wildcard IP address */
	hints.ai_protocol = 0;			/* Any protocol */
	hints.ai_canonname = NULL;
	hints.ai_addr = NULL;
	hints.ai_next = NULL;
	s = getaddrinfo(g_host, NULL, &hints, &result);
	if (s != 0) {
	   fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(s));
	   exit(EXIT_FAILURE);
	}

	/*	Create socket.	*/
	af = result->ai_family;
	connection->sock = socket(af, SOCK_STREAM, 0);
	if(connection->sock  < 0){
		fprintf(stderr, "socket failed, %s.\n", strerror(errno));
		return EXIT_FAILURE;
	}

	/*	init socket address.	*/
	switch(af){
	case AF_INET:
		bzero(&addr4, sizeof(addr4));
		addr4.sin_family = AF_INET;
		addr4.sin_port = htons(port);
		/*	*/
		bcopy( &((const struct sockaddr_in*)result->ai_addr)->sin_addr,
		         (char*)&addr4.sin_addr.s_addr, 4);
		addr = (struct sockaddr*)&addr4;
		soclen = sizeof(addr4);
		break;
	case AF_INET6:
		break;
		addr6.sin6_family = AF_INET6;
		addr6.sin6_port = htons(port);
		addr = (struct sockaddr*)&addr6;
		soclen = sizeof(addr6);
		break;
	default:
		fprintf(stderr, "Invalid address family.\n");
		close(connection->sock );
		return EXIT_FAILURE;
	}

	/*	Release results.	*/
	freeaddrinfo(result);


	/*	TCP connection.	*/
	if( connect(connection->sock , addr, soclen ) < 0 ){
		fprintf(stderr, "Failed to connect to %s, %s\n", g_host, strerror(errno));
		status = 0;
		goto error;
	}

	/*	Use OpenSSL.	*/
	if( g_secure ){
		SSL_load_error_strings ();
		if( SSL_library_init () < 0){
			status = 0;
			goto error;
		}

		/*	Create context.	*/
		connection->ssl_ctx = SSL_CTX_new (TLSv1_2_client_method ());
		if( connection->ssl_ctx == NULL){
			status = 0;
			goto error;
		}

		SSL_CTX_set_options(connection->ssl_ctx, SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3);

		/* create an SSL connection and attach it to the socket	*/
		connection->conn = SSL_new(connection->ssl_ctx);
		if( SSL_set_fd(connection->conn, connection->sock ) == 0){
			status = 0;
			goto error;
		}

		/*	Connect by performing TLS/SSL handshake with server.	*/
		if( (sslcode = SSL_connect(connection->conn)) != 1 ){
			fprintf(stderr, "Failed to SSL connect, code %d.\n", SSL_get_error(connection->conn, sslcode));		/*	ERR_error_string(sslcode, NULL)	*/
			status = 0;
			goto error;
		}

		/*	*/
		connection->write = (PWRITE)kcSecWrite;
		connection->read = (PREAD)kcSecRead;
		connection->secure = 1;

	}else{
		/*	*/
		connection->secure = 0;
		connection->write = (PWRITE)kcNSecWrite;
		connection->read = (PREAD)kcNSecRead;
	}

	error:

	return status;
}

void kcDisconnect(KCConection* connection){

	if(connection->secure == 1 && connection->ssl_ctx != NULL){
		SSL_shutdown(connection->conn);
		SSL_free(connection->conn);
		SSL_CTX_free(connection->ssl_ctx);
	}
	close(connection->sock);
}

int kcSecWrite(KCConection* connection, const void* buffer, unsigned int len){
	return SSL_write(connection->conn, buffer, len);
}
int kcNSecWrite(KCConection* connection, const void* buffer, unsigned int len){
	return write(connection->sock, buffer, len);
}

int kcSecRead(KCConection* connection, void* buffer, unsigned int len){
	return SSL_read(connection->conn, buffer, len);
}
int kcNSecRead(KCConection* connection, void* buffer, unsigned int len){
	return read(connection->sock, buffer, len);
}
