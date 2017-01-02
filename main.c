/**
	Konachan is command search tool.
    Copyright (C) 2016  Valdemar Lindberg

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
#include <errno.h>
#include <getopt.h>
#include <json-c/json.h>
#include <json-c/json_object.h>
#include <json-c/json_tokener.h>
#include <netdb.h>
#include <netinet/in.h>
#include <openssl/ossl_typ.h>
#include <openssl/ssl.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>
#include <stdarg.h>
#include <assert.h>


/**
 *	Global variable.
 */
char* host = "konachan.com";			/*	host. (Default konachan.com )	*/
char* limit = "1";				/*	limit. ( 1 result by default)	*/
int page = 0;					/*	page.	*/
char* tags = NULL;				/*	tags.	*/
unsigned int verbose = 1;			/*	verbose mode.	*/
unsigned int flag = 0x4;			/*	flags.	*/
unsigned int port = 443;			/*	port to connect to. (Default HTTPS port).*/
unsigned int secure = 1;			/*	security mode. (Default enabled.)	*/
unsigned int verbosefd;				/*	verbose file description.	*/
unsigned int ratingmode = 0;			/*	Search rating. (Disable by default).	*/


/**
 *	Flags.
 */
#define FLAG_URL 0x1				/*	Get url.	*/
#define FLAG_URL_SIZE 0x2			/*	Get url size in bytes.	*/
#define FLAG_PREVIEW 0x4			/*	Get preview.*/
#define FLAG_PREVIEW_SIZE 0x8		/*	Not supported.	*/
#define FLAG_SAMPLE_URL 0x10		/*	Get sample url.	*/
#define FLAG_SAMPLE_URL_SIZE 0x20	/*	Get sample size in bytes.	*/
#define FLAG_TAGS 0x40				/*	Get tags associated with result.	*/
#define FLAG_ID 0x80				/*	Get the ID of the object.	*/
#define FLAG_JPEG_URL 0x100			/*	Get JPEG url if exists.	*/
#define FLAG_JPEG_SIZE 0x200		/*	Get JPEG size in bytes if exits.	*/
#define FLAG_PNG_URL 0x400			/*	Not supported.	*/
#define FLAG_PNG_SIZE 0x800			/*	Not supported.	*/
#define FLAG_SCORE 0x1000			/*	Get source as a numeric digit.*/
#define FLAG_MD5 0x2000				/*	Get hashed MD5 for the  .	*/
#define FLAG_SOURCE 0x4000			/*	Get source of the object.	*/



/**
 *	Flag keyword.
 */
#define FLAG_KEY_URL "url"
#define FLAG_KEY_URL_SIZE "size"
#define FLAG_KEY_PREVIEW_URL "preview"
#define FLAG_KEY_PREVIEW_SIZE "preview_size"
#define FLAG_KEY_SAMPLE_URL "sample"
#define FLAG_KEY_SAMPLE_SIZE "sampe_size"
#define FLAG_KEY_TAGS "tags"
#define FLAG_KEY_ID "id"
#define FLAG_KEY_JPEG_URL "jpeg_url"
#define FLAG_KEY_JPEG_SIZE "jpeg_size"
#define FLAG_KEY_PNG_URL "png_url"
#define FLAG_KEY_PNG_SIZE "png_size"
#define FLAG_KEY_SCORE "score"
#define FLAG_KEY_MD5 "md5"
#define FLAG_KEY_SOURCE "source"

/**
 *	Rating mode
 */
#define MODE_SAFE 0x1
#define MODE_EXPLICIT 0x2


/**
 *	JSON attribute name key.
 */
#define KEY_URL "file_url"					/*	JSON attribute name for file URL.	*/
#define KEY_URL_SIZE "file_size"			/*	JSON attribute name*/
#define KEY_PREVIEW "preview_url"			/*	JSON attribute name*/
#define KEY_PREVIEW_SIZE "preview_url"		/*	Not supported.	*/
#define KEY_SAMPLE_URL "sample_url"			/*	*/
#define KEY_SAMPLE_URL_SIZE "sample_file_size"
#define KEY_TAGS "tags"
#define KEY_ID "id"
#define KEY_JPEG_URL "jpeg_url"
#define KEY_JPEG_SIZE "jpeg_file_size"
#define KEY_PNG_URL "png_url"
#define KEY_PNG_SIZE "png_file_size"
#define KEY_SCORE "score"
#define KEY_MD5 "md5"
#define KEY_SOURCE "source"



/**
 *	@Return get version string.
 */
const char* getVersion(void){
	return "1.0.2";
}

/**
 *
 */
void verbose_printf(const char* format, ...){
	va_list vl;

	if(verbose == 1){
		va_start(vl,format);
		vfprintf(stderr, format, vl);	/*	TODO resolve file descriptor.	*/
		va_end(vl);
	}
}

const char* get_json_value_by_key(struct json_object* json, const char* key){

	struct json_object* tmp;
	char* tout;

	tmp = json_object_object_get(json, key);

	if(tmp){
		tout = json_object_to_json_string(tmp);
		simple_escape_str(tout);
		return tout;
	} else{
		return "";
	}
}

/**
 *
 */
void simple_escape_str(char* str){
	char* pstr;

	/*	convert \\/ to a / */
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

/**
 *
 */
char* simple_extract_json_body(char* str){

	char* b = strchr(str, '[');
	char* e = strrchr(str, ']');

	e++;
	*e = '\0';

	return b;
}



/**
 *	@Return
 */
char* simple_extract_html_body(char* str){

	const char* bc = "\r\n\r\n";

	/*	Find beginning.	*/
	str = strstr(str, bc);
	str += strlen(bc);

	/*	Next line after a hexadecimal.	*/
	str = strstr(str, "\n");
	str[0] = '\0';
	str++;

	return str;
}

/**
 *	Allocate tag header.
 *
 *	@Return
 */
char* allocate_tag_header(size_t size){
	tags = realloc(tags, size);
	assert(tags);
	return tags;
}

/**
 *	Construct tag string for HTTP can
 *	interpret.
 */
char* construct_tag_lvalue(const char* opts){
	char* tag;
	int len;

	/*	*/
	tag = allocate_tag_header(strlen(opts) + 1024);
	memcpy(tag, opts, strlen(opts) + 1);
	char* tmp = tag;
	while( ( tmp = strstr(tmp, " ") ) ){
		*tmp = '+';
		tmp++;
	}
	len = strlen(tag);
	strcat(tag, "+");

	/*	Rating.	*/
	if(ratingmode == MODE_SAFE){
		strcat(tag, "%20rating:safe" );
	}
	if(ratingmode == MODE_EXPLICIT){
		strcat(tag, "%20rating:explicit" );
	}

	return tag;
}


/**
 *	Read flag options.
 */
void read_flag_options(const char* optarg){

	flag = 0;

	if(strstr(optarg, FLAG_KEY_URL) != NULL){
		flag |= FLAG_URL;
	}
	if(strstr(optarg, FLAG_KEY_URL_SIZE) != NULL){
		flag |= FLAG_URL_SIZE;
	}
	if(strstr(optarg, FLAG_KEY_PREVIEW_URL) != NULL){
		flag |= FLAG_PREVIEW;
	}
	if(strstr(optarg, FLAG_KEY_PREVIEW_SIZE) != NULL){
		flag |= FLAG_PREVIEW_SIZE;
	}
	if(strstr(optarg, FLAG_KEY_SAMPLE_URL) != NULL){
		flag |= FLAG_SAMPLE_URL;
	}
	if(strstr(optarg, FLAG_KEY_SAMPLE_SIZE)!= NULL){
		flag |= FLAG_SAMPLE_URL_SIZE;
	}
	if(strstr(optarg, FLAG_KEY_TAGS) != NULL){
		flag |= FLAG_TAGS;
	}
	if(strstr(optarg, FLAG_KEY_ID) != NULL){
		flag |= FLAG_ID;
	}
	if(strstr(optarg, FLAG_KEY_JPEG_URL) != NULL){
		flag |= FLAG_JPEG_URL;
	}
	if(strstr(optarg, FLAG_KEY_JPEG_SIZE) != NULL){
		flag |= FLAG_JPEG_SIZE;
	}
	if(strstr(optarg, FLAG_KEY_PNG_URL) != NULL){
		flag |= FLAG_PNG_URL;
	}
	if(strstr(optarg, FLAG_KEY_PNG_SIZE) != NULL){
		flag |= FLAG_PNG_SIZE;
	}
	if(strstr(optarg, FLAG_KEY_SCORE) != NULL){
		flag |= FLAG_SCORE;
	}
	if(strstr(optarg, FLAG_KEY_MD5) != NULL){
		flag |= FLAG_MD5;
	}
	if(strstr(optarg, FLAG_KEY_SCORE) != NULL){
		flag |= FLAG_SOURCE;
	}
}



int main(int argc, char *const * argv){

	/*	Exit status.	*/
	int status = EXIT_SUCCESS;

	/*	*/
	int len;
	int total = 0;
	char inbuf[1024];
	char cmd[8192];
	char* json_serv;
	char* json_str;

	/*	*/
	struct sockaddr_in serv_addr;
	int sock;
	struct hostent* server;

	/*	Secure Socket layer for HTTP/S (Secure).	*/
	SSL *conn = NULL;
	SSL_CTX *ssl_ctx = NULL;


	/*	Get option for long options.	*/
	static struct option longoption[] = {
		{"version", 		no_argument, 		0, 'v'},
		{"secure", 			no_argument, 		0, 's'},
		{"not-secure", 		no_argument, 		0, 'n'},
		{"safe-mode", 		no_argument, 		0, 'S'},
		{"explicit-mode",	no_argument, 		0, 'E'},
		{"host", 			required_argument, 	0, 'h'},
		{"limit", 			required_argument, 	0, 'l'},
		{"page", 			required_argument, 	0, 'p'},
		{"tags", 			required_argument, 	0, 't'},
		{"flag", 			required_argument, 	0, 'f'},
		{"port", 			required_argument, 	0, 'P'},
		{"id", 				required_argument, 	0, 'i'},

		{NULL, 0, NULL, 0}
	};

	int c;
	int index;
	const char* shortopt = "vh:l:p:t:f:P:snVESi:";
	char* tmptags = NULL;

	while( (c = getopt_long(argc, argv, shortopt, longoption, &index)) != EOF){

		switch(c){
		case 'v':

			printf("version %s\n", getVersion());
			return EXIT_SUCCESS;
		case 'h':
			if(optarg){
				host = optarg;
			}
			break;
		case 's':
			secure = 1;
			port = 443;
			break;
		case 'n':
			secure = 0;
			port = 80;
			break;
		case 'l':
			if(optarg){
				limit = optarg;
			}
			break;
		case 'p':
			if(optarg){
				page = strtol(optarg, NULL, 10);
			}
			break;
		case 'P':
			if(optarg){
				port = strtol(optarg, NULL ,10);
			}
			break;
		case 't':
			if(optarg){
				tmptags = optarg;
			}
			break;
		case 'f':
			if(optarg){
				read_flag_options(optarg);
			}
			break;
		case 'i':
			if(optarg){
				char idc[64];
				sprintf(idc, "id:%s+", optarg);
				if(tags == NULL){
					allocate_tag_header(1024);
					memset(tags, '\0', 1024);
				}
				strcat(tags, idc);
			}
			break;
		case 'S':
			ratingmode |= MODE_SAFE;
			break;
		case 'E':
			ratingmode |= MODE_EXPLICIT;
			break;
		default:	/*	No such option.	*/
			break;
		}

	}


	/*	*/
	if( tmptags != NULL ){
		tags = construct_tag_lvalue(tmptags);
	}
	else if(tags == NULL){
		return EXIT_FAILURE;
	}


	sock = socket(AF_INET, SOCK_STREAM, 0);
	if(sock < 0){
		return EXIT_FAILURE;
	}

	/*	init addr.	*/
	bzero(&serv_addr, sizeof(serv_addr));
	serv_addr.sin_family = AF_INET;
	serv_addr.sin_port = htons(port);


	/*	*/
	server = gethostbyname(host);
	if(server == NULL){
		close(sock);
		return EXIT_FAILURE;
	}

	/*	*/
	bcopy((const void*)server->h_addr,
	         (char*)&serv_addr.sin_addr.s_addr,
	         (size_t)server->h_length);


	/*	ssl	*/
	if( secure == 1 ){
		SSL_load_error_strings ();
		SSL_library_init ();

		/**/
		ssl_ctx = SSL_CTX_new (TLSv1_2_client_method ());
		if( ssl_ctx == NULL){
			status = EXIT_FAILURE;
			goto error;
		}

		/* create an SSL connection and attach it to the socket	*/
		conn = SSL_new(ssl_ctx);
		if( SSL_set_fd(conn, sock) == 0){
			status = EXIT_FAILURE;
			goto error;
		}
	}


	if( connect(sock, (struct sockaddr *)&serv_addr, sizeof(serv_addr) ) < 0 ){
		fprintf(stderr, "Failed to connect to %s, %s\n", host, strerror(errno));
		status = EXIT_FAILURE;
		goto error;
	}

	/*	Connect by performing TLS/SSL handshake with server.	*/
	if(secure == 1){
		if( SSL_connect(conn) != 1 ){
			status = EXIT_FAILURE;
			goto error;
		}
	}


	/*	Generate HTTP request.	*/
	memset(cmd, 0, sizeof(cmd));
	sprintf(cmd,
			"GET /post.json?tags=%s&page=%d&limit=%s HTTP/1.1 \r\n"
			"Host: %s \r\n"
			"%s"
			"Accept-Encoding:gzip, deflate, sdch\r\n"
			"Accept-Language:en-US,en;q=0.8\r\n"
			"Accept:text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8 \r\n"
			"\r\n", tags, page, limit, host, secure ? "Referer: https://konachan.com/post \r\n" : "");


	/*	Send HTTP request.	*/
	if (secure == 1){
		if( (len = SSL_write(conn, cmd, strlen(cmd) +1)) < 0){
			status = EXIT_FAILURE;
			goto error;
		}
	}
	else {
		if(write(sock, cmd, strlen(cmd) + 1) < 0){
			status = EXIT_FAILURE;
			goto error;
		}
	}



	/*	Fetch HTTP response.	*/
	if(secure == 1){
		while((len = SSL_read(conn, inbuf, sizeof(inbuf))) > 0){
			total += len;
			json_serv = realloc(json_serv, total);
			memcpy(json_serv + ( total - len ), inbuf, len);
		}
	}
	else {
		while((len = read(sock, inbuf, sizeof(inbuf))) > 0){
			total += len;
			json_serv = realloc(json_serv, total);
			memcpy(json_serv + ( total - len ), inbuf, len);
		}
	}

	/*	Check if the fetch was successfully.	*/
	if(json_serv == NULL || total < 0){
		status = EXIT_FAILURE;
		goto error;
	}


	/*	Extract html */
	json_str = simple_extract_html_body(json_serv);

	/*	Extract JSON.	*/
	json_str = simple_extract_json_body(json_str);


	/*	Parse extracted JSON data.	*/
	struct json_object* j1 = NULL;
	struct json_object* j2 = NULL;
	enum json_tokener_error json_error;
	int i = 0;
	j1 = json_tokener_parse_verbose(json_str, &json_error);

	/*	Check parsing errors.	*/
	if(is_error(j1)){
		fprintf(stderr, "%s\n", json_tokener_errors[json_error]);
		status = EXIT_FAILURE;
		goto error;
	}


	/*	Extract value for each element in JSON array.	*/
	while((j2 = json_object_array_get_idx(j1, i)) != NULL){

		if(flag & FLAG_URL){
			printf("%s ", get_json_value_by_key(j2, KEY_URL) );
		}
		if(flag & FLAG_URL_SIZE){
			printf("%s ", get_json_value_by_key(j2, KEY_URL_SIZE) );
		}
		if(flag & FLAG_PREVIEW){
			printf("%s ", get_json_value_by_key(j2, KEY_PREVIEW) );
		}
		if(flag & FLAG_SAMPLE_URL){
			printf("%s ", get_json_value_by_key(j2, KEY_SAMPLE_URL) );
		}
		if(flag & FLAG_SAMPLE_URL_SIZE){
			printf("%s ", get_json_value_by_key(j2, KEY_SAMPLE_URL_SIZE) );
		}
		if(flag & FLAG_TAGS){
			printf("%s ", get_json_value_by_key(j2, KEY_TAGS) );
		}
		if(flag & FLAG_ID){
			printf("%s ", get_json_value_by_key(j2, KEY_ID) );
		}
		if(flag & FLAG_ID){
			printf("%s ", get_json_value_by_key(j2, KEY_ID) );
		}
		if(flag & FLAG_JPEG_URL){
			printf("%s ", get_json_value_by_key(j2, KEY_JPEG_URL) );
		}
		if(flag & FLAG_JPEG_SIZE){
			printf("%s ", get_json_value_by_key(j2, KEY_JPEG_SIZE) );
		}
		if(flag & FLAG_PNG_URL){
			printf("%s ", get_json_value_by_key(j2, KEY_PNG_URL) );
		}
		if(flag & FLAG_PNG_SIZE){
			printf("%s ", get_json_value_by_key(j2, KEY_PNG_SIZE) );
		}
		if(flag & FLAG_SCORE){
			printf("%s ", get_json_value_by_key(j2, KEY_SCORE) );
		}
		if(flag & FLAG_MD5){
			printf("%s ", get_json_value_by_key(j2, KEY_MD5) );
		}
		if(flag & FLAG_SOURCE){
			printf("%s ", get_json_value_by_key(j2, KEY_SOURCE) );
		}


		i++;
	}

	error:	/*	Error.	*/

	/*	Cleanup code.	*/
	json_object_put(j1);
	free(tags);
	free(json_serv);
	if(secure == 1 && ssl_ctx != NULL){
		SSL_shutdown(conn);
		SSL_free(conn);
		SSL_CTX_free(ssl_ctx);
	}
	close(sock);

	return status;
}
