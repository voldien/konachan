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
#include "konachan.h"
#include <errno.h>
#include <getopt.h>
#include <netdb.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <json-c/json.h>
#include <json-c/json_object.h>
#include <json-c/json_tokener.h>
#include <zlib.h>
#include <openssl/ossl_typ.h>
#include <openssl/ssl.h>
#include <openssl/crypto.h>
#include <openssl/err.h>


int main(int argc, char *const * argv){

	/*	Exit status.	*/
	int status = EXIT_SUCCESS;

	/*	*/
	int len;
	int comlen;
	int resp_len = 0;
	char inbuf[4096];
	char cmd[4096];
	char* json_serv = NULL;
	char* json_str;
	unsigned int* forder = NULL;
	unsigned int nflags;

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

	/*	Sockets.	*/
	int s;
	int af = AF_UNSPEC;
	struct sockaddr_in addr4;
	socklen_t soclen;
	struct sockaddr_in6 addr6;
	struct sockaddr* addr;
	int sock;
	struct addrinfo hints;
	struct addrinfo *result, *rp;

	/*	Secure Socket layer for HTTP/S (Secure).	*/
	SSL *conn = NULL;
	SSL_CTX *ssl_ctx = NULL;
	int sslcode = 0;

	/*	Get option for long options.	*/
	static struct option longoption[] = {
		{"version", 		no_argument, 		0, 'v'},	/*	Version of the program.*/
		{"debug",			no_argument,		0, 'D'},	/*	Debug.	*/
		{"secure", 			no_argument, 		0, 's'},	/*	Force Secure connection.	*/
		{"not-secure", 		no_argument, 		0, 'n'},	/*	Force unsecure connection.	*/
		{"compression",		no_argument,		0, 'C'},	/*	Enable compression.	*/
		{"safe-mode", 		no_argument, 		0, 'S'},	/*	Set konachan safe mode.	*/
		{"explicit-mode",	no_argument, 		0, 'E'},	/*	Set konachan explict mode.	*/
		{"random",			no_argument, 		0, 'r'},	/*	Random order.	*/
		{"tag-list",		no_argument,		0, 'T'},	/*	List tags.	*/
		{"host", 			required_argument, 	0, 'h'},	/*	Set host to connect to.	*/
		{"limit", 			required_argument, 	0, 'l'},	/*	Set max number of result.	*/
		{"page", 			required_argument, 	0, 'p'},	/*	Set page start search from.	*/
		{"tags", 			required_argument, 	0, 't'},	/*	Tags used for searching.	*/
		{"flag", 			required_argument, 	0, 'f'},	/*	Flag */
		{"port", 			required_argument, 	0, 'P'},	/*	Change port for connecting to webserver.	*/
		{"id", 				required_argument, 	0, 'i'},	/*	Set element.	*/
		{NULL, 0, NULL, 0}
	};

	int c;
	int index;
	const char* shortopt = "vdh46l:p:t:f:P:snVErSCi:T";
	char* tmptags = NULL;

	while( (c = getopt_long(argc, argv, shortopt, longoption, &index)) != EOF){

		switch(c){
		case 'v':
			printf("version %s\n", getVersion());
			return EXIT_SUCCESS;
		case 'd':
			kcg_debug = 1;
			break;
		case 'h':
			if(optarg){
				host = optarg;
			}
			break;
		case '4':
			af = AF_INET;
			break;
		case '6':
			af = AF_INET6;
			break;
		case 's':
			secure = 1;
			port = 443;
			break;
		case 'n':
			secure = 0;
			port = 80;
			break;
		case 'C':
			compression = 1;
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
				port = strtol(optarg, NULL, 10);
			}
			break;
		case 't':
			if(optarg){
				tmptags = optarg;
			}
			break;
		case 'f':
			if(optarg){	/*	Get list of there order.	*/
				read_flag_options(optarg, &forder, &nflags);
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
			ratingmode = MODE_SAFE;
			break;
		case 'E':
			ratingmode = MODE_EXPLICIT;
			break;
		case 'r':
			randorder = 1;
			break;
		case 'T':
			g_mode = MODE_TAG;
			break;
		default:	/*	No such option.	*/
			break;
		}

	}

	/*	Construct tag string.	*/
	if( tmptags != NULL){
		tags = construct_tag_lvalue(tmptags, g_mode == MODE_POST ? ratingmode : 0);
	}
	if(forder == NULL){
		read_flag_options("url", &forder, &nflags);
	}
	if(tags == NULL){
		return EXIT_FAILURE;
	}


	/*	*/
	hints.ai_family = af;
	hints.ai_socktype = SOCK_STREAM; /* Datagram socket */
	hints.ai_flags = AI_PASSIVE;    /* For wildcard IP address */
	hints.ai_protocol = 0;          /* Any protocol */
	hints.ai_canonname = NULL;
	hints.ai_addr = NULL;
	hints.ai_next = NULL;
	s = getaddrinfo(host, NULL, &hints, &result);
	if (s != 0) {
	   fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(s));
	   exit(EXIT_FAILURE);
	}

	/*	Create socket.	*/
	af = result->ai_family;
	sock = socket(af, SOCK_STREAM, 0);
	if(sock < 0){
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
		close(sock);
		return EXIT_FAILURE;
	}

	/*	Release results.	*/
	freeaddrinfo(result);


	/*	TCP connection.	*/
	if( connect(sock, addr, soclen ) < 0 ){
		fprintf(stderr, "Failed to connect to %s, %s\n", host, strerror(errno));
		status = EXIT_FAILURE;
		goto error;
	}

	/*	Use OpenSSL.	*/
	if( secure ){
		SSL_load_error_strings ();
		if( SSL_library_init () < 0){
			status = EXIT_FAILURE;
			goto error;
		}

		/**/
		ssl_ctx = SSL_CTX_new (TLSv1_2_client_method ());
		if( ssl_ctx == NULL){
			status = EXIT_FAILURE;
			goto error;
		}

		SSL_CTX_set_options(ssl_ctx, SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3);

		/* create an SSL connection and attach it to the socket	*/
		conn = SSL_new(ssl_ctx);
		if( SSL_set_fd(conn, sock) == 0){
			status = EXIT_FAILURE;
			goto error;
		}

		/*	Connect by performing TLS/SSL handshake with server.	*/
		if( (sslcode = SSL_connect(conn)) != 1 ){
			fprintf(stderr, "Failed to SSL connect, code %d.\n", SSL_get_error(conn, sslcode));		/*	ERR_error_string(sslcode, NULL)	*/
			status = EXIT_FAILURE;
			goto error;
		}
	}

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
			get_http_filename(g_mode),
			(g_mode == MODE_POST ? "tags" : "name"),
			tags, page, limit, host,
			secure ? "Referer:https://konachan.com/post \r\n" : "",
			compression ? "gzip, deflate, sdch"  : "");

	/*	Send HTTP request.	*/
	debug_printf(cmd);
	if (secure == 1){
		if( (len = SSL_write(conn, cmd, strlen(cmd) +1)) < 0){
			status = EXIT_FAILURE;
			goto error;
		}
	}
	else {
		if(write(sock, cmd, strlen(cmd)) < 0){
			status = EXIT_FAILURE;
			goto error;
		}
	}

	/*	Fetch HTTP response.	*/
	if(secure == 1){
		while((len = SSL_read(conn, inbuf, sizeof(inbuf))) > 0){
			resp_len += len;
			json_serv = realloc(json_serv, resp_len);
			assert(json_serv);
			memcpy(json_serv + ( resp_len - len ), inbuf, len);
		}
	}
	else {
		while((len = read(sock, inbuf, sizeof(inbuf))) > 0){
			resp_len += len;
			json_serv = realloc(json_serv, resp_len);
			assert(json_serv);
			memcpy(json_serv + ( resp_len - len ), inbuf, len);
		}

	}

	/*	Check if the fetch was successfully.	*/
	if(json_serv == NULL || resp_len == 0){
		status = EXIT_FAILURE;
		goto error;
	}

	/*	Add string terminator.	*/
	json_serv = realloc(json_serv, resp_len + 1);
	json_serv[resp_len] = '\0';

	/*	Parse HTTP's response header.	*/
	httpheader = simple_extract_html_header(json_serv, &httphlen);
	if(httpheader == NULL){
		status = EXIT_FAILURE;
		goto error;
	}
	debug_printf(httpheader);


	/*	Extract html body.	*/
	if(http_use_gzip_encoding(httpheader)){
		comlen = 0;
		while((len = uncompress(inbuf, sizeof(inbuf), (const Bytef*)(json_serv + httphlen),
				(uLong)(resp_len - httphlen))) > 0){

			json_str = realloc(json_str, comlen + len);
			memcpy(json_str + comlen, inbuf, len);
			comlen += len;
		}
	}else{
		json_str = json_serv + httphlen;
	}

	/*	Extract JSON.	*/
	json_str = simple_extract_json_body(json_str);

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
				printf("%s ", get_json_value_by_key(j2, KEY_URL) );
			}
			if(g_flag & FLAG_URL_SIZE){
				printf("%s ", get_json_value_by_key(j2, KEY_URL_SIZE) );
			}
			if(g_flag & FLAG_PREVIEW){
				printf("%s ", get_json_value_by_key(j2, KEY_PREVIEW) );
			}
			if(g_flag & FLAG_SAMPLE_URL){
				printf("%s ", get_json_value_by_key(j2, KEY_SAMPLE_URL) );
			}
			if(g_flag & FLAG_SAMPLE_URL_SIZE){
				printf("%s ", get_json_value_by_key(j2, KEY_SAMPLE_URL_SIZE) );
			}
			if(g_flag & FLAG_TAGS){
				printf("%s ", get_json_value_by_key(j2, KEY_TAGS) );
			}
			if(g_flag & FLAG_ID){
				printf("%s ", get_json_value_by_key(j2, KEY_ID) );
			}
			if(g_flag & FLAG_JPEG_URL){
				printf("%s ", get_json_value_by_key(j2, KEY_JPEG_URL) );
			}
			if(g_flag & FLAG_JPEG_SIZE){
				printf("%s ", get_json_value_by_key(j2, KEY_JPEG_SIZE) );
			}
			if(g_flag & FLAG_PNG_URL){
				printf("%s ", get_json_value_by_key(j2, KEY_PNG_URL) );
			}
			if(g_flag & FLAG_PNG_SIZE){
				printf("%s ", get_json_value_by_key(j2, KEY_PNG_SIZE) );
			}
			if(g_flag & FLAG_SCORE){
				printf("%s ", get_json_value_by_key(j2, KEY_SCORE) );
			}
			if(g_flag & FLAG_MD5){
				printf("%s ", get_json_value_by_key(j2, KEY_MD5) );
			}
			if(g_flag & FLAG_SOURCE){
				printf("%s ", get_json_value_by_key(j2, KEY_SOURCE) );
			}
			if(g_flag & FLAG_NAME){
				printf("%s ", get_json_value_by_key(j2, KEY_NAME) );
			}
		}
		i++;
	}

	error:	/*	Error.	*/

	/*	Cleanup code.	*/
	json_object_put(j1);
	free(tags);
	free(json_serv);
	free(httpheader);
	free(forder);
	if(secure == 1 && ssl_ctx != NULL){
		SSL_shutdown(conn);
		SSL_free(conn);
		SSL_CTX_free(ssl_ctx);
	}
	close(sock);

	return status;
}
