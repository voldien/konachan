#include"konachan.h"
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
 *	Global variables.
 */
char* host = "konachan.com";		/*	host. (Default konachan.com )	*/
char* limit = "1";					/*	limit. ( 1 result by default)	*/
int page = 0;						/*	page.	*/
char* tags = NULL;					/*	tags.	*/
unsigned int verbose = 1;			/*	verbose mode.	*/
unsigned int kcg_debug = 0;			/*	debug mode.	*/
unsigned int port = 443;			/*	port to connect to. (Default HTTPS port).*/
unsigned int secure = 1;			/*	security mode. (Default enabled.)	*/
unsigned int ratingmode = 1;		/*	Search rating. (Safe by default.).	*/
unsigned int compression = 0;		/*	Use compression.	*/
unsigned int randorder = 0;			/*	random order.	*/
unsigned int g_mode = MODE_POST;

/**
 *	Global constant variables.
 */
const char* post_tag_json = "post.json";
const char* tags_tag_json = "tag.json";

/**
 *
 */
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

/**
 *
 */
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

/**
 *
 */
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



/**
 *	@Return get version string.
 */
const char* getVersion(void){
	return KONACHAN_STR_VERSION;
}

/**
 *	Debug print formated.
 */
void debug_printf(const char* format, ...){
	va_list vl;

	if(kcg_debug){
		va_start(vl,format);
		vfprintf(stderr, format, vl);	/*	TODO resolve file descriptor.	*/
		va_end(vl);
	}
}

/**
 *
 */
void simple_remove_escape_str(char* str){
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


const char* get_json_value_by_key(struct json_object* json, const char* key){

	struct json_object* pvalue;
	char* strvalue;
	json_bool ret;

	/*	*/
	ret = json_object_object_get_ex(json, key, &pvalue);
	if(ret){
		strvalue = json_object_to_json_string(pvalue);
		simple_remove_escape_str(strvalue);
		return strvalue;
	} else{
		return "";
	}
}


/**
 *	Extract root json array.
 */
char* simple_extract_json_body(char* str){

	char* b = strchr(str, '[');
	char* e = strrchr(str, ']');

	/*	Terminate string.	*/
	e++;
	*e = '\0';

	return b;
}


char* simple_extract_html_header(char* str, int* headerlen){

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
int http_use_gzip_encoding(const char* header){

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
char* allocate_tag_header(size_t size){
	tags = realloc(tags, size);
	assert(tags);
	return tags;
}

/**
 *	Construct tag string for HTTP can
 *	interpret.
 */
char* construct_tag_lvalue(const char* opts, unsigned int rating){

	char* tag;

	/*	*/
	tag = allocate_tag_header(strlen(opts) + 1024);
	memcpy(tag, opts, strlen(opts) + 1);
	char* tmp = tag;
	while( ( tmp = strstr(tmp, " ") ) ){
		*tmp = '+';
		tmp++;
	}

	if(rating > 0 || randorder > 0){
		strcat(tag, "+");
	}

	/*	Rating.	*/
	if(rating == MODE_SAFE){
		strcat(tag, "%20rating:safe" );
	}
	else if(rating == MODE_EXPLICIT){
		strcat(tag, "%20rating:explicit" );
	}

	if(randorder == 1){
		strcat(tag, "+order%3Arandom" );
	}


	return tag;
}


/**
 *	Read flag options.
 */
void read_flag_options(const char* optarg, unsigned int** lorder,
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
			porder[optcount] = get_str_value_to_enum(tmpstr);
			optcount++;

			hstr = whstr;
		}
	}

	free(tmpstr);
	*lorder = porder;
	*count = optcount;
}

unsigned int get_str_value_to_enum(const char* opt){

	int i = 0;

	do{
		if(strstr(opt,flag_name_table[i])){
			return flag_value_table[i];
		}
		i++;
	}while(flag_name_table[i]);

	return 0;
}


const char* get_http_filename(unsigned int mode){
	switch(mode){
	case MODE_POST:
		return post_tag_json;
	case MODE_TAG:
		return tags_tag_json;
	default:
		return "";
	}
}
