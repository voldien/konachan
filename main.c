#include "konachan.h"
#include <errno.h>
#include <getopt.h>
#include <netdb.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <zlib.h>

int main(int argc, char *const * argv){

	/*	Exit status.	*/
	int status = EXIT_SUCCESS;

	/*	*/
	int resp_len = 0;
	char* json_serv = NULL;
	unsigned int* forder = NULL;
	unsigned int nflags;
	struct kc_connection_t connection = {0};

	/*	Sockets.	*/
	int s;
	int af = AF_UNSPEC;

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
			printf("version %s\n", kcGetVersion());
			return EXIT_SUCCESS;
		case 'd':
			kcg_debug = 1;
			break;
		case 'h':
			if(optarg){
				g_host = optarg;
			}
			break;
		case '4':
			af = AF_INET;
			break;
		case '6':
			af = AF_INET6;
			break;
		case 's':
			g_secure = 1;
			g_port = 443;
			break;
		case 'n':
			g_secure = 0;
			g_port = 80;
			break;
		case 'C':
			g_compression = 1;
			break;
		case 'l':
			if(optarg){
				g_limit = optarg;
			}
			break;
		case 'p':
			if(optarg){
				g_page = strtol(optarg, NULL, 10);
			}
			break;
		case 'P':
			if(optarg){
				g_port = strtol(optarg, NULL, 10);
			}
			break;
		case 't':
			if(optarg){
				tmptags = optarg;
			}
			break;
		case 'f':
			if(optarg){	/*	Get list of there order.	*/
				kcReadFlagOptions(optarg, &forder, &nflags);
			}
			break;
		case 'i':
			if(optarg){
				char idc[64];
				sprintf(idc, "id:%s+", optarg);
				if(g_tags == NULL){
					kcAllocateTagHeader(1024);
					memset(g_tags, '\0', 1024);
				}
				strcat(g_tags, idc);
			}
			break;
		case 'S':
			g_ratingmode = MODE_SAFE;
			break;
		case 'E':
			g_ratingmode = MODE_EXPLICIT;
			break;
		case 'r':
			g_randorder = 1;
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
		g_tags = kcConstructTagLValue(tmptags, g_mode == MODE_POST ? g_ratingmode : 0);
	}
	if(forder == NULL){
		kcReadFlagOptions("url", &forder, &nflags);
	}
	if(g_tags == NULL){
		return EXIT_FAILURE;
	}

	/*	*/
	if(!kcConnect(&connection, g_secure, af, g_host, g_port)){
		fprintf(stderr, "Failed creating connection.\n");
		return EXIT_FAILURE;
	}

	/*	*/
	resp_len = kcSendRecv(&connection, &json_serv);

	/*	Disconnect.	*/
	kcDisconnect(&connection);

	/*	Check.	*/
	if(resp_len <= 0 || json_serv == NULL)
		return EXIT_FAILURE;

	/*	*/
	if(!kcDecodeInput(json_serv, resp_len, forder, nflags)){
		return EXIT_FAILURE;
	}

	free(forder);

	return EXIT_SUCCESS;
}
