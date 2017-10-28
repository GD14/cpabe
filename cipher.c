#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <glib.h>
#include <pbc.h>
#include <pbc_random.h>
#include <time.h> 
#include<sys/time.h>

#include "bswabe.h"
#include "common.h"
#include "policy_lang.h"

char* setup_usage =
"Usage: cpabe-setup [OPTION ...]\n"
"\n"
"Generate system parameters, a public key, and a master secret key\n"
"for use with cpabe-keygen, cpabe-enc, and cpabe-dec.\n"
"\n"
"Output will be written to the files \"pub_key\" and \"master_key\"\n"
"unless the --output-public-key or --output-master-key options are\n"
"used.\n"
"\n"
"Mandatory arguments to long options are mandatory for short options too.\n\n"
" -h, --help                    print this message\n\n"
" -v, --version                 print version information\n\n"
" -p, --output-public-key FILE  write public key to FILE\n\n"
" -m, --output-master-key FILE  write master secret key to FILE\n\n"
" -d, --deterministic           use deterministic \"random\" numbers\n"
"                               (only for debugging)\n\n"
"";


char* default_pub_file = "pub_key";
char* default_msk_file = "master_key";

char* in_file  = 0;
//char* out_file = 0;
int   keep     = 1;
char* policy = 0;
char*  pub_file = 0;
char*  prv_file=0;
char*  msk_file = 0;
char** attrs    = 0;
char*  out_file = 0;


clock_t start,finish;  
		void
setup_args( int argc, char** argv )
{
		int i;

		for( i = 1; i < argc; i++ )
				if(      !strcmp(argv[i], "-h") || !strcmp(argv[i], "--help") )
				{
						printf("%s", setup_usage);
						exit(0);
				}
				else if( !strcmp(argv[i], "-v") || !strcmp(argv[i], "--version") )
				{
						printf(CPABE_VERSION, "-setup");
						exit(0);
				}
				else if( !strcmp(argv[i], "-p") || !strcmp(argv[i], "--output-public-key") )
				{
						if( ++i >= argc )
								die(setup_usage);
						else
								default_pub_file = argv[i];
				}
				else if( !strcmp(argv[i], "-m") || !strcmp(argv[i], "--output-master-key") )
				{
						if( ++i >= argc )
								die(setup_usage);
						else
								default_msk_file = argv[i];
				}
				else if( !strcmp(argv[i], "-d") || !strcmp(argv[i], "--deterministic") )
				{
						pbc_random_set_deterministic(0);
				}
				else
						die(setup_usage);
}

char* enc_usage =
"Usage: cpabe-enc [OPTION ...] PUB_KEY FILE [POLICY]\n"
"\n"
"Encrypt FILE under the decryption policy POLICY using public key\n"
"PUB_KEY. The encrypted file will be written to FILE.cpabe unless\n"
"the -o option is used. The original file will be removed. If POLICY\n"
"is not specified, the policy will be read from stdin.\n"
"\n"
"Mandatory arguments to long options are mandatory for short options too.\n\n"
" -h, --help               print this message\n\n"
" -v, --version            print version information\n\n"
" -k, --keep-input-file    don't delete original file\n\n"
" -o, --output FILE        write resulting key to FILE\n\n"
" -d, --deterministic      use deterministic \"random\" numbers\n"
"                          (only for debugging)\n\n"
"";


		void
enc_args( int argc, char** argv )
{
		int i;

		for( i = 1; i < argc; i++ )
				if(      !strcmp(argv[i], "-h") || !strcmp(argv[i], "--help") )
				{
						printf("%s", enc_usage);
						exit(0);
				}
				else if( !strcmp(argv[i], "-v") || !strcmp(argv[i], "--version") )
				{
						printf(CPABE_VERSION, "-enc");
						exit(0);
				}
				else if( !strcmp(argv[i], "-k") || !strcmp(argv[i], "--keep-input-file") )
				{
						keep = 1;
				}
				else if( !strcmp(argv[i], "-o") || !strcmp(argv[i], "--output") )
				{
						if( ++i >= argc )
								die(enc_usage);
						else
								out_file = argv[i];
				}
				else if( !strcmp(argv[i], "-d") || !strcmp(argv[i], "--deterministic") )
				{
						pbc_random_set_deterministic(0);
				}
				else if( !pub_file )
				{
						pub_file = argv[i];
				}
				else if( !in_file )
				{
						in_file = argv[i];
				}
				else if( !policy )
				{
						policy = parse_policy_lang(argv[i]);
				}
				else
						die(enc_usage);

		if( !pub_file || !in_file )
				die(enc_usage);

		if( !out_file )
				out_file = g_strdup_printf("%s.cpabe", in_file);

		if( !policy )
				policy = parse_policy_lang(suck_stdin());
}

bswabe_pub_t* pub=0;
bswabe_msk_t* msk=0;
bswabe_prv_t* prv;


	
void setup(){
	if(pub==NULL&&msk==NULL)	
	bswabe_setup(&pub, &msk);
}

void enc( int argc, char** argv )
{
		bswabe_pub_t* pub;
		bswabe_cph_t* cph;
		int file_len;
		GByteArray* plt;
		GByteArray* cph_buf;
		GByteArray* aes_buf;
		element_t m;

		enc_args(argc, argv);


	//  get from the global var
	//	pub = bswabe_pub_unserialize(suck_file(pub_file), 1);

		if( !(cph = bswabe_enc(pub, m, policy)) )
				die("%s", bswabe_error());
		free(policy);

		cph_buf = bswabe_cph_serialize(cph);
		bswabe_cph_free(cph);

		plt = suck_file(in_file);
		file_len = plt->len;
		aes_buf = aes_128_cbc_encrypt(plt, m);
		g_byte_array_free(plt, 1);
		element_clear(m);
		write_cpabe_file(out_file, cph_buf, file_len, aes_buf);

		g_byte_array_free(cph_buf, 1);
		g_byte_array_free(aes_buf, 1);

		printf("out_file %s\n",out_file);
		if( !keep )
				unlink(in_file);

}

char* keygen_usage =
"Usage: cpabe-keygen [OPTION ...] PUB_KEY MASTER_KEY ATTR [ATTR ...]\n"
"\n"
"Generate a key with the listed attributes using public key PUB_KEY and\n"
"master secret key MASTER_KEY. Output will be written to the file\n"
"\"priv_key\" unless the -o option is specified.\n"
"\n"
"Attributes come in two forms: non-numerical and numerical. Non-numerical\n"
"attributes are simply any string of letters, digits, and underscores\n"
"beginning with a letter.\n"
"\n"
"Numerical attributes are specified as `attr = N', where N is a non-negative\n"
"integer less than 2^64 and `attr' is another string. The whitespace around\n"
"the `=' is optional. One may specify an explicit length of k bits for the\n"
"integer by giving `attr = N#k'. Note that any comparisons in a policy given\n"
"to cpabe-enc(1) must then specify the same number of bits, e.g.,\n"
"`attr > 5#12'.\n"
"\n"
"The keywords `and', `or', and `of', are reserved for the policy language\n"
"of cpabe-enc (1) and may not be used for either type of attribute.\n"
"\n"
"Mandatory arguments to long options are mandatory for short options too.\n\n"
" -h, --help               print this message\n\n"
" -v, --version            print version information\n\n"
" -o, --output FILE        write resulting key to FILE\n\n"
" -d, --deterministic      use deterministic \"random\" numbers\n"
"                          (only for debugging)\n\n"
"";

/*
   TODO ensure we don't give out the same attribute more than once (esp
   as different numerical values)
 */

		gint
comp_string( gconstpointer a, gconstpointer b)
{
		return strcmp(a, b);
}

		void
keygen_args( int argc, char** argv )
{
		int i;
		GSList* alist;
		GSList* ap;
		int n;

		alist = 0;
		for( i = 1; i < argc; i++ )
				if(      !strcmp(argv[i], "-h") || !strcmp(argv[i], "--help") )
				{
						printf("%s", keygen_usage);
						exit(0);
				}
				else if( !strcmp(argv[i], "-v") || !strcmp(argv[i], "--version") )
				{
						printf(CPABE_VERSION, "-keygen");
						exit(0);
				}
				else if( !strcmp(argv[i], "-o") || !strcmp(argv[i], "--output") )
				{
						if( ++i >= argc )
								die(keygen_usage);
						else
								out_file = argv[i];
				}
				else if( !strcmp(argv[i], "-d") || !strcmp(argv[i], "--deterministic") )
				{
						pbc_random_set_deterministic(0);
				}
				else if( !pub_file )
				{
						pub_file = argv[i];
				}
				else if( !msk_file )
				{
						msk_file = argv[i];
				}
				else
				{
						parse_attribute(&alist, argv[i]);
				}

		if( !pub_file || !msk_file || !alist )
				die(keygen_usage);

		alist = g_slist_sort(alist, comp_string);
		n = g_slist_length(alist);

		attrs = malloc((n + 1) * sizeof(char*));

		i = 0;
		for( ap = alist; ap; ap = ap->next )
				attrs[i++] = ap->data;
		attrs[i] = 0;
}

void keygen( int argc, char** argv )
{
				keygen_args(argc, argv);

		pub = bswabe_pub_unserialize(suck_file(pub_file), 1);
		msk = bswabe_msk_unserialize(pub, suck_file(msk_file), 1);

		prv = bswabe_keygen(pub, msk, attrs);
		spit_file(out_file, bswabe_prv_serialize(prv), 1);

}


char* dec_usage =
"Usage: cpabe-dec [OPTION ...] PUB_KEY PRIV_KEY FILE\n"
"\n"
"Decrypt FILE using private key PRIV_KEY and assuming public key\n"
"PUB_KEY. If the name of FILE is X.cpabe, the decrypted file will\n"
"be written as X and FILE will be removed. Otherwise the file will be\n"
"decrypted in place. Use of the -o option overrides this\n"
"behavior.\n"
"\n"
"Mandatory arguments to long options are mandatory for short options too.\n\n"
" -h, --help               print this message\n\n"
" -v, --version            print version information\n\n"
" -k, --keep-input-file    don't delete original file\n\n"
" -o, --output FILE        write output to FILE\n\n"
" -d, --deterministic      use deterministic \"random\" numbers\n"
"                          (only for debugging)\n\n"
/* " -s, --no-opt-sat         pick an arbitrary way of satisfying the policy\n" */
/* "                          (only for performance comparison)\n\n" */
/* " -n, --naive-dec          use slower decryption algorithm\n" */
/* "                          (only for performance comparison)\n\n" */
/* " -f, --flatten            use slightly different decryption algorithm\n" */
/* "                          (may result in higher or lower performance)\n\n" */
/* " -r, --report-ops         report numbers of group operations\n" */
/* "                          (only for performance evaluation)\n\n" */
"";

/* enum { */
/* 	DEC_NAIVE, */
/* 	DEC_FLATTEN, */
/* 	DEC_MERGE, */
/* } dec_strategy = DEC_MERGE;		 */

/* int   no_opt_sat = 0; */
/* int   report_ops = 0; */

/* int num_pairings = 0; */
/* int num_exps     = 0; */
/* int num_muls     = 0; */

		void
dec_args( int argc, char** argv )
{
		int i;

		for( i = 1; i < argc; i++ )
				if(      !strcmp(argv[i], "-h") || !strcmp(argv[i], "--help") )
				{
						printf("%s", dec_usage);
						exit(0);
				}
				else if( !strcmp(argv[i], "-v") || !strcmp(argv[i], "--version") )
				{
						printf(CPABE_VERSION, "-dec");
						exit(0);
				}
				else if( !strcmp(argv[i], "-k") || !strcmp(argv[i], "--keep-input-file") )
				{
						keep = 1;
				}
				else if( !strcmp(argv[i], "-o") || !strcmp(argv[i], "--output") )
				{
						if( ++i >= argc )
								die(dec_usage);
						else
								out_file = argv[i];
				}
				else if( !strcmp(argv[i], "-d") || !strcmp(argv[i], "--deterministic") )
				{
						pbc_random_set_deterministic(0);
				}
		/* 		else if( !strcmp(argv[i], "-s") || !strcmp(argv[i], "--no-opt-sat") ) */
		/* 		{ */
		/* 			no_opt_sat = 1; */
		/* 		} */
		/* 		else if( !strcmp(argv[i], "-n") || !strcmp(argv[i], "--naive-dec") ) */
		/* 		{ */
		/* 			dec_strategy = DEC_NAIVE; */
		/* 		} */
		/* 		else if( !strcmp(argv[i], "-f") || !strcmp(argv[i], "--flatten") ) */
		/* 		{ */
		/* 			dec_strategy = DEC_FLATTEN; */
		/* 		} */
		/* 		else if( !strcmp(argv[i], "-r") || !strcmp(argv[i], "--report-ops") ) */
		/* 		{ */
		/* 			report_ops = 1; */
		/* 		} */
				else if( !pub_file )
				{
						pub_file = argv[i];
				}
				else if( !prv_file )
				{
						prv_file = argv[i];
				}
				else if( !in_file )
				{
						in_file = argv[i];
				}
				else
						die(dec_usage);

		if( !pub_file || !prv_file || !in_file )
				die(dec_usage);

		if( !out_file )
		{
				if(  strlen(in_file) > 6 &&
								!strcmp(in_file + strlen(in_file) - 6, ".cpabe") )
						out_file = g_strndup(in_file, strlen(in_file) - 6);
				else
						out_file = strdup(in_file);
		}

		if( keep && !strcmp(in_file, out_file) )
				die("cannot keep input file when decrypting file in place (try -o)\n");
}

		void
dec( int argc, char** argv )
{
		bswabe_pub_t* pub;
		bswabe_prv_t* prv;
		int file_len;
		GByteArray* aes_buf;
		GByteArray* plt;
		GByteArray* cph_buf;
		bswabe_cph_t* cph;
		element_t m;

		out_file="result.txt";
		dec_args(argc, argv);


		struct  timeval    startTv,endTv;
		pub = bswabe_pub_unserialize(suck_file(pub_file), 1);
		prv = bswabe_prv_unserialize(pub, suck_file(prv_file), 1);

		read_cpabe_file(in_file, &cph_buf, &file_len, &aes_buf);
		
		gettimeofday(&startTv,NULL);
		cph = bswabe_cph_unserialize(pub, cph_buf, 1);
		if( !bswabe_dec(pub, prv, cph, m) )
				die("%s", bswabe_error());
		bswabe_cph_free(cph);

		plt = aes_128_cbc_decrypt(aes_buf, m);
		g_byte_array_set_size(plt, file_len);
		g_byte_array_free(aes_buf, 1);

		spit_file(out_file, plt, 1);

		gettimeofday(&endTv,NULL);
		double timer;
		timer=1000000.0 * (endTv.tv_sec-startTv.tv_sec)+ endTv.tv_usec-startTv.tv_usec;
		 printf("timer = %.3f ms\n",timer/1000);

		if( !keep )
				unlink(in_file);

		/* report ops if necessary */
		/* 	if( report_ops ) */
		/* 		printf("pairings:        %5d\n" */
		/* 					 "exponentiations: %5d\n" */
		/* 					 "multiplications: %5d\n", num_pairings, num_exps, num_muls); */

}

int main( int argc, char** argv )
{
		double TheTimes;
		dec(argc,argv);
		return 0;
}

