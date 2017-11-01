#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <glib.h>
#include <pbc.h>
#include <sys/time.h>
#include <pbc_random.h>
#include <hiredis/hiredis.h>
#include "bswabe.h"
#include "common.h"
#include "policy_lang.h"


bswabe_pub_t * pub=0;
bswabe_msk_t * msk=0;;

char * ALL_ATTRS="(sysadmin and (hire_date < 946702800 or security_team)) or\
				  (business_staff and 2 of (executive_level >= 5, audit_group, strategy_team))";

char *policy=0;
GByteArray*	cph_buf;
GByteArray* aes_buf;
redisContext * conn=0;
char *usage="hello";
char * enc_msg=0;
size_t enc_msg_len;

char**attribute=0;
void parse_args(int argc,char ** argv){
		int i;
		for( i = 1; i < argc; i++ )
				if( !strcmp(argv[i], "-h") || !strcmp(argv[i], "--help") )
				{   
						printf("%s", usage);
						exit(0);
				}   
				else if( !strcmp(argv[i], "-e") || !strcmp(argv[i], "--encrypt") )
				{   

						if( ++i >= argc )
								die(usage);
						else{
								enc_msg=argv[i];
								enc_msg_len=strlen(enc_msg);
						}
				}
				else if(!strcmp(argv[i],"-a")|| !strcmp(argv[i],"--attribute") )
				{
						if(++i >=argc)
								die(usage);
						else{
								int j=0;
								attribute=argv+i;
								while(i<argc)
								{
										i+=1;
										j+=1;
								}

						}	
				}
				else if( !strcmp(argv[i], "-d") || !strcmp(argv[i], "--deterministic") )
				{   
						pbc_random_set_deterministic(0);
				}      

}


int setup(){
		bswabe_setup(&pub,&msk);
		return 0;
}

		gint 
comp_string( gconstpointer a, gconstpointer b)
{
		return strcmp(a,b);
}

int keygen(bswabe_pub_t* pub,bswabe_msk_t* msk,
				char*attribute[],bswabe_prv_t** prv){
		GSList* alist;
		GSList* ap;
		int n;
		int i=0;
		alist=0;	

		while(attribute[i]){
				parse_attribute(&alist,attribute[i++]);
		}

		char**attrs=0;
		alist = g_slist_sort(alist,comp_string);
		n = g_slist_length(alist);
		attrs = malloc((n+1)*sizeof(char*));
		i=0;
		for(ap = alist;ap;ap=ap->next)
				attrs[i++]=ap->data;	
		attrs[i]=0;
		(*prv)=bswabe_keygen(pub,msk,attrs);

		return 0;
}

int enc(bswabe_pub_t* pub,bswabe_msk_t*msk,GByteArray* plt,
				GByteArray**cph_buf, GByteArray** aes_buf){
		bswabe_cph_t* cph;
		element_t m;
		if(!policy) 
				policy=parse_policy_lang(ALL_ATTRS);
		cph = bswabe_enc(pub, m, policy);
		(*cph_buf) = bswabe_cph_serialize(cph);
		(*aes_buf) = aes_128_cbc_encrypt(plt, m);
		element_clear(m);
		return 0;
}

int dec(bswabe_pub_t* pub,bswabe_prv_t*prv,GByteArray*aes_buf,
				GByteArray*cph_buf,GByteArray**plt){
		element_t m ;
		bswabe_cph_t* cph;
		cph=bswabe_cph_unserialize(pub,cph_buf,1);
		if( !bswabe_dec(pub,prv,cph,m))
				die("%s\n", bswabe_error());
		(*plt)=aes_128_cbc_decrypt(aes_buf,m);
		return 0;
}

int init_hiredis(){
		//init redis connect,and check connect 
		conn = redisConnect("127.0.0.1", 6379);
		if(NULL == conn) {
				fprintf(stderr, "redisConnect 127.0.0.1:6379 error!\n");
				exit(EXIT_FAILURE);
		}   
		if(conn->err) {
				fprintf(stderr, "redisConect error:%d\n", conn->err);
				redisFree(conn);
				exit(EXIT_FAILURE);
		}   

		return 0;
}
int get_pub_and_msk()
{
		//if no find pub and msk from redis then
		//setup for cpabe,gen the msk and pub,save in redis 
		//1. get the byte[]ofmsk,the byte[]of pub from redis
		redisReply * pubReply=redisCommand(conn,"get pub");
		redisReply * mskReply=redisCommand(conn,"get msk");
		//2. if found then unserialize pub,msk
		if(pubReply&&(pubReply->type==REDIS_REPLY_STRING)
						&&mskReply&&(mskReply->type==REDIS_REPLY_STRING)){
				GByteArray* tmp1;
				tmp1 = g_byte_array_new();
				g_byte_array_set_size(tmp1,pubReply->len);
				memcpy(tmp1->data,pubReply->str,pubReply->len);
				pub=bswabe_pub_unserialize(tmp1,1);

				GByteArray* tmp2;
				tmp2 = g_byte_array_new();
				g_byte_array_set_size(tmp2,mskReply->len);
				memcpy(tmp2->data,mskReply->str,mskReply->len);
				msk=bswabe_msk_unserialize(pub,tmp2,1);
				printf("found pub and msk\n");
				freeReplyObject(pubReply);
				freeReplyObject(mskReply);

		}else //3.if not found,then call setup() and save into redis
		{

				setup();
				GByteArray* pub_buf=bswabe_pub_serialize(pub);
				redisReply* result=redisCommand(conn, "set pub %b",pub_buf->data,pub_buf->len);	
				if(result)
						freeReplyObject(result);

				GByteArray* msk_buf=bswabe_msk_serialize(msk);
				result=redisCommand(conn, "set msk %b",msk_buf->data,msk_buf->len);	
				if(result)
						freeReplyObject(result);
				printf("not found pub and msk\n");
		}
		return 0;

}

int get_encrypted_msg(){
		if(enc_msg){
				GByteArray* plt=g_byte_array_new();
				g_byte_array_set_size(plt,enc_msg_len);
				memcpy(plt->data,enc_msg,enc_msg_len);
				enc(pub,msk,plt,&cph_buf,&aes_buf);
				redisReply* result;
				result=redisCommand(conn,"set cph_buf %b",cph_buf->data,cph_buf->len);
				if(result)
						freeReplyObject(result);

				result=redisCommand(conn,"set aes_buf %b",aes_buf->data,aes_buf->len);
				if(result)
						freeReplyObject(result);
				printf("update encrypted messge\n");
		}else{
				//if no find plt from redis then
				//enc plt and save in redis.
				//1. get the byte[] of cph_buf,aes_buf from redis	
				//2. if found then just use
				redisReply* cphReply=redisCommand(conn,"get cph_buf");
				redisReply* aesReply=redisCommand(conn,"get aes_buf");
				if(cphReply&&cphReply->type==REDIS_REPLY_STRING
								&&aesReply&&aesReply->type==REDIS_REPLY_STRING){
						cph_buf= g_byte_array_new();
						g_byte_array_set_size(cph_buf,cphReply->len);
						memcpy(cph_buf->data,cphReply->str,cphReply->len);

						aes_buf=g_byte_array_new();
						g_byte_array_set_size(aes_buf,aesReply->len);
						memcpy(aes_buf->data,aesReply->str,aesReply->len);

						freeReplyObject(cphReply);
						freeReplyObject(aesReply);
						printf("found cph_buf and aes_buf\n");
				}
		}
		return 0;
}

bswabe_prv_t* get_prv(char **m_attrbutes){
		//if no find user's prv then
		//keygen for user,save prv in redis
		//1. get the byte[] of prv from redis
		bswabe_prv_t* tmp_prv;
		redisReply* prvReply=redisCommand(conn,"get prv_123");
		//2.if found then unserialize prv
		if(prvReply&&prvReply->type==REDIS_REPLY_STRING){
				GByteArray* tmp1;
				tmp1 = g_byte_array_new();
				g_byte_array_set_size(tmp1,prvReply->len);
				memcpy(tmp1->data,prvReply->str,prvReply->len);
				tmp_prv = bswabe_prv_unserialize(pub, tmp1, 1);
				freeReplyObject(prvReply);
				printf("found prv\n");
		}
		//3.if not found then call keygen(),gen prv,unserialize,  and save the byte[] into redis
		else{
				keygen(pub,msk,m_attrbutes,&tmp_prv);
				GByteArray*prv_buf=bswabe_prv_serialize(tmp_prv);
				redisReply* result=redisCommand(conn, "set prv_123 %b",prv_buf->data,prv_buf->len);
				if(result)
						freeReplyObject(result);
				printf("not found prv\n");
		}

		return tmp_prv;

}


int main(int argc,char *argv[]){

		parse_args(argc, argv);
		//		struct timeval mystart,myend;
		//		gettimeofday(&mystart,NULL);

		init_hiredis();

		get_pub_and_msk();

		get_encrypted_msg();

		/*
		int i=0;
		while(attribute&&attribute[i]){
				printf("%s\n",attribute[i++]);	
		}		
			char* kev_attr[]={"business_staff",
				"strategy_team",
				"executive_level = 7",
				"office = 2362",
				"hire_date = 1509094170",
				NULL};
		*/

		bswabe_prv_t* my_prv=get_prv(attribute);


		//dec 
		GByteArray* ans=0;
		dec(pub,my_prv,aes_buf,cph_buf,&ans);
		//		gettimeofday(&myend,NULL);
		//		double timeuse= 1000000.0*(myend.tv_sec-mystart.tv_sec)+(myend.tv_usec-mystart.tv_usec);
		//		printf("the total time is :%.2fms\n",timeuse/1000);


		spit_file("ans.tmp",ans,1);
		redisFree(conn);
		return 0;
}
