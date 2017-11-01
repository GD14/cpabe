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
		int file_len = plt->len;
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
int main(int argc,char *argv[]){
		struct timeval mystart,myend;
		gettimeofday(&mystart,NULL);
		if(argc>3)pbc_random_set_deterministic(0);
		if(argc!=2){
				printf("wrong\n");
				return -1;
		}

		//init redis connect
		redisContext *conn = redisConnect("127.0.0.1", 6379);
		if(NULL == conn) {
				fprintf(stderr, "redisConnect 127.0.0.1:6379 error!\n");
				exit(EXIT_FAILURE);
		}   
		if(conn->err) {
				fprintf(stderr, "redisConect error:%d\n", conn->err);
				redisFree(conn);
				exit(EXIT_FAILURE);
		}   
		

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

		}else //3.if not found,then call setup() and save into redis
		{

				setup();
				GByteArray* pub_buf=bswabe_pub_serialize(pub);
				redisCommand(conn, "set pub %b",pub_buf->data,pub_buf->len);	
				GByteArray* msk_buf=bswabe_msk_serialize(msk);
				redisCommand(conn, "set msk %b",msk_buf->data,msk_buf->len);	

				printf("not found pub and msk\n");
		}




		char* attr[]={	"sysadmin",
				"it_department",
				"office = 1431",
				"hire_date = 1509094170",
				NULL};
		char* kev_attr[]={"business_staff",
				"strategy_team",
				"executive_level = 7",
				"office = 2362",
				"hire_date = 1509094170",
				NULL};

		//if no find user's prv then
		//keygen for user,save prv in redis
		//1. get the byte[] of prv from redis
		bswabe_prv_t* kev_prv;
		redisReply* prvReply=redisCommand(conn,"get prv_123");
		//2.if found then unserialize prv
		if(prvReply&&prvReply->type==REDIS_REPLY_STRING){
			 GByteArray* tmp1;
             tmp1 = g_byte_array_new();
			 g_byte_array_set_size(tmp1,prvReply->len);
			 memcpy(tmp1->data,prvReply->str,prvReply->len);
			 kev_prv = bswabe_prv_unserialize(pub, tmp1, 1);
			printf("found kev_prv\n");
		}
		//3.if not found then call keygen(),gen prv,unserialize,  and save the byte[] into redis
		else{
			keygen(pub,msk,kev_attr,&kev_prv);
			GByteArray*prv_buf=bswabe_prv_serialize(kev_prv);
			redisCommand(conn, "set prv_123 %b",prv_buf->data,prv_buf->len);
			printf("not found kev_prv\n");
		}

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
			printf("found cph_buf and aes_buf\n");
		}
		//3. if not found,call enc(),use default plt to gen cph_buf,aes_buf
		else{		
			GByteArray* plt=suck_file(argv[1]);
			enc(pub,msk,plt,&cph_buf,&aes_buf);
			redisCommand(conn,"set cph_buf %b",cph_buf->data,cph_buf->len);
			redisCommand(conn,"set aes_buf %b",aes_buf->data,aes_buf->len);
			printf("not found cph_buf and aes_buf\n");
		}
	

		//dec 
		GByteArray* ans=0;
		dec(pub,kev_prv,aes_buf,cph_buf,&ans);
		gettimeofday(&myend,NULL);
		double timeuse= 1000000.0*(myend.tv_sec-mystart.tv_sec)+(myend.tv_usec-mystart.tv_usec);
		printf("the total time is :%.2fus\n",timeuse/1000);
		spit_file("ans.tmp",ans,1);
		redisFree(conn);
		return 0;
}
