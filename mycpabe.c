#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <glib.h>
#include <pbc.h>
#include <sys/time.h>
#include <pbc_random.h>

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
		write_cpabe_file("v.txt", *cph_buf, file_len, *aes_buf);
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
		struct timeval startTv,endTv;
		double timer;

		if(argc>3)pbc_random_set_deterministic(0);
		if(argc!=2){
				printf("wrong\n");
				return -1;
		}
		gettimeofday(&startTv,NULL);
		setup();
		gettimeofday(&endTv,NULL);
		timer=1000000.0 * (endTv.tv_sec-startTv.tv_sec)+ endTv.tv_usec-startTv.tv_usec;
		printf("setup_time=%.3fms, ",timer/1000);


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

		bswabe_prv_t* kev_prv;
		gettimeofday(&startTv,NULL);
		keygen(pub,msk,kev_attr,&kev_prv);
		gettimeofday(&endTv,NULL);
		timer=1000000.0 * (endTv.tv_sec-startTv.tv_sec)+ endTv.tv_usec-startTv.tv_usec;
		printf("keygen_time=%.3fms, ",timer/1000);



		
		GByteArray* plt=suck_file(argv[1]);
		gettimeofday(&startTv,NULL);
		enc(pub,msk,plt,&cph_buf,&aes_buf);
		GByteArray* ans=0;
		gettimeofday(&endTv,NULL);
		timer=1000000.0 * (endTv.tv_sec-startTv.tv_sec)+ endTv.tv_usec-startTv.tv_usec;
		printf("enc_time=%.3fms, ",timer/1000);

		gettimeofday(&startTv,NULL);
		dec(pub,kev_prv,aes_buf,cph_buf,&ans);
		gettimeofday(&endTv,NULL);
		timer=1000000.0 * (endTv.tv_sec-startTv.tv_sec)+ endTv.tv_usec-startTv.tv_usec;
		printf("dec_time=%.3fms\n",timer/1000);
		spit_file("ans.tmp",ans,1);
		return 0;
}

