/* R47 independent bounded test peer. Public OpenSSL APIs only; no custom crypto. */
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static unsigned u16(const unsigned char *p) { return ((unsigned)p[0]<<8)|p[1]; }
static unsigned u24(const unsigned char *p) { return ((unsigned)p[0]<<16)|((unsigned)p[1]<<8)|p[2]; }
static void digest(const unsigned char *p, size_t n) {
  unsigned char d[EVP_MAX_MD_SIZE]; unsigned len=0;
  if (!EVP_Digest(p,n,d,&len,EVP_sha256(),NULL)) { printf("null"); return; }
  putchar('"'); for(unsigned i=0;i<len;i++) printf("%02x",d[i]); putchar('"');
}
static void schemes(const unsigned char *p, size_t n) {
  putchar('['); for(size_t i=0;i+1<n;i+=2) printf("%s%u",i?",":"",u16(p+i)); putchar(']');
}
static void names(const unsigned char *p, size_t n) {
  int first=1; putchar('[');
  while(n>=2) { unsigned len=u16(p); p+=2;n-=2;if(len>n)break;
    if(!first)putchar(',');digest(p,len);first=0;p+=len;n-=len; }
  putchar(']');
}
static void certificate(const unsigned char *p,size_t n,int tls13) {
  if(tls13) {if(n<1||n<1+(size_t)p[0])return;size_t k=1+p[0];p+=k;n-=k;}
  if(n<3)return;unsigned total=u24(p);p+=3;n-=3;if(total!=n)return;
  printf("{\"event\":\"wire_client_chain\",\"sha256\":[");int first=1;
  while(n>=3) {unsigned len=u24(p);p+=3;n-=3;if(len>n)break;
    if(!first)putchar(',');digest(p,len);first=0;p+=len;n-=len;
    if(tls13) {if(n<2)break;unsigned ext=u16(p);p+=2;n-=2;if(ext>n)break;p+=ext;n-=ext;}
  }
  printf("]}\n");fflush(stdout);
}
static void request(const unsigned char *p,size_t n,int tls13) {
  printf("{\"event\":\"certificate_request\",\"certificate_types\":[");
  if(!tls13) {
    if(n<1||n<1+(size_t)p[0])goto invalid;
    unsigned len=p[0];p++;n--;for(unsigned i=0;i<len;i++)printf("%s%u",i?",":"",p[i]);p+=len;n-=len;
    printf("],\"signature_schemes\":");
    if(n<2)goto invalid;len=u16(p);p+=2;n-=2;if(len>n)goto invalid;schemes(p,len);p+=len;n-=len;
    printf(",\"ca_name_sha256\":");
    if(n<2)goto invalid;len=u16(p);p+=2;n-=2;if(len>n)goto invalid;names(p,len);
  } else {
    printf("],\"signature_schemes\":");
    if(n<1||n<1+(size_t)p[0])goto invalid;size_t k=1+p[0];p+=k;n-=k;
    if(n<2)goto invalid;unsigned len=u16(p);p+=2;n-=2;if(len!=n)goto invalid;
    const unsigned char *sig=NULL,*ca=NULL;size_t sn=0,cn=0;
    while(n>=4){unsigned type=u16(p),size=u16(p+2);p+=4;n-=4;if(size>n)goto invalid;
      if(type==13&&size>=2&&u16(p)==size-2){sig=p+2;sn=size-2;}
      if(type==47&&size>=2&&u16(p)==size-2){ca=p+2;cn=size-2;}
      p+=size;n-=size;
    }
    schemes(sig,sn);printf(",\"ca_name_sha256\":");names(ca,cn);
  }
  printf("}\n");fflush(stdout);return;
invalid: printf("],\"parse_error\":true}\n");fflush(stdout);
}
static void message(int write_p,int version,int content,const void *buffer,size_t size,SSL *ssl,void *arg) {
  (void)version;(void)arg;
  if(content!=SSL3_RT_HANDSHAKE||size<4)return;
  const unsigned char *p=buffer;unsigned len=u24(p+1);if(len!=size-4)return;
  int tls13=SSL_version(ssl)==TLS1_3_VERSION;
  if(!write_p&&p[0]==SSL3_MT_CLIENT_HELLO&&size>=38){
    printf("{\"event\":\"client_hello_random\",\"sha256\":");digest(p+6,32);printf("}\n");fflush(stdout);}
  if(write_p&&p[0]==SSL3_MT_CERTIFICATE_REQUEST)request(p+4,size-4,tls13);
  if(!write_p&&p[0]==SSL3_MT_CERTIFICATE)certificate(p+4,size-4,tls13);
  if(!write_p&&p[0]==SSL3_MT_CERTIFICATE_VERIFY&&size>=6){
    printf("{\"event\":\"client_cv\",\"scheme\":%u}\n",u16(p+4));fflush(stdout);}
}
static void verified(SSL *ssl) {
  X509 *leaf=SSL_get1_peer_certificate(ssl);
  printf("{\"event\":\"authenticated\",\"version\":\"%s\",\"client_leaf_sha256\":",SSL_get_version(ssl));
  if(leaf){unsigned char *der=NULL;int len=i2d_X509(leaf,&der);if(len>0)digest(der,len);else printf("null");OPENSSL_free(der);X509_free(leaf);}else printf("null");
  printf(",\"verified_chain_sha256\":[");STACK_OF(X509) *chain=SSL_get0_verified_chain(ssl);
  for(int i=0;chain&&i<sk_X509_num(chain);i++){unsigned char *der=NULL;int len=i2d_X509(sk_X509_value(chain,i),&der);
    if(i)putchar(',');if(len>0)digest(der,len);else printf("null");OPENSSL_free(der);}
  printf("],\"verify_result\":%ld,\"ems\":%ld,\"secure_renegotiation\":%ld}\n",
    SSL_get_verify_result(ssl),SSL_get_extms_support(ssl),SSL_get_secure_renegotiation_support(ssl));fflush(stdout);
}
int main(int argc,char **argv) {
  /* cert,key,verify trust,advertised hints|none,version,required|optional|none,schemes,types */
  if(argc!=11){fprintf(stderr,"peer argument count\n");return 2;}
  setvbuf(stdout,NULL,_IOLBF,0);signal(SIGPIPE,SIG_IGN);alarm(12);
  SSL_CTX *ctx=SSL_CTX_new(TLS_server_method());if(!ctx)return 3;
  int v=strcmp(argv[5],"tls12")==0?TLS1_2_VERSION:TLS1_3_VERSION;
  if(!SSL_CTX_set_min_proto_version(ctx,v)||!SSL_CTX_set_max_proto_version(ctx,v))return 4;
  if(!SSL_CTX_use_certificate_chain_file(ctx,argv[1])||!SSL_CTX_use_PrivateKey_file(ctx,argv[2],SSL_FILETYPE_PEM)||!SSL_CTX_check_private_key(ctx))return 5;
  if(!SSL_CTX_load_verify_locations(ctx,argv[3],NULL))return 6;
  SSL_CTX_set_verify_depth(ctx,6);
  int verify=strcmp(argv[6],"none")==0?SSL_VERIFY_NONE:SSL_VERIFY_PEER;
  if(strcmp(argv[6],"required")==0)verify|=SSL_VERIFY_FAIL_IF_NO_PEER_CERT;
  SSL_CTX_set_verify(ctx,verify,NULL);
  if(strcmp(argv[4],"none")!=0){STACK_OF(X509_NAME) *ca=SSL_load_client_CA_file(argv[4]);if(!ca)return 7;SSL_CTX_set_client_CA_list(ctx,ca);}
  if(!SSL_CTX_set_cipher_list(ctx,"ECDHE-RSA-AES128-GCM-SHA256"))return 8;
  if(!SSL_CTX_set_ciphersuites(ctx,"TLS_AES_128_GCM_SHA256"))return 9;
  if(!SSL_CTX_set1_client_sigalgs_list(ctx,argv[7]))return 10;
  if(!SSL_CTX_set1_groups_list(ctx,argv[9]))return 10;
  if(v==TLS1_2_VERSION&&strcmp(argv[8],"default")!=0){
    unsigned char types[2];size_t n=0;
    if(strstr(argv[8],"rsa"))types[n++]=SSL3_CT_RSA_SIGN;
    if(strstr(argv[8],"ec"))types[n++]=TLS_CT_ECDSA_SIGN;
    if(!SSL_CTX_set1_client_certificate_types(ctx,types,n))return 11;
  }
  SSL_CTX_set_options(ctx,SSL_OP_NO_TICKET|SSL_OP_NO_COMPRESSION|SSL_OP_NO_RENEGOTIATION);
  SSL_CTX_set_msg_callback(ctx,message);
  int listener=socket(AF_INET,SOCK_STREAM,0);if(listener<0)return 12;
  struct timeval tv={5,0};setsockopt(listener,SOL_SOCKET,SO_RCVTIMEO,&tv,sizeof(tv));
  struct sockaddr_in a={0};a.sin_family=AF_INET;a.sin_addr.s_addr=htonl(INADDR_LOOPBACK);a.sin_port=0;
  if(bind(listener,(struct sockaddr*)&a,sizeof(a))||listen(listener,1))return 13;
  socklen_t alen=sizeof(a);getsockname(listener,(struct sockaddr*)&a,&alen);
  printf("{\"event\":\"ready\",\"port\":%u,\"openssl\":\"%s\"}\n",ntohs(a.sin_port),OpenSSL_version(OPENSSL_VERSION));
  int fd=accept(listener,NULL,NULL);close(listener);if(fd<0){printf("{\"event\":\"no_accept\"}\n");SSL_CTX_free(ctx);return 0;}
  printf("{\"event\":\"accepted\"}\n");
  setsockopt(fd,SOL_SOCKET,SO_RCVTIMEO,&tv,sizeof(tv));setsockopt(fd,SOL_SOCKET,SO_SNDTIMEO,&tv,sizeof(tv));
  SSL *ssl=SSL_new(ctx);SSL_set_fd(ssl,fd);int result=SSL_accept(ssl);
  if(result!=1){int ssl_error=SSL_get_error(ssl,result);unsigned long last=ERR_peek_last_error();printf("{\"event\":\"handshake_error\",\"ssl_error\":%d,\"reason_code\":%d,\"verify_result\":%ld}\n",ssl_error,ERR_GET_REASON(last),SSL_get_verify_result(ssl));goto cleanup;}
  verified(ssl);
  unsigned char buf[16384];size_t n=0;
  while(n<sizeof(buf)) {int count=SSL_read(ssl,buf+n,sizeof(buf)-n);if(count<=0)break;n+=count;
    if(n>=4&&memmem(buf,n,"\r\n\r\n",4))break;}
  const char *expected="GET /r47 HTTP/1.1\r\nHost: r47.server\r\nConnection: close\r\n\r\n";
  int request_ok=0,written_ok=0;
  if(strcmp(argv[10],"http")==0) {
    request_ok=n==strlen(expected)&&memcmp(buf,expected,n)==0;
    if(request_ok) {
      const char *response="HTTP/1.1 200 OK\r\nContent-Length: 11\r\nConnection: close\r\n\r\nr47-peer-ok";
      written_ok=SSL_write(ssl,response,strlen(response))==(int)strlen(response);
    }
  } else if(n<sizeof(buf)) {
    buf[n]=0;
    request_ok=strncmp((char*)buf,"GET /r47 HTTP/1.1\r\n",19)==0;
    if(strcmp(argv[10],"sse")==0) {
      request_ok=request_ok&&strcasestr((char*)buf,"Accept: text/event-stream\r\n")!=NULL;
      if(request_ok) {
        const char *body="id: r47\ndata: r47-sse-ok\n\n";
        char response[512];int size=snprintf(response,sizeof(response),"HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nContent-Length: %zu\r\nConnection: close\r\n\r\n%s",strlen(body),body);
        written_ok=SSL_write(ssl,response,size)==size;
      }
    } else if(strcmp(argv[10],"wss")==0) {
      char *header=strcasestr((char*)buf,"Sec-WebSocket-Key: ");
      request_ok=request_ok&&header&&strcasestr((char*)buf,"Upgrade: websocket\r\n");
      if(request_ok) {
        header+=19;char *end=strstr(header,"\r\n");
        if(!end||end-header!=24)request_ok=0;
        else {
          char input[61],accept[29],response[512];unsigned char hash[EVP_MAX_MD_SIZE];unsigned len=0;
          memcpy(input,header,24);memcpy(input+24,"258EAFA5-E914-47DA-95CA-C5AB0DC85B11",36);
          if(!EVP_Digest(input,60,hash,&len,EVP_sha1(),NULL)||len!=20)goto cleanup;
          EVP_EncodeBlock((unsigned char*)accept,hash,len);
          int size=snprintf(response,sizeof(response),"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: %s\r\n\r\n",accept);
          written_ok=SSL_write(ssl,response,size)==size;
          const unsigned char frame[]={0x81,10,'r','4','7','-','w','s','s','-','o','k',0x88,2,3,0xe8};
          written_ok=written_ok&&SSL_write(ssl,frame,sizeof(frame))==(int)sizeof(frame);
        }
      }
    }
  }
  printf("{\"event\":\"http\",\"application\":\"%s\",\"request_exact\":%s,\"response_written\":%s}\n",argv[10],request_ok?"true":"false",written_ok?"true":"false");
  SSL_shutdown(ssl);
cleanup:
  SSL_free(ssl);close(fd);SSL_CTX_free(ctx);return 0;
}
