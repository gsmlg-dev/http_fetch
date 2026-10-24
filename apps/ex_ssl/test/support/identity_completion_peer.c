/* Independent identity/completion TLS witness. Public OpenSSL APIs; no custom crypto. */
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
#include <poll.h>
#include <errno.h>

static int gate_client_hello = 0;
static int gate_used = 0;
static int gate_rejection = 0;
static int stop_received = 0;

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
  if(content==SSL3_RT_ALERT&&size==2) {
    const unsigned char *alert=buffer;
    printf("{\"event\":\"tls_alert\",\"sent\":%s,\"level\":%u,\"description\":%u}\n",write_p?"true":"false",alert[0],alert[1]);
    fflush(stdout);return;
  }
  if(content!=SSL3_RT_HANDSHAKE||size<4)return;
  const unsigned char *p=buffer;unsigned len=u24(p+1);if(len!=size-4)return;
  int tls13=SSL_version(ssl)==TLS1_3_VERSION;
  if(!write_p&&p[0]==SSL3_MT_CLIENT_HELLO&&size>=38){
    printf("{\"event\":\"client_hello_random\",\"sha256\":");digest(p+6,32);printf("}\n");fflush(stdout);
    if(gate_client_hello && !gate_used) {
      char command[32]; gate_used=1;
      printf("{\"event\":\"client_hello_gate\"}\n");fflush(stdout);
      if(!fgets(command,sizeof(command),stdin)||strcmp(command,"go\n")!=0) _exit(0);
    }
  }
  if(write_p&&p[0]==SSL3_MT_CERTIFICATE_REQUEST)request(p+4,size-4,tls13);
  if(!write_p&&p[0]==SSL3_MT_CERTIFICATE) {
    certificate(p+4,size-4,tls13);
    /* Pause before OpenSSL validates the received empty certificate and emits
       its fatal alert, so the client can install a real pending read. */
    if(gate_rejection) {
      char command[32];
      printf("{\"event\":\"rejection_gate\"}\n");fflush(stdout);
      if(!fgets(command,sizeof(command),stdin)||strcmp(command,"reject\n")!=0)_exit(0);
    }
  }
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
  const unsigned char *alpn=NULL; unsigned size=0; SSL_get0_alpn_selected(ssl,&alpn,&size);
  const char *sni=SSL_get_servername(ssl,TLSEXT_NAMETYPE_host_name);
  printf("{\"event\":\"negotiated\",\"alpn\":\"%.*s\",\"sni\":\"%s\"}\n",(int)size,alpn?alpn:(const unsigned char *)"",sni?sni:"");fflush(stdout);
}

static const unsigned char *selected_protocol;
static unsigned selected_protocol_size;
static int select_alpn(SSL *ssl,const unsigned char **out,unsigned char *outlen,
                       const unsigned char *in,unsigned inlen,void *arg) {
  (void)ssl;(void)arg;
  unsigned at=0;
  while(at<inlen) {
    unsigned size=in[at++];
    if(size>inlen-at)return SSL_TLSEXT_ERR_ALERT_FATAL;
    if(size==selected_protocol_size&&!memcmp(in+at,selected_protocol,size)) {
      *out=in+at;*outlen=(unsigned char)size;return SSL_TLSEXT_ERR_OK;
    }
    at+=size;
  }
  return SSL_TLSEXT_ERR_ALERT_FATAL;
}
static int application_socket(unsigned port) {
  int fd=socket(AF_INET,SOCK_STREAM,0);
  struct sockaddr_in address={0};
  address.sin_family=AF_INET;address.sin_addr.s_addr=htonl(INADDR_LOOPBACK);
  address.sin_port=htons((unsigned short)port);
  if(fd<0||connect(fd,(struct sockaddr*)&address,sizeof(address))) {
    if(fd>=0)close(fd);
    return -1;
  }
  return fd;
}
static int relay(SSL *ssl,int fd,int app) {
  unsigned char buffer[16384];
  struct pollfd inputs[3]={{fd,POLLIN,0},{app,POLLIN,0},{STDIN_FILENO,POLLIN,0}};
  for(;;) {
    int ready=poll(inputs,3,10000);
    if(ready<=0)return 20;
    if(inputs[2].revents&(POLLIN|POLLHUP)) {stop_received=1;return 0;}
    if(inputs[0].revents&(POLLIN|POLLHUP)||SSL_pending(ssl)) {
      int size=SSL_read(ssl,buffer,sizeof(buffer));
      if(size<=0) {shutdown(app,SHUT_WR);return 0;}
      int at=0;
      while(at<size) {
        ssize_t sent=send(app,buffer+at,(size_t)(size-at),0);
        if(sent<=0)return 21;
        at+=(int)sent;
      }
    }
    if(inputs[1].revents&(POLLIN|POLLHUP)) {
      ssize_t size=recv(app,buffer,sizeof(buffer),0);
      if(size<=0)return 0;
      int at=0;
      while(at<size) {
        int sent=SSL_write(ssl,buffer+at,(int)size-at);
        if(sent<=0)return 22;
        at+=sent;
      }
    }
  }
}
int main(int argc,char **argv) {
  /* cert,key,clienttrust,hint,version,auth,schemes,ALPN,application-port,gate */
  if(argc!=11)return 2;
  setvbuf(stdout,NULL,_IOLBF,0);signal(SIGPIPE,SIG_IGN);alarm(25);
  gate_client_hello=strcmp(argv[10],"gate")==0;
  gate_rejection=strcmp(argv[10],"reject")==0;
  selected_protocol=(const unsigned char*)argv[8];
  selected_protocol_size=(unsigned)strlen(argv[8]);
  SSL_CTX *ctx=SSL_CTX_new(TLS_server_method());
  if(!ctx)return 3;
  int version=!strcmp(argv[5],"tls12")?TLS1_2_VERSION:TLS1_3_VERSION;
  if(!SSL_CTX_set_min_proto_version(ctx,version)||!SSL_CTX_set_max_proto_version(ctx,version))return 4;
  if(!SSL_CTX_use_certificate_chain_file(ctx,argv[1])||
     !SSL_CTX_use_PrivateKey_file(ctx,argv[2],SSL_FILETYPE_PEM)||
     !SSL_CTX_check_private_key(ctx))return 5;
  if(!SSL_CTX_load_verify_locations(ctx,argv[3],NULL))return 6;
  SSL_CTX_set_verify_depth(ctx,6);
  int verify=!strcmp(argv[6],"none")?SSL_VERIFY_NONE:SSL_VERIFY_PEER;
  if(!strcmp(argv[6],"required"))verify|=SSL_VERIFY_FAIL_IF_NO_PEER_CERT;
  SSL_CTX_set_verify(ctx,verify,NULL);
  if(strcmp(argv[4],"none")) {
    STACK_OF(X509_NAME) *ca=SSL_load_client_CA_file(argv[4]);
    if(!ca)return 7;
    SSL_CTX_set_client_CA_list(ctx,ca);
  }
  if(!SSL_CTX_set_cipher_list(ctx,"ECDHE-RSA-AES128-GCM-SHA256")||
     !SSL_CTX_set_ciphersuites(ctx,"TLS_AES_128_GCM_SHA256")||
     !SSL_CTX_set1_client_sigalgs_list(ctx,argv[7]))return 8;
  SSL_CTX_set_options(ctx,SSL_OP_NO_TICKET|SSL_OP_NO_COMPRESSION|SSL_OP_NO_RENEGOTIATION);
  SSL_CTX_set_alpn_select_cb(ctx,select_alpn,NULL);SSL_CTX_set_msg_callback(ctx,message);
  int listener=socket(AF_INET,SOCK_STREAM,0);
  if(listener<0)return 9;
  struct sockaddr_in address={0};address.sin_family=AF_INET;
  address.sin_addr.s_addr=htonl(INADDR_LOOPBACK);
  if(bind(listener,(struct sockaddr*)&address,sizeof(address))||listen(listener,2))return 10;
  socklen_t length=sizeof(address);getsockname(listener,(struct sockaddr*)&address,&length);
  printf("{\"event\":\"ready\",\"port\":%u}\n",ntohs(address.sin_port));
  struct pollfd waiting[2]={{listener,POLLIN,0},{STDIN_FILENO,POLLIN,0}};
  if(poll(waiting,2,15000)<=0)return 11;
  if(waiting[1].revents) {close(listener);SSL_CTX_free(ctx);return 0;}
  int fd=accept(listener,NULL,NULL);close(listener);
  if(fd<0)return 12;
  struct timeval timeout={12,0};
  setsockopt(fd,SOL_SOCKET,SO_RCVTIMEO,&timeout,sizeof(timeout));
  setsockopt(fd,SOL_SOCKET,SO_SNDTIMEO,&timeout,sizeof(timeout));
  printf("{\"event\":\"accepted\"}\n");
  SSL *ssl=SSL_new(ctx);SSL_set_fd(ssl,fd);
  int status=0,accepted=SSL_accept(ssl);
  if(accepted!=1) {
    printf("{\"event\":\"handshake_error\",\"ssl_error\":%d,\"verify_result\":%ld}\n",SSL_get_error(ssl,accepted),SSL_get_verify_result(ssl));
    unsigned char probe;
    ssize_t observed=recv(fd,&probe,1,MSG_PEEK|MSG_DONTWAIT);
    if(observed==0)printf("{\"event\":\"transport_terminal\",\"observed\":\"eof\"}\n");
    else if(observed<0&&errno==ECONNRESET)printf("{\"event\":\"transport_terminal\",\"observed\":\"reset\"}\n");
    /* Preserve the fatal alert before close: unread client Finished bytes must
       not turn an authenticated rejection into an operating-system reset. */
    shutdown(fd,SHUT_WR);
    for(int attempt=0;attempt<10;attempt++) {
      struct pollfd incoming={fd,POLLIN,0};
      if(poll(&incoming,1,100)<=0)continue;
      unsigned char discarded[16384];
      if(recv(fd,discarded,sizeof(discarded),MSG_DONTWAIT)<=0)break;
    }
  } else {
    verified(ssl);
    int app=application_socket((unsigned)strtoul(argv[9],NULL,10));
    if(app<0)status=13;
    else {status=relay(ssl,fd,app);close(app);}
    SSL_shutdown(ssl);
  }
  SSL_free(ssl);close(fd);SSL_CTX_free(ctx);
  printf("{\"event\":\"tls_closed\",\"status\":%d}\n",status);
  /* Explicit process-exit barrier; never used as transport EOF evidence. */
  if(!stop_received) {
    struct pollfd control={STDIN_FILENO,POLLIN,0};
    if(poll(&control,1,5000)>0) {char command[32];(void)fgets(command,sizeof(command),stdin);}
  }
  return status;
}
