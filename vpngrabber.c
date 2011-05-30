#include <stdio.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netdb.h>
#include <string.h>
#include <glib.h>
#define PORT 80
#define HEADER_MAX_NR 16
#define HEADER_MAX_LEN 512
#define RESPON_BUF_SIZE 10240
void email_main();
void email_login(int fd, char *username, char *password);
char *email_get_verify_url(int fd);
struct _find_from_header_result
{
        int items;
        int items_search;
        char datas[HEADER_MAX_NR][HEADER_MAX_LEN];
}find_from_header_result;
void get_auth();
void conv(char *in, char *out);
void do_post(int fd, char *uri, char *host, char *postbuf, char *req, char *ref, char *cookie);
char username[16] = {"goodnight"};
char password[16] = {"goodnight"};
char email[64] = {"sunuslikeme%2Bsleep%40gmail.com"}; /* @ == %40 */
char *post1 = "utf8=%E2%9C%93&authenticity_token=";

/* packet to registration */
char *post2_0 = "&user%5Busername%5D=";
char *post2_1 = "&user%5Bpassword%5D=";
char *post2_2 = "&user%5Bpassword_confirmation%5D=";
char *post2_3 = "&commit=%E6%B3%A8%E5%86%8C";

/* packet to mail verify */
char *post3_0 = "&user%5Bemail%5D=";
char *post3_1 = "&commit=%E5%8F%91%E9%80%81%E9%AA%8C%E8%AF%81%E9%82%AE%E4%BB%B6";


char *post_login = "&session%5Busername%5D=iwantp0st&session%5Bpassword%5D=iwantp0st&commit=%E7%99%BB%E9%99%86";
char *addr = "www.asvpn.com";
char cookie_buf[2048]; 
char request[2048];
char *find_auth;
char auth[64];
char auth_conv[64];
char post_t[256];
/* return the copy size */
struct respond_t
{
        char buf[RESPON_BUF_SIZE];
        char *header;
        char *body;     /* header and body are point to somewhere in buf;*/
}respond;

/* return the copy size */
/* add '\0' in the end of string */
int linecpy(char *dst, char *src) 
{
        char *d = dst;
        char *s = src;
        int size;
        for(size = 0 ; (!((*s == '\r') && (*(s+1) == '\n'))) && (*s != '\0') && (*s != ';'); size++)
        {
                *d++ = *s++;
        }
        if(*s == '\0')
        {
                *d = '\0';
                return size;
        }
        *d++ = '\r';
        *d++ = '\n';
        *d = '\0';
        return size + 2;
}
/* return the recieved bytes */
int http_recv(int fd, char *buf, int buf_size)
{
        int recv_size;
        int len;
        char *copy;
        int is_header = TRUE;
        memset(buf, 0, buf_size);
        for(recv_size = 0 ; (recv_size = recv(fd, buf, buf_size, 0)) > 0 ; )
        {
                if((is_header == TRUE) && ((respond.body = strstr(buf, "\r\n\r\n")) != NULL))
                {
                        respond.header = ((char *)&respond.buf);
                        *(respond.body + 4) = '\0';
                        respond.body += 5;
                        is_header = FALSE;
                        printf("get header :\n%s\n",respond.header);
                }
                buf += recv_size;
        }
        return recv_size;
}

/* find must be something like this "find: " ,don't forget the last space*/
/* return the number of find */
/* it ends with '/0', that means in do_post, u have to put '\r\n' */
int find_from_header(char *header, char *find, char *result, int result_size)
{
        char *find_next = header;
        int skip = strlen(find);
        int find_len;
        int find_nr = 0;
        int i = 0;
        memset(result, 0, result_size);
        while(1)
        {
                if((find_next = strstr(find_next, find)) != NULL)
                {
                        find_next += skip;
                        find_len = linecpy((char *)&(find_from_header_result.datas[find_from_header_result.items]), find_next);
                        i = sprintf(result,"%s%s",result,(char *)&(find_from_header_result.datas[find_from_header_result.items]));
                        result[i - 2] = ';';
                        result[i - 1] = '\0';
                        printf("found a %s #%d\n%s", find, find_nr, (char *)(find_from_header_result.datas)[find_from_header_result.items]);
                        find_next += find_len;
                        find_nr++;
                        find_from_header_result.items++;
                }
                else
                        break;
        }
        if(i)
                result[i - 2] = '\0';
        return find_nr;
}

void do_get(int fd, char *reqbuff, char *uri, char *host, char *cookie)
{
        int next_post = 0;
        char *rb = reqbuff;
        char *find_auth = NULL;
        char *find_cookie = NULL;
        int send_size,recv_size;
        int disable_content = 0;
        next_post = sprintf(rb, "GET ");
        next_post = sprintf(rb += next_post, "%s ",uri);         
        next_post = sprintf(rb += next_post, "HTTP/1.1\r\n");
        next_post = sprintf(rb += next_post, "Host: %s\r\n",host);
        next_post = sprintf(rb += next_post, "Content-Type: application/x-www-form-urlencoded\r\n");
#if 0
        next_post = sprintf(rb += next_post, "User-Agent: Mozilla/5.0 (X11; Linux i686; rv:2.0.1) Gecko/20100101 Firefox/4.0.1\r\n");
        next_post = sprintf(rb += next_post, "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\n");
        next_post = sprintf(rb += next_post, "Accept-Language: en-us,en;q=0.5\r\n");
        next_post = sprintf(rb += next_post, "Accept-Encoding: gzip, deflate\r\n");
        next_post = sprintf(rb += next_post, "Accept-Charset: ISO-8859-1,utf-8;q=0.7,*;q=0.7\r\n");
        next_post = sprintf(rb += next_post, "Keep Alive: 115\r\n");
        next_post = sprintf(rb += next_post, "Connection: keep-alive\r\n");
        next_post = sprintf(rb += next_post, "If-None-Match: \"2f4583ff45929dafdc2ef67ce7a2046a\"\r\n");
        /* unnecessarily i think */
#endif
        next_post = sprintf(rb += next_post, "\r\n");
        printf("sending request : size = %d\n", send_size = strlen(reqbuff));
        printf("%s\n\n",reqbuff);
        recv_size = 0;
        send_size = send(fd, reqbuff, send_size, 0);
        printf("%d bytes sent\n",send_size);
        http_recv(fd, respond.buf, RESPON_BUF_SIZE);
}
void do_post(int fd, char *uri, char *host, char *postbuf, char *req, char *ref ,char *cookie)
{
        int send_size;
        int recv_size ;
        int next_post = 0;
        char *pb = postbuf;
        next_post = sprintf(pb, "POST ");
        next_post = sprintf(pb += next_post, "%s ",uri );
        next_post = sprintf(pb += next_post, "HTTP/1.1\r\n");
        next_post = sprintf(pb += next_post, "Host: %s\r\n",host);
//*        next_post = sprintf(pb += next_post, "User-Agent: Mozilla/5.0 (X11; Linux i686; rv:2.0.1) Gecko/20100101 Firefox/4.0.1\r\n");
//*        next_post = sprintf(pb += next_post, "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\n");
//*        next_post = sprintf(pb += next_post, "Accept-Language: en-us,en;q=0.5\r\n");
//*        next_post = sprintf(pb += next_post, "Accept-Encoding: gzip, deflate\r\n");
//*        next_post = sprintf(pb += next_post, "Accept-Charset: ISO-8859-1,utf-8;q=0.7,*;q=0.7\r\n");
        next_post = sprintf(pb += next_post, "Keep-Alive: 115\r\n");
        next_post = sprintf(pb += next_post, "Connection: keep-alive\r\n");
        if(ref)
                next_post = sprintf(pb += next_post, "Referer: %s\r\n",ref);
        if(cookie)
                next_post = sprintf(pb += next_post, "Cookie: %s\r\n",cookie);
        next_post = sprintf(pb += next_post, "Content-Type: application/x-www-form-urlencoded\r\n");
        next_post = sprintf(pb += next_post, "Content-Length: %d\r\n",strlen(req));
        next_post = sprintf(pb += next_post, "\r\n");
        next_post = sprintf(pb += next_post, "%s",req);
        printf("post is\n%s\nsize = %d\n",postbuf,send_size = strlen(postbuf));
        send_size = send(fd, postbuf, send_size, 0);
        printf("\n%d by sent",send_size);
        http_recv(fd, respond.buf, RESPON_BUF_SIZE);
}
int main()
{
        int fd,fd_post_reg,fd_post_mail,fd_get_ov,fd_login;
        int fd_size,send_size,recv_size;
        struct addrinfo *ai;
        struct sockaddr_in sin;
        char addrstr[32];
        int errno;
        memset(sin.sin_zero, 0, sizeof(sin.sin_zero));
        if((errno = getaddrinfo(addr, "http", NULL, &ai)) == 0)
        {
                for( ; ai != NULL ; )
                {
                        sin = *((struct sockaddr_in *)ai->ai_addr);
                        inet_ntop(AF_INET, &(sin.sin_addr), addrstr, 32);
                        printf("addr = %s : port = %hd \n",addrstr,(ntohs(sin.sin_port)));
                        ai = ai->ai_next;
                }
                fd = socket(AF_INET, SOCK_STREAM, 0);
                if(fd < 0)
                {
                        printf("socket error fd = %d\n",fd);
                        return 1;
                }
                if(connect(fd, (struct sockaddr *)&sin, sizeof(sin)) == 0)
                {
                        printf("connection success!\n");
                        do_get(fd, (char *)&request, "/signup", addr, NULL);

                        find_from_header(respond.header,  "Set-Cookie: ", (char *)&cookie_buf, 2048);
                        get_auth();
                        printf("\ncookie = %s\n",cookie_buf);
                        /*
                        // login
                        strcpy(post_t, post1);
                        strcat(post_t, auth_conv);
                        strcat(post_t, post2);
                        fd_login = socket(AF_INET, SOCK_STREAM, 0);
                        if(connect(fd_login, (struct sockaddr *)&sin, sizeof(sin)) == 0)
                        {
                                memset(request, 0, sizeof(request));
                                memset(post_t, 0, sizeof(post_t));
                                strcpy(post_t, post1);
                                strcat(post_t, auth_conv);
                                strcat(post_t, post_login);
                                do_post(fd_login, "/sessions", addr, request, post_t, "http://www.asvpn.com/signin", (char *)&cookie_buf);
                                // update cookie 
                                find_from_header(respond.header,  "Set-Cookie: ", (char *)&cookie_buf, 2048);
                                printf("new cook is \n%s",cookie_buf);
                        }
                        */
                        // make datas(registration) to be posted
                        fd_post_reg = socket(AF_INET, SOCK_STREAM, 0);
                        if(fd_post_reg < 0)
                        {
                                printf("socket error %s = %d\n","fd_post_reg",fd_post_reg);
                                return 1;
                        }
                        if(connect(fd_post_reg, (struct sockaddr *)&sin, sizeof(sin)) == 0)
                        {
                                printf("fd_post ready to post!\n\n\n\n");
                                sprintf(post_t,"%s%s%s%s%s%s%s%s%s",
                                                post1,auth_conv,post2_0,username,post2_1,password,post2_2,password,post2_3);
                                printf("post1 = %s\n",post_t);
                                do_post(fd_post_reg, "/users", addr, request, post_t, NULL, (char *)&cookie_buf);
                                // update cookie 
                                find_from_header(respond.header,  "Set-Cookie: ", (char *)&cookie_buf, 2048);
                                printf("new cook is \n%s",cookie_buf);
                                close(fd_post_reg);
                        }
                        // make datas(email) to be post
                        memset(post_t, 0, sizeof(post_t));
                        memset(request, 0, sizeof(request));
                        sprintf(post_t,"%s%s%s%s%s",post1,auth_conv,post3_0,email,post3_1);
                        fd_post_mail = socket(AF_INET, SOCK_STREAM, 0);
                        if(fd_post_mail < 0 )
                        {
                                printf("socket error %s = %d\n","fd_post_mail",fd_post_mail);
                                return 1;
                        }
                        printf("fd_post ready to post!\n\n\n\n");
                        if(connect(fd_post_mail, (struct sockaddr *)&sin, sizeof(sin)) == 0)
                                        do_post(fd_post_mail, "/users/verify_email", addr, request, post_t, 
                                                        "http://www.asvpn.com/users/verify_form",
                                                        (char *)&cookie_buf);
                                close(fd_post_mail);
                        sleep(20);
                        printf("\n*******************************\n");
                        printf("mail is on the way!\n");
                        email_main();
                }
        }
        return 0;
}

void conv(char *in, char *out)
{
        char *pin = in;
        char *pout = out;
        int hex;
        for( ; *pin; pin++)
        {
                if(isalnum(*pin) || *pin == '&' || *pin == '_')
                {
                        *pout++ = *pin;
                        continue;
                }
                else
                {
                        *pout++ = '%';
                        hex = *pin;
                        printf("Got a symbol = %2X\n",hex);
                        snprintf(pout,3,"%2X",hex);
                        pout+=2;
                }
        }
}

/* get authenticity_token from body
   and convert it ready to be posted*/
void get_auth()
{
        if(find_auth)
                return ; /* already found */
        
        if((find_auth = strstr(respond.body, "\"authenticity_token\" type=\"hidden\" value=\"")) != NULL)
        {
                find_auth += 42;
                printf("get authenticity_token :\n");
                snprintf(auth, 45, "%s",find_auth);
                printf("%s\n",auth);
                conv(auth, auth_conv);
                printf("convert to :\n%s",auth_conv);   /* this area should only run once! , since the authenticity_token doesn't change */
        }
}

/* backups */
//*char *post1 = "utf8=%E2%9C%93&authenticity_token=";
//*char *post2 = "&user%5Busername%5D=iamemailll&user%5Bpassword%5D=iamemailll&user%5Bpassword_confirmation%5D=iamemailll&commit=%E6%B3%A8%E5%86%8C";
//*char *post3 = "&user%5Bemail%5D=iamemail2%40eyou.com&commit=%E5%8F%91%E9%80%81%E9%AA%8C%E8%AF%81%E9%82%AE%E4%BB%B6";
//*char *post_login = "&session%5Busername%5D=iwantp0st&session%5Bpassword%5D=iwantp0st&commit=%E7%99%BB%E9%99%86";
/* backups */

/* you need to add \r\n yourself ! */
#define CMD(cmd_buf, cmd, args) strcmp(args, "\r\n") == 0 ? sprintf(cmd_buf,"%s%s", cmd,args) : sprintf(cmd_buf, "%s %s", cmd, args)
#define DEBUG(on,...) if(on) printf(__VA_ARGS__);
char *mail_addr = "pop3.163.com";
char *user = "cs_jonas_johnnyr\r\n";
char *pass = "6328100\r\n";
char sendcmd[32];
char mail_respond[1024] ;
char verify_url_final[256];

char *verify_url_0 = "http://www.asvpn.com/users/email_verify?username=";
char *verify_url_1 = "&verify=";
void email_login(int fd, char *username, char *password)
{        
        int data_size;

        CMD(sendcmd, "user", username);
        data_size = send(fd, sendcmd, strlen(sendcmd), 0);
        DEBUG(1,"send data : LEN = %d\n%s\n",strlen(sendcmd), sendcmd); 
        
        data_size = recv(fd, mail_respond, 1024, 0);
        DEBUG(1,"recv data : LEN = %d\n%s\n",strlen(mail_respond),mail_respond);
        
        CMD(sendcmd, "pass", password);
        data_size = send(fd, sendcmd, strlen(sendcmd), 0);
        DEBUG(1,"send data : LEN = %d\n%s\n",strlen(sendcmd),sendcmd);
        
        data_size = recv(fd, mail_respond, 1024, 0);
        DEBUG(1,"recv data : LEN = %d\n%s\n",strlen(mail_respond),mail_respond);

}
#define VERIFY_CODE_LEN 32
char *email_get_verify_url(int fd)
{
        int data_size;
        char str_get_mail_nr[16];
        int mail_nr;
        char verify_code[VERIFY_CODE_LEN + 1];
        char *find_verify_code;

        /* base_64 vars*/
        char *find_base64 = NULL;
        char base64_input[2048];
        char *pbase64_decode = NULL;
        int b64_len = 2048;
        CMD(sendcmd,"list","\r\n");
        data_size = send(fd, sendcmd, strlen(sendcmd), 0);
        DEBUG(1,"send data : LEN = %d\n%s\n",strlen(sendcmd), sendcmd); 
        
        data_size = recv(fd, mail_respond, 1024, 0);
        DEBUG(1,"recv data : LEN = %d\n%s\n",strlen(mail_respond),mail_respond);
        

        /* get the mail numbers , the respond is like this :
        +OK 3*
        */
        strncpy(str_get_mail_nr, mail_respond, sizeof(str_get_mail_nr));
        sscanf(str_get_mail_nr, "+OK %d%*s",&mail_nr);
        printf("mail nr = %d\n", mail_nr);

        /* get the latest mail */
        sprintf(str_get_mail_nr, "%d\r\n",mail_nr);

        CMD(sendcmd, "retr", str_get_mail_nr);
        data_size = send(fd, sendcmd, strlen(sendcmd), 0);
        DEBUG(1,"send data : LEN = %d\n%s\n",strlen(sendcmd), sendcmd);

        while((data_size = recv(fd, mail_respond, 1024, 0)) > 0)
        {
                DEBUG(1,"recv data : LEN = %d\n%s\n",strlen(mail_respond),mail_respond);

                if((find_base64 = strstr(mail_respond,"Content-Transfer-Encoding: base64")) != NULL)
                {
                        find_base64 += strlen("Content-Transfer-Encoding: base64\r\n\r\n");
                        while(*find_base64 != '\n')
                                find_base64++;
                        printf("b64 start here!\n");
                        strncpy(base64_input, find_base64, strlen(find_base64));
                        printf("%s",base64_input);
                        printf("AFTER DECODE\n\n");
                        pbase64_decode = g_base64_decode(base64_input, &b64_len);
                        printf("%s",pbase64_decode);
                }
                if(pbase64_decode && ((find_verify_code = strstr(pbase64_decode, "verify=")) != NULL))
                {
                        find_verify_code += 7; /* right behind verify= */
                        memset(verify_code, 0, sizeof(verify_code));
                        strncpy(verify_code, find_verify_code, 34);
                        DEBUG(1,"FOUND THE V:\n%s",verify_code);
                        /* Make the final verify_url */
                        sprintf(verify_url_final,"%s%s%s%s",verify_url_0,username,verify_url_1,verify_code);
                        printf("verify_url_final = :\n%s\n",verify_url_final);
                        free(pbase64_decode);
                        close(fd);
                        return (char *)&verify_url_final;
                }
                sleep(1);
        }
}

void email_main()
{
        int mail;
        struct addrinfo *ai;
        struct sockaddr_in sin;
        char addrstr[32];
        int r ;
        memset(sin.sin_zero, 0, sizeof(sin.sin_zero));
        if((getaddrinfo(mail_addr, "pop3", NULL, &ai)) == 0)
        {
                for( ; ai != NULL ; )
                {
                        sin = *((struct sockaddr_in *)ai->ai_addr);
                        inet_ntop(AF_INET, &(sin.sin_addr), addrstr, 32);
                        printf("addr = %s : port = %hd \n",addrstr,(ntohs(sin.sin_port)));
                        ai = ai->ai_next;
                }
                mail = socket(AF_INET, SOCK_STREAM, 0);
                if(mail < 0)
                {
                        printf("socket error fd = %d\n",mail);
                        return ;
                }
                if(( r = connect(mail, (struct sockaddr *)&sin, sizeof(sin))) == 0)
                        printf("connect success!\n");
                else
                {
                        printf("connect error!\n");
                }
                email_login(mail, user, pass);
                email_get_verify_url(mail);

        }
        else
        {
                printf("EMAIL SERVER IS UN-AVAILABE\n\n");
        }
}

