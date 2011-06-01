#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <ctype.h>
#include <fcntl.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netdb.h>
#include <string.h>
#include <glib.h>

#define MODE_RELEASE 0
#define MODE_DEBUG !MODE_RELEASE
#define MODE MODE_RELEASE      /* control output info */
#define PORT 80
#define HEADER_MAX_NR 16
#define HEADER_MAX_LEN 512
#define RESPON_BUF_SIZE 10240
#define DEBUG(on,...) do{if(on) printf(__VA_ARGS__);}while(0)
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
char username[16] ;
char password[16] ;

char email_0[] = {"sunuslikeme%2B"}; /* %2B == '+' ,thanks to google , we can use ALIAS*/
char email_1[] = {"%40gmail.com"};   /* %40 == '@' */
char email[64] ;
char verify_url_final[256];
/* i set up this mail so that it can auto-forward verify_code to a pop3 mail */
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
                        DEBUG(MODE,"get header :\n%s\n",respond.header);
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
                        DEBUG(MODE,"found a %s #%d\n%s", find, find_nr, (char *)(find_from_header_result.datas)[find_from_header_result.items]);
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
        int send_size,recv_size;
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
        send_size = strlen(reqbuff);
        DEBUG(MODE,"sending request : size = %d\n", send_size);
        DEBUG(1,"%s\n\n",reqbuff);
        recv_size = 0;
        send_size = send(fd, reqbuff, send_size, 0);
        DEBUG(MODE,"%d bytes sent\n",send_size);
        http_recv(fd, respond.buf, RESPON_BUF_SIZE);
        DEBUG(MODE,"recv :\n%s\n",respond.buf);
}
void do_post(int fd, char *uri, char *host, char *postbuf, char *req, char *ref ,char *cookie)
{
        int send_size;
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
        send_size = strlen(postbuf);
        DEBUG(MODE,"post is\n%s\nsize = %d\n",postbuf,send_size);
        send_size = send(fd, postbuf, send_size, 0);
        DEBUG(MODE,"\n%d by sent",send_size);
        http_recv(fd, respond.buf, RESPON_BUF_SIZE);
}

/* 
 *  init the username , password , email in this pattern
 *  user_0001
 *  user_0002
 *  .........
 *  user_9999
 */
void user_info_init(char *info)
{
        FILE *f;
        int postfix;
        int num_pos;
        char *pinfo ;
        char history[32] = {0};
        if(info == NULL) /* load from history */
        {
                f = fopen("history", "rb+");
                fread(history, sizeof(char), 32, f);
                DEBUG(MODE,"read : %s\n",history);
                num_pos = strlen(history);
                pinfo = &history[num_pos - 4];
                sscanf(pinfo,"%04d",&postfix);
                history[num_pos - 4] = '\0';
                postfix++;
                sprintf(history,"%s%04d",history, postfix);
                DEBUG(MODE,"new history = %s",history);
                fseek(f, 0, SEEK_SET);
        }
        else    /* creat history from info*/
        {
                f = fopen("history", "ab");
                sprintf(history,"%s_0000",info);
        }

        fwrite((void *)history, sizeof(char), strlen(history), f);
        pinfo = history;
        sprintf(username, "%s", pinfo);
        sprintf(password, "%s", pinfo);
        sprintf(email, "%s%s%s",email_0,pinfo,email_1);
        printf("username : %s\npassword : %s\nemail : %s\n",username,password,email);
        fclose(f);
}
int main(int argc, char *argv[])
{
        int fd,fd_post_reg,fd_post_mail,fd_verify;
        struct addrinfo *ai;
        struct sockaddr_in sin;
        char addrstr[32];
        char *uri ;
        int errno;
        if(argc >= 2)
        {
                if((argc == 2) && 
                                (strlen(argv[1]) < 15))
                        ;  /* We're safe */
                else
                {
                        printf("\n\n\nUsage : VpnGrabber -SpeciaToken for the first time\n");
                        printf("when the first time success , Use ./VpnGrabber\n\n\n\n");
                        return 1;
                }
        }
        printf("Good luck ! we're good to go\n");
        user_info_init(argc == 2 ? argv[1] : NULL);
        memset(sin.sin_zero, 0, sizeof(sin.sin_zero));
        if((errno = getaddrinfo(addr, "http", NULL, &ai)) == 0)
        {
                for( ; ai != NULL ; )
                {
                        sin = *((struct sockaddr_in *)ai->ai_addr);
                        inet_ntop(AF_INET, &(sin.sin_addr), addrstr, 32);
                        DEBUG(MODE,"addr = %s : port = %hd \n",addrstr,(ntohs(sin.sin_port)));
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
                        DEBUG(MODE,"connection success!\n");
                        do_get(fd, (char *)&request, "/signup", addr, NULL);
                        close(fd);
                        find_from_header(respond.header,  "Set-Cookie: ", (char *)&cookie_buf, 2048);
                        get_auth();
                        DEBUG(MODE,"\ncookie = %s\n",cookie_buf);
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
                                DEBUG(MODE,"fd_post ready to post!\n\n\n\n");
                                sprintf(post_t,"%s%s%s%s%s%s%s%s%s",
                                                post1,auth_conv,post2_0,username,post2_1,password,post2_2,password,post2_3);
                                DEBUG(MODE,"post1 = %s\n",post_t);
                                do_post(fd_post_reg, "/users", addr, request, post_t, NULL, (char *)&cookie_buf);
                                // update cookie 
                                find_from_header(respond.header,  "Set-Cookie: ", (char *)&cookie_buf, 2048);
                                DEBUG(MODE,"new cook is \n%s",cookie_buf);
                                close(fd_post_reg);
                        }
                        // make datas(email) to be post
                        memset(post_t, 0, sizeof(post_t));
                        memset(request, 0, sizeof(request));
                        sprintf(post_t,"%s%s%s%s%s",post1,auth_conv,post3_0,email,post3_1);
                        fd_post_mail = socket(AF_INET, SOCK_STREAM, 0);
                        if(fd_post_mail < 0 )
                        {
                                DEBUG(1,"socket error %s = %d\n","fd_post_mail",fd_post_mail);
                                return 1;
                        }
                        DEBUG(MODE,"fd_post ready to post!\n\n\n\n");
                        if(connect(fd_post_mail, (struct sockaddr *)&sin, sizeof(sin)) == 0)
                                do_post(fd_post_mail, "/users/verify_email", addr, request, post_t, 
                                                "http://www.asvpn.com/users/verify_form",
                                                (char *)&cookie_buf);
                        close(fd_post_mail);
                        printf("mail is on the way!\n");
                        sleep(30);
                        printf("\n*******************************\n");
                        email_main();

                        printf("\n******************************************************\n\n");
                        printf("The ips are: MAIN ADDRESS -- BACKUP ADDRESS\n"
                                        "us001.asvpn.com -- us001.fast-as.info\n"
                                        "us002.asvpn.com -- us002.fast-as.info (No speed limit)\n"
                                        "us003.asvpn.com -- us003.fast-as.info (No speed limit)\n"
                                        "us004.asvpn.com -- us004.fast-as.info\n"
                                        "us005.asvpn.com -- us005.fast-as.info\n"
                                        "us006.asvpn.com -- us006.fast-as.info\n"
                                        "us007.asvpn.com -- us007.fast-as.info (No speed limit)\n"
                                        "us008.asvpn.com -- us008.fast-as.info\n"
                                        "us009.asvpn.com -- us009.fast-as.info\n");
                        printf("\n******************************************************\n");

                        fd_verify = socket(AF_INET, SOCK_STREAM, 0);
                        if(connect(fd_verify, (struct sockaddr *)&sin, sizeof(sin)) == 0)
                        {
                                uri = (char *)(verify_url_final + 20);
                                while(*uri != '\n')
                                        uri++;
                                *uri = '\0';
                                uri = (char *)(verify_url_final + 20);
                                printf("uri = %s\n",uri);
                                memset(request, 0, sizeof(request));
                                do_get(fd, (char *)&request, uri, addr, NULL);
                        }
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
                        DEBUG(MODE,"Got a symbol = %2X\n",hex);
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
                DEBUG(MODE,"get authenticity_token :\n");
                snprintf(auth, 45, "%s",find_auth);
                DEBUG(MODE,"%s\n",auth);
                conv(auth, auth_conv);
                DEBUG(MODE,"convert to :\n%s",auth_conv);   /* this area should only run once! , since the authenticity_token doesn't change */
        }
}


/* you need to add \r\n yourself ! */
#define CMD(cmd_buf, cmd, args) strcmp(args, "\r\n") == 0 ? sprintf(cmd_buf,"%s%s", cmd,args) : sprintf(cmd_buf, "%s %s", cmd, args)
char *mail_addr = "pop3.163.com";
char *user = "sunusgotvpn\r\n";
char *pass = "vpngotsunus\r\n";
char sendcmd[32];
char mail_respond[1024] ;

char *verify_url_0 = "http://www.asvpn.com/users/email_verify?username=";
char *verify_url_1 = "&verify=";
void email_login(int fd, char *username, char *password)
{        
        int data_size;

        CMD(sendcmd, "user", username);
        data_size = send(fd, sendcmd, strlen(sendcmd), 0);
        DEBUG(MODE,"send data : LEN = %d\n%s\n",strlen(sendcmd), sendcmd); 
        
        data_size = recv(fd, mail_respond, 1024, 0);
        DEBUG(MODE,"recv data : LEN = %d\n%s\n",strlen(mail_respond),mail_respond);
        
        CMD(sendcmd, "pass", password);
        data_size = send(fd, sendcmd, strlen(sendcmd), 0);
        DEBUG(MODE,"send data : LEN = %d\n%s\n",strlen(sendcmd),sendcmd);
        
        data_size = recv(fd, mail_respond, 1024, 0);
        DEBUG(MODE,"recv data : LEN = %d\n%s\n",strlen(mail_respond),mail_respond);

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
        gsize b64_len = 2048;
        CMD(sendcmd,"list","\r\n");
        data_size = send(fd, sendcmd, strlen(sendcmd), 0);
        DEBUG(MODE,"send data : LEN = %d\n%s\n",strlen(sendcmd), sendcmd); 
        
        data_size = recv(fd, mail_respond, 1024, 0);
        DEBUG(MODE,"recv data : LEN = %d\n%s\n",strlen(mail_respond),mail_respond);
        

        /* get the mail numbers , the respond is like this :
        +OK 3*
        */
        strncpy(str_get_mail_nr, mail_respond, sizeof(str_get_mail_nr));
        sscanf(str_get_mail_nr, "+OK %d%*s",&mail_nr);
        DEBUG(MODE,"mail nr = %d\n", mail_nr);

        /* get the latest mail */
        sprintf(str_get_mail_nr, "%d\r\n",mail_nr);

        CMD(sendcmd, "retr", str_get_mail_nr);
        data_size = send(fd, sendcmd, strlen(sendcmd), 0);
        DEBUG(MODE,"send data : LEN = %d\n%s\n",strlen(sendcmd), sendcmd);

        while((data_size = recv(fd, mail_respond, 1024, 0)) > 0)
        {
                DEBUG(MODE,"recv data : LEN = %d\n%s\n",strlen(mail_respond),mail_respond);

                if((find_base64 = strstr(mail_respond,"Content-Transfer-Encoding: base64")) != NULL)
                {
                        find_base64 += strlen("Content-Transfer-Encoding: base64\r\n\r\n");
                        while(*find_base64 != '\n')
                                find_base64++;
                        DEBUG(MODE,"b64 start here!\n");
                        strncpy(base64_input, find_base64, strlen(find_base64));
                        DEBUG(MODE,"%s",base64_input);
                        DEBUG(MODE,"AFTER DECODE\n\n");
                        pbase64_decode = (char *)g_base64_decode(base64_input, &b64_len);
                        DEBUG(MODE,"%s",pbase64_decode);
                }
                if(pbase64_decode && ((find_verify_code = strstr(pbase64_decode, "verify=")) != NULL))
                {
                        find_verify_code += 7; /* right behind verify= */
                        memset(verify_code, 0, sizeof(verify_code));
                        strncpy(verify_code, find_verify_code, 34);
                        DEBUG(MODE,"FOUND THE V:\n%s",verify_code);
                        /* Make the final verify_url */
                        sprintf(verify_url_final,"%s%s%s%s",verify_url_0,username,verify_url_1,verify_code);
                        printf("verify_url_final = :\n%s\n",verify_url_final);
                        printf("uri = %s\n",(char *)(verify_url_final + 20));
                        free(pbase64_decode);
                        close(fd);
                        printf("username : %s\npassword : %s\nemail : %s\n",username,password,email);
                        return (char *)(verify_url_final + 20);
                }
                sleep(1);
        }
        return NULL;
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
                        DEBUG(MODE,"addr = %s : port = %hd \n",addrstr,(ntohs(sin.sin_port)));
                        ai = ai->ai_next;
                }
                mail = socket(AF_INET, SOCK_STREAM, 0);
                if(mail < 0)
                {
                        DEBUG(1,"socket error fd = %d\n",mail);
                        return ;
                }
                if(( r = connect(mail, (struct sockaddr *)&sin, sizeof(sin))) == 0)
                        DEBUG(MODE,"connect success!\n");
                else
                {
                        DEBUG(1,"connect error!\n");
                }
                email_login(mail, user, pass);
                if(email_get_verify_url(mail) == NULL)
                {
                        printf("retry : please wait...");
                        if(email_get_verify_url(mail) == NULL)
                                printf("we're done! admin find us>.<\n\n");
                }
        }
        else
        {
                printf("EMAIL SERVER IS UN-AVAILABE\n\n");
        }
}

