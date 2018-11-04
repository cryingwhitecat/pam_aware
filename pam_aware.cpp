#include <security/pam_appl.h>
#include <signal.h>
#include <security/pam_misc.h>
#include <pwd.h>
void block_kb_interrupt()
{
    signal(SIGINT,SIG_IGN);//ctrl+c
    signal(SIGQUIT,SIG_IGN);//ctrl+z
}
int main()
{
    pam_conv conv_function = {misc_conv,NULL}; // conv function that will send msg to/from terminal
    pam_handle_t *pamh;
    passwd* passwd;
    int code;
    if((passwd=getpwuid(getuid()))==NULL) // if can`t find user in /etc/passwd(no user exists)
    {
        printf("can`t find user\n");
        pam_strerror(pamh, code);
        exit(-1);
    }
    code = pam_start("pam_aware",passwd->pw_name,&conv_function,&pamh);
    if(code != PAM_SUCCESS)
    {
        printf("error\n");
        pam_strerror(pamh, code);
        exit(-10);
    }
    block_kb_interrupt();
    printf("try to log in as %s\n",passwd->pw_name);
    do{
        code = pam_authenticate(pamh,0);
        if(code !=PAM_SUCCESS)
        {
            printf("wrong password\n");
        }
    }while(code != PAM_SUCCESS);
    printf("succesfully logged in as %s\n",passwd->pw_name);
    exit(0);
}
