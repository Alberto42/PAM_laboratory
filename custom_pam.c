#include <stdlib.h>
#include <stdio.h>
#include <termios.h>
#include <unistd.h>

#include <security/_pam_macros.h>
#include <security/pam_modules.h>
#include <security/pam_ext.h>
#include <security/pam_modutil.h>

char* getpass(const char* prompt);

const unsigned root_second_password_hash = 2607260048;
unsigned int getHash(const char* string) {
    unsigned int result=0;
    unsigned int pow=1;
    for(const char* s=string; *s != 0;s++) {
        result+=((int)*s)*pow;
        pow*=1007;
    }
    return result;
}
int
pam_sm_authenticate(pam_handle_t *pamh, int flags, int argc, const char **argv) {

    const char *username;

    int retval;
    retval = pam_get_user(pamh, &username, NULL);
    if (retval != PAM_SUCCESS || username == NULL) {
        printf("Cannot determin username");
        return (retval == PAM_CONV_AGAIN ? PAM_INCOMPLETE:PAM_SERVICE_ERR);
    }

    struct passwd *user_pwd = pam_modutil_getpwnam(pamh, username);
    if (user_pwd != NULL && user_pwd->pw_uid != 0) {
        /* If the user is not root, custom_pam does not apply to them */
        return PAM_SUCCESS;
    }

    char* password = getpass("Podaj drugie haslo:");
//    printf("%s\n",password);
//    printf("%u %u\n",getHash(password),root_second_password_hash);
    if (getHash(password) == root_second_password_hash) {
        return PAM_SUCCESS;
    } else {
        return PAM_AUTH_ERR;
    }
}

