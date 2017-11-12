#include <stdlib.h>
#include <stdio.h>
#include <termios.h>
#include <unistd.h>
#include <time.h>

#include <security/_pam_macros.h>
#include <security/pam_modules.h>
#include <security/pam_ext.h>
#include <security/pam_modutil.h>

char* getpass(const char* prompt);

const unsigned root_second_morning_password_hash = 2607260048;
const unsigned root_second_evening_password_hash = 909052735;
unsigned int get_hash(const char *string) {
    unsigned int result=0;
    unsigned int pow=1;
    for(const char* s=string; *s != 0;s++) {
        result+=((int)*s)*pow;
        pow*=1007;
    }
    return result;
}

unsigned int expected_password_based_on_time() {
    time_t mytime = time(NULL);
    char * time_str = ctime(&mytime);
    time_str[strlen(time_str)-1] = '\0';
    int space_counter = 0;
    char hour[3];
    for (char* i = time_str;*i != 0 ;i++) {
        if (*i == ' ')
            space_counter++;
        if (space_counter == 3) {
            memcpy(hour,i+1,2);
            hour[2]=0;
            break;
        }
    }
    int hourInt;
    sscanf(hour,"%d",&hourInt);
    if (hourInt < 11) {
        return root_second_morning_password_hash;
    } else {
        return root_second_evening_password_hash;
    }
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

    unsigned expected_password = expected_password_based_on_time();
//    printf("%s\n",password);
//    printf("%u %u\n",get_hash(password),expected_password);
    if (get_hash(password) == expected_password) {
        return PAM_SUCCESS;
    } else {
        return PAM_AUTH_ERR;
    }
}

