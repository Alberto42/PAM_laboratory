#include <iostream>
#include <security/pam_appl.h>
#include <security/pam_misc.h>

using namespace std;

static struct pam_conv login_conv = {
        misc_conv,               /* przykładowa funkcja konwersacji z libpam_misc */
        NULL                        /* ewentualne dane aplikacji (,,domknięcie'') */
};

int main() {

    pam_handle_t* pamh = NULL;
    int retval;
    char *username = NULL;

    retval = pam_start("pal", username, &login_conv, &pamh);
    if (pamh == NULL || retval != PAM_SUCCESS) {
        fprintf(stderr, "Error when starting: %d\n", retval);
        exit(1);
    }

    pam_set_item(pamh, PAM_USER_PROMPT, "Kto to?: ");
    retval = pam_acct_mgmt(pamh,0);
    if (retval != PAM_SUCCESS) {
        fprintf(stderr, "Nie udalo sie zalogowac!\n");
        exit(3);
    }
    retval = pam_authenticate(pamh, 0);  /* próba autoryzacji */
    if (retval != PAM_SUCCESS) {
        fprintf(stderr, "Nie udalo sie zalogowac!\n");
        exit(2);
    }
    else
        fprintf(stderr, "Udalo sie zalogowac.\n");

    while(true) {
        string s;
        cin >> s;
        if (s.size() == 1 && s[0] == '.')
            return 0;
        bool error = false;
        for(int i=0,j=s.size()-1;i<j;i++,j--) {
            if (s[i] != s[j]){
                cout<<"Nie"<<endl;
                error = true;
                break;
            }
        }
        if (error == false)
            cout<<"Tak"<<endl;
    }

    pam_end(pamh, PAM_SUCCESS);
}
