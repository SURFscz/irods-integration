#define PAM_SM_ACCOUNT
#define PAM_SM_AUTH
#define PAM_SM_PASSWORD
#define PAM_SM_SESSION

#include <syslog.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <security/pam_appl.h>
#include <security/pam_modules.h>
#include <security/pam_ext.h>
#include <security/pam_modutil.h>

#include <curl/curl.h>

#define HTTP_BUF_LEN 2048
#define SOAP_DEFAULT_METHOD "Authenticate"
#define SOAP_REQUEST_TEMPL "<?xml version=\"1.0\" encoding=\"UTF-8\"?><SOAP:Envelope xmlns:SOAP=\"http://schemas.xmlsoap.org/soap/envelope/\" xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\"><SOAP:Header/><SOAP:Body><CredentialsAuthenticate><login>%s</login><token>%s</token></CredentialsAuthenticate></SOAP:Body></SOAP:Envelope>"

struct response_curl {
        char buffer[HTTP_BUF_LEN];
        size_t size;
};

typedef struct {
        int debug;
        char *capath;
        char *uri;
        char *method;
} module_config;

void
free_config(module_config *cfg)
{
        if (cfg) {
                free(&cfg->capath);
                free(&cfg->uri);
                free(&cfg->method);
                free(cfg);
        }
}

/**
 * cleans up memory allocated for the 3 parameters
 * returns PAM_AUTH_ERR
 */
int cleanup (CURL *curlh, struct curl_slist *header_list)
{
        if (curlh) curl_easy_cleanup(curlh);
        if (header_list) curl_slist_free_all(header_list);
        return PAM_AUTH_ERR;
}

/**
 * check the value of retval.
 * In case of failure, prints an error message.
 * returns 1 if there was a failure, 0 otherwise
 */
int check_curl_ret(int retval, char* curl_error, pam_handle_t * pamh, module_config * cfg)
{
        if (retval != CURLE_OK) {
                pam_syslog(pamh, LOG_ERR, "Unable to set CURL options: %s", curl_error);
                return 1;
        }
        return 0;
}

static size_t writefunc_curl (char *ptr, size_t size, size_t nmemb, void *userdata)
{
        struct response_curl *response = (struct response_curl *) userdata;
        size_t handled;

        if (size * nmemb > HTTP_BUF_LEN - response->size - 1)
                return 0;

        handled = size * nmemb;
        memcpy(response->buffer + response->size, ptr, handled);
        response->size += handled;

        return handled;
}

int soap(pam_handle_t * pamh, module_config * cfg, const char *user, const char *token)
{
        CURL *curlh = NULL;
        char *result = NULL;
        char *soap_action, *soap_result_tag, *soap_result_ok;
        char http_request[HTTP_BUF_LEN] = { 0 }, curl_error[CURL_ERROR_SIZE] = { 0 };
        struct response_curl http_response = { .size = 0 };
        int retval = 0;
        struct curl_slist *header_list = NULL;

        if (! user) {
                pam_syslog(pamh, LOG_ERR, "Module error: called without an user");
                return PAM_AUTH_ERR;
        }

        if (! token) {
                pam_syslog(pamh, LOG_ERR, "Module error: called without an token");
                return PAM_AUTH_ERR;
        }

        //CURL INITIALIZATION
        curlh = curl_easy_init();
        header_list = curl_slist_append(header_list, "Content-Type: text/xml; charset=utf-8");

        if (asprintf(&soap_action, "SOAPAction: \"%s\"", cfg->method) < 0) {
                pam_syslog(pamh, LOG_ERR, "Unable to allocate soap_action");
                return PAM_AUTH_ERR;
        }

        header_list = curl_slist_append(header_list, soap_action);
        free(soap_action);

        retval = curl_easy_setopt(curlh, CURLOPT_FAILONERROR, 1);
        if (check_curl_ret(retval, curl_error, pamh, cfg)) return cleanup(curlh, header_list);

        retval = curl_easy_setopt(curlh, CURLOPT_ERRORBUFFER, curl_error);
        if (check_curl_ret(retval, curl_error, pamh, cfg)) return cleanup(curlh, header_list);

        if (cfg->capath) {
            retval = curl_easy_setopt(curlh, CURLOPT_CAPATH, cfg->capath);
            if (check_curl_ret(retval, curl_error, pamh, cfg)) return cleanup(curlh, header_list);
        }

        retval = curl_easy_setopt(curlh, CURLOPT_SSL_VERIFYPEER, 1L);
        if (check_curl_ret(retval, curl_error, pamh, cfg)) return cleanup(curlh, header_list);

        retval = curl_easy_setopt(curlh, CURLOPT_HTTPHEADER, header_list);
        if (check_curl_ret(retval, curl_error, pamh, cfg)) return cleanup(curlh, header_list);

        retval = curl_easy_setopt(curlh, CURLOPT_URL, cfg->uri);
        if (check_curl_ret(retval, curl_error, pamh, cfg)) return cleanup(curlh, header_list);

        retval = curl_easy_setopt(curlh, CURLOPT_WRITEFUNCTION, &writefunc_curl);
        if (check_curl_ret(retval, curl_error, pamh, cfg)) return cleanup(curlh, header_list);

        retval = curl_easy_setopt(curlh, CURLOPT_WRITEDATA, &http_response);
        if (check_curl_ret(retval, curl_error, pamh, cfg)) return cleanup(curlh, header_list);

        // build and perform HTTP Request
        snprintf(http_request, HTTP_BUF_LEN, SOAP_REQUEST_TEMPL, user, token);

        int setopt_retval = curl_easy_setopt(curlh, CURLOPT_POSTFIELDS, http_request);

        if (setopt_retval != CURLE_OK) {
            pam_syslog(pamh, LOG_ERR, "Unable to set CURL POST request: %s", curl_error);
            cleanup(curlh, header_list);
            return PAM_AUTH_ERR;
        }

        int perform_retval = curl_easy_perform(curlh);

        if (perform_retval) {
            pam_syslog(pamh, LOG_ERR, "curl return value (%d): %s", perform_retval, curl_error);

            cleanup(curlh, header_list);
            return PAM_AUTH_ERR;
        }

        // PARSE THE RESPONSE
        http_response.buffer[http_response.size] = 0;

        http_response.size = 0;
        if (asprintf(&soap_result_tag, "<returns>") < 0) {
            pam_syslog(pamh, LOG_ERR, "Unable to allocate soap_result_tag");
            return PAM_AUTH_ERR;
        }

        result = strstr(http_response.buffer, soap_result_tag);
        free(soap_result_tag);

        if (result == NULL) {
            pam_syslog(pamh, LOG_ERR, "Invalid SOAP response: %s", http_response.buffer);

            cleanup(curlh, header_list);
            return PAM_AUTH_ERR;
        }

        if (asprintf(&soap_result_ok, "<returns>true</returns>") < 0) {
            pam_syslog(pamh, LOG_ERR, "Unable to allocate soap_result_ok");
            return PAM_AUTH_ERR;
        }

        if (!strncmp(result, soap_result_ok, strlen(soap_result_ok))) {
            retval = PAM_SUCCESS;
        } else {
            retval = PAM_AUTH_ERR;
        }

        free(soap_result_ok);
        cleanup(curlh, header_list);

        return retval;
}

int pam_sm_open_session(pam_handle_t *pamh, int flags, int argc, const char **argv) {
    return(PAM_SUCCESS);
}

int pam_sm_close_session(pam_handle_t *pamh, int flags, int argc, const char **argv) {
    return(PAM_SUCCESS);
}

int pam_sm_acct_mgmt(pam_handle_t *pamh, int flags, int argc, const char **argv) {
    return(PAM_SUCCESS);
}

/**
 * Handles the basic parsing of a given option.
 * @arg buf is the buffer to be parsed
 * @arg opt_name_with_eq is the option name we are looking for (including equal sign)
 * Note that dst has to be freed by the caller in case of 0 return code
 * returns 0 if the option was not found
 * returns -1 if an error occured (duplicate option)
 * returns the position of the start of the value in the buffer otherwise
 */
int raw_parse_option(pam_handle_t *pamh, const char* buf, const char* opt_name_with_eq, char** dst)
{
    size_t opt_len = strlen(opt_name_with_eq);
    if (0 == strncmp(buf, opt_name_with_eq, opt_len)) {
        if (dst && *dst) {
            pam_syslog(pamh, LOG_ERR,
                "Duplicated option : %s. Only first one is taken into account",
                opt_name_with_eq);
            return -1;
        } else {
            return (int)opt_len;
        }
    }
    return 0;
}

/// calls strdup and returns whether we had a memory error
int strdup_or_die(char** dst, const char* src)
{
    *dst = strdup(src);
    return *dst ? 0 : -1;
}

/**
 * Handles the parsing of a given option.
 * @arg buf is the buffer to be parsed
 * @arg opt_name_with_eq is the option name we are looking for (including equal sign)
 * @arg dst is the destination buffer for the value found if any.
 * Note that dst has to be freed by the caller in case of 0 return code
 * returns 0 if the option was not found in the buffer
 * returns 1 if the option was found in buffer and parsed properly
 * returns -1 in case of error
 */
int parse_str_option(pam_handle_t *pamh, const char* buf, const char* opt_name_with_eq, char** dst)
{
    int value_pos = raw_parse_option(pamh, buf, opt_name_with_eq, dst);
    if (value_pos > 0) {
        if (strdup_or_die(dst, buf+value_pos)) {
            return -1;
        }
        return 1;
    } else if (value_pos == -1) {
        // Don't crash on duplicate, ignore 2nd value
        return 1;
    }
    return value_pos;
}

void
parse_config(pam_handle_t *pamh, int argc, const char **argv, module_config **ncfg)
{
        module_config *cfg = NULL;
        int mem_error = 0;
        int i;

        cfg = (module_config *) calloc(1, sizeof(module_config));
        if (!cfg) {
                pam_syslog(pamh, LOG_CRIT, "Out of memory");
                return;
        }

	cfg->debug = 0;
	cfg->capath = NULL;
	cfg->uri = NULL;
	cfg->method = NULL;

        for (i = 0; i < argc; ++i) {
                int retval = !strcmp(argv[i], "debug");
                if (retval) cfg->debug = 1;

                if (retval == 0) retval = parse_str_option(pamh, argv[i], "capath=", &cfg->capath);
                if (retval == 0) retval = parse_str_option(pamh, argv[i], "uri=", &cfg->uri);
                if (retval == 0) retval = parse_str_option(pamh, argv[i], "method=", &cfg->method);

                if (0 == retval) {
                        pam_syslog(pamh, LOG_ERR, "Invalid option: %s", argv[i]);
                        free_config(cfg);
                        return;
                } else if (retval < 0) {
                        mem_error = retval;
                        break;
                }
        }

        //DEFAULT VALUES
        if (!cfg->method &&  !mem_error)
                mem_error = strdup_or_die(&cfg->method, SOAP_DEFAULT_METHOD);

        // in case we got a memory error in the previous code, give up immediately
        if (mem_error) {
                pam_syslog(pamh, LOG_CRIT, "Out of memory");
                free_config(cfg);

                return;
        }

        if (cfg->debug) {
                pam_syslog(pamh, LOG_INFO, "debug => %d",           cfg->debug);
                pam_syslog(pamh, LOG_INFO, "capath => %s",          cfg->capath);
                pam_syslog(pamh, LOG_INFO, "uri => %s",             cfg->uri);
                pam_syslog(pamh, LOG_INFO, "method => %s",          cfg->method);
        }

        *ncfg = cfg;
}

int pam_sm_authenticate(pam_handle_t *pamh, int flags, int argc, const char **argv) {
        char *user = NULL;
        char *token = NULL;

        module_config *cfg = NULL;

        parse_config(pamh, argc, argv, &cfg);

        if (!cfg) {
                pam_syslog(pamh, LOG_ERR, "configuration invalid");
                return PAM_AUTH_ERR;
        }

        (void) pam_get_user(pamh, (const char **) &user, NULL);

        if (!user) {
                return PAM_USER_UNKNOWN;
        }

        if (pam_prompt(pamh, PAM_PROMPT_ECHO_ON, &token, "%s", "TOKEN: ") != PAM_SUCCESS) {
                pam_syslog(pamh, LOG_INFO, "Unable to get user input");

                return PAM_AUTH_ERR;
        }

        int result = soap(pamh, cfg, user, token);

        free(token);

        return (result);
}

int pam_sm_setcred(pam_handle_t *pamh, int flags, int argc, const char **argv) {
        return (PAM_SUCCESS);
}

int pam_sm_chauthtok(pam_handle_t *pamh, int flags, int argc, const char **argv) {
        return (PAM_SUCCESS);
}
