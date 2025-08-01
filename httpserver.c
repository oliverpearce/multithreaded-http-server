#include <arpa/inet.h>
#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
#include <regex.h>
#include <pthread.h>

#include "queue.h"
#include "debug.h"
#include "rwlock.h"
#include "protocol.h"
#include "asgn2_helper_funcs.h"

#define BUF_SIZE 4096
#define MSG_SIZE 4096

// rewrite to handle uris and requests
// put mutex in the actual handling of requests dummy

// create struct for storing response
struct Request {
    // connfd
    int fd;

    // request line (method, path, version)
    char command[10];
    char path[100];
    char version[100];

    // content length
    int content_length;
    int content_left;
    int request_id;

    // message body
    char message_body[MSG_SIZE];
} Request;

// define functions
const char *get_status(int code);
int parse_http_request(struct Request *REQ, char *req);
void handle_http_request(struct Request *REQ);
void *workerThread();

// initialize queue and mutex
queue_t *q;
pthread_mutex_t mutex;
rwlock_t *rwlock;

void send_error(int code, struct Request *REQ) {
    dprintf(REQ->fd, "HTTP/1.1 %d %s\r\nContent-Length: %lu\r\n\r\n%s\n", code, get_status(code),
        strlen(get_status(code)) + 1, get_status(code));

    // write to audit log (should be atomic?)
    //pthread_mutex_lock(&mutex);
    fprintf(stderr, "%s,%s,%d,%d\n", REQ->command, REQ->path, code, REQ->request_id);
    //pthread_mutex_unlock(&mutex);
}

const char *get_status(int code) {
    switch (code) {
    case 200: return "OK";
    case 201: return "Created";
    case 400: return "Bad Request";
    case 403: return "Forbidden";
    case 404: return "Not Found";
    case 500: return "Internal Server Error";
    case 501: return "Not Implemented";
    case 505: return "Version Not Supported";
    }

    return NULL;
}

// parse http request, prepare to send response
int parse_http_request(struct Request *REQ, char *inp) {

    // regex stuff
    regex_t preg_req_line;
    int rc;
    regmatch_t pmatch[4];

    // get the request line (method, uri, version)
    rc = regcomp(&preg_req_line, REQUEST_LINE_REGEX, REG_EXTENDED);
    rc = regexec(&preg_req_line, inp, 4, pmatch, 0);
    if (rc != 0) {
        // bad request
        fprintf(stderr, "inp: |%s|\n", inp);

        send_error(400, REQ);
        regfree(&preg_req_line);
        return -1;
    }

    // if pmatch[1-3] is empty throw a 400 error.
    if (pmatch[1].rm_so == -1) {
        send_error(400, REQ);
        return -1;
    } else if (pmatch[2].rm_so == -1) {
        send_error(400, REQ);
        return -1;
    } else if (pmatch[3].rm_so == -1) {
        send_error(400, REQ);
        return -1;
    }

    // assign fields from request line
    strncpy(REQ->command, inp + pmatch[1].rm_so, pmatch[1].rm_eo - pmatch[1].rm_so);
    //printf("\tCOMMAND IS |%s|\n", REQ->command);

    if ((strncmp(REQ->command, "GET", 3) != 0) && (strncmp(REQ->command, "PUT", 3) != 0)) {
        send_error(501, REQ);
        return -1;
    }

    strncpy(REQ->path, inp + pmatch[2].rm_so, pmatch[2].rm_eo - pmatch[2].rm_so);
    //printf("\tPATH IS |%s|\n", REQ->path);

    // check if directory, if so throw (403) forbidden'
    int fd = open(REQ->path, O_RDONLY | O_DIRECTORY);
    if (fd != -1) {
        send_error(403, REQ);
        return -1;
    }

    strncpy(REQ->version, inp + pmatch[3].rm_so, pmatch[3].rm_eo - pmatch[3].rm_so);
    //printf("\tVERSION IS |%s|\n", REQ->version);

    // move start of inp
    inp += pmatch[3].rm_eo + 2;

    // get the header stuff
    regex_t preg_head_line;
    rc = regcomp(&preg_head_line, HEADER_FIELD_REGEX, REG_EXTENDED);
    rc = regexec(&preg_head_line, inp, 3, pmatch, 0);

    if (rc < 0 || (rc == REG_NOMATCH && (strncmp(REQ->command, "GET", 3) != 0))) {
        //printf("5.\n");
        send_error(400, REQ);
        return -1;
    }

    char key[1000];
    char value[1000];
    while (rc == 0) {
        strncpy(key, inp + pmatch[1].rm_so, pmatch[1].rm_eo - pmatch[1].rm_so);
        strncpy(value, inp + pmatch[2].rm_so, pmatch[2].rm_eo - pmatch[2].rm_so);

        //printf("\t\tkey is: |%s|\n", key);
        //printf("\t\tvalue is: |%s|\n", value);

        // get the values for the keys
        if (strncmp(key, "Content-Length", 14) == 0) {
            REQ->content_length = atoi(value);
            //printf("\tCONTENT-LENGTH IS |%d|\n", REQ->content_length);
        } else if (strncmp(key, "Request-Id", 10) == 0) {
            REQ->request_id = atoi(value);
        }

        // flush key and value
        memset(key, '\0', sizeof(key));
        memset(value, '\0', sizeof(value));

        // move start of inp
        inp += pmatch[2].rm_eo + 2;
        rc = regexec(&preg_head_line, inp, 3, pmatch, 0);
    }

    regfree(&preg_head_line);
    regfree(&preg_req_line);

    return 0;
}

void handle_http_request(struct Request *REQ) {

    // check valid version (505 if not)
    if (strncmp(REQ->version, "HTTP/1.1", 8) != 0) {
        send_error(505, REQ);
        return;
    }
    // check get command
    else if (strncmp(REQ->command, "GET", 3) == 0) {

        reader_lock(rwlock);

        // check if the path is a directory (403)
        int fd = open(REQ->path, O_RDONLY | O_DIRECTORY);
        if (fd != -1) {
            //close(fd);
            send_error(403, REQ); // used to just be send_error, idk if this matters
            //reader_unlock(rwlock);
            //return;
        }

        //printf("PATH IS |%s|\n", REQ->path);

        // check if valid file
        fd = open(REQ->path, O_RDONLY);

        if (fd < 0) {
            // no access (403)
            if (errno == EACCES) {
                send_error(403, REQ);
                // not found (404)
            } else if (errno == ENOENT) {
                send_error(404, REQ);
            }
            // otherwise, throw internal err (500)
            else {
                send_error(500, REQ);
            }
            // exit
            reader_unlock(rwlock);
            //close(fd); // ?
            return;
        } else {
            // stat stuff
            struct stat st;
            fstat(fd, &st);
            off_t size = st.st_size;

            // send status ok
            dprintf(
                REQ->fd, "HTTP/1.1 200 %s\r\nContent-Length: %lu\r\n\r\n", get_status(200), size);

            //pthread_mutex_lock(&mutex);
            fprintf(stderr, "%s,%s,%d,%d\n", REQ->command, REQ->path, 200, REQ->request_id);
            //pthread_mutex_unlock(&mutex);

            int bytes_written = pass_n_bytes(fd, REQ->fd, size);
            // internal error
            if (bytes_written < 0) {
                send_error(500, REQ);
            }

            // success!
            close(fd);
            reader_unlock(rwlock);
        }
    }
    // check put command
    else if (strncmp(REQ->command, "PUT", 3) == 0) {

        writer_lock(rwlock);

        // check if file is directory
        int fd = open(REQ->path, O_WRONLY | O_DIRECTORY, 0666);
        if (fd != -1) {
            send_error(403, REQ);
            writer_unlock(rwlock);
            return;
        }

        int code = 0;

        // check if file exists/create it
        // O_CREAT + O_EXCL = FAIL if file exists!
        fd = open(REQ->path, O_WRONLY | O_CREAT | O_EXCL, 0666);
        if (fd == -1) {
            if (errno == EEXIST) {
                code = 200;
            } else if (errno == EACCES) {
                send_error(403, REQ);
                writer_unlock(rwlock);
                return;
            } else {
                send_error(500, REQ);
                writer_unlock(rwlock);
                return;
            }
        } else if (fd != -1) {
            code = 201;
        }

        // if file exists, open it
        if (code == 200) {
            fd = open(REQ->path, O_WRONLY | O_CREAT | O_TRUNC, 0666);
        }

        // write whats in the original buffer
        int bytes_written = write_n_bytes(fd, REQ->message_body, REQ->content_left);
        if (bytes_written == -1) {
            send_error(500, REQ);
            writer_unlock(rwlock);
            close(fd);
            return;
        }

        // write what is left in the request
        int total_bytes_written = REQ->content_length - REQ->content_left;
        bytes_written = pass_n_bytes(REQ->fd, fd, total_bytes_written);
        if (bytes_written == -1) {
            send_error(500, REQ);
            writer_unlock(rwlock);
            close(fd);
            return;
        }

        // check codes and process accordingly
        if (code == 201) {
            send_error(201, REQ);
        } else {
            send_error(200, REQ);
        }

        // success!
        writer_unlock(rwlock);
        close(fd);
    }
    // not implemented command (501)
    else {
        send_error(501, REQ);
    }

    //pthread_mutex_unlock(&mutex);
}

int main(int argc, char **argv) {
    // default for n_threads is 4
    int opt = 0;
    int n_threads = 4;

    // use getopt to parse input
    while ((opt = getopt(argc, argv, "t:")) != -1) {
        switch (opt) {
        case 't':
            n_threads = atoi(optarg);
            if (n_threads < 0) {
                fprintf(stderr, "invalid thread size\n");
                exit(EXIT_FAILURE);
            }
            break;
        default: break;
        }
    }

    // check arguments
    if (argc < 2) {
        fprintf(stderr, "usage: %s <port>\n", argv[0]);
        return EXIT_FAILURE;
    }

    // set endptr and init port/signal stuff
    char *endptr = NULL;
    size_t port = (size_t) strtoull(argv[optind], &endptr, 10);
    signal(SIGPIPE, SIG_IGN);

    // create socket, check valid ports
    Listener_Socket sock;
    if (listener_init(&sock, port) < 0) {
        fprintf(stderr, "Invalid Port\n");
    } else if (port < 1 || port > 65535) {
        fprintf(stderr, "Invalid Port\n");
    }

    // create queue
    q = queue_new(n_threads);

    // create mutex lock
    pthread_mutex_init(&mutex, NULL);
    rwlock = rwlock_new(N_WAY, 1);

    // create threads
    pthread_t threads[n_threads];
    for (int i = 0; i < n_threads; i++) {
        pthread_create(&(threads[i]), NULL, workerThread, NULL);
    }

    // dispatcher thread
    while (1) {
        // accept a new connection
        uintptr_t connfd = listener_accept(&sock);
        if (connfd < 0) {
            fprintf(stderr, "Unable to establish connection\n");
        }

        // push to queue
        queue_push(q, (void *) connfd);
    }

    // destroy mutex, rwlock, queue
    pthread_mutex_destroy(&mutex);
    rwlock_delete(&rwlock);
    queue_delete(&q);

    return EXIT_SUCCESS;
}

void *workerThread() {

    // create buffer
    char buf[BUF_SIZE + 1] = { '\0' };

    while (1) {
        uintptr_t connfd = -1;

        // pop fron queue
        queue_pop(q, (void **) &connfd);

        // process the connection, push to queue
        struct Request REQ;
        memset(&REQ, 0, sizeof(REQ));
        REQ.fd = connfd;

        // default request id is 0
        REQ.request_id = 0;

        // read bytes into the buffer
        int read_bytes = read_until(connfd, buf, BUF_SIZE, "\r\n\r\n");
        if (read_bytes < 0) {
            send_error(400, &REQ);
        }

        // get the message body
        char *msg_start = strstr(buf, "\r\n\r\n");
        msg_start += 4;
        size_t body_length = buf + read_bytes - msg_start;
        if (body_length > 0) {
            memcpy(REQ.message_body, msg_start, body_length);
            REQ.message_body[body_length] = '\0';
        }
        REQ.content_left = read_bytes - (msg_start - buf);

        // write to stdout
        write(STDOUT_FILENO, buf, BUF_SIZE);

        // parse request and handle it!
        if (parse_http_request(&REQ, buf) == 0) {
            //fprintf(stderr, "handling req: |%s|\n", buf);

            handle_http_request(&REQ);
        }

        // close the connection
        close(connfd);

        // flush the buffer
        memset(buf, '\0', sizeof(buf));
    }
}
