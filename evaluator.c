#define _POSIX_C_SOURCE 200809L
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/wait.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <semaphore.h>
#include <signal.h>
#include <errno.h>
#include <stdbool.h>

#ifndef STATE_SIZE
#define STATE_SIZE 32
#endif
#ifndef ACTION_SIZE
#define ACTION_SIZE 32
#endif
#ifndef NAME_SIZE
#define NAME_SIZE 32
#endif
#ifndef ORDERED_OUTPUT
#define ORDERED_OUTPUT 0
#endif

#define ENV_MOVE 0
#define POLICY_MOVE 1

char **extraArgs;
const char *policy_path;
const char *env_path;

typedef struct PolicyProcess {
    int to_policy;
    int from_policy;
    bool running;
    struct PolicyProcess* next;
} PolicyProcess;

typedef struct Queue_Tests {
    char* name;
    struct Queue_Tests* next;
} Queue_Tests;

typedef struct Running_Tests_List {
    PolicyProcess* taken_policy;
    char* name;
    char* last_state;
    char* last_action;
    int fd_to_env;
    int fd_from_env;
    int state;
    ssize_t partially_read;
    struct Running_Tests_List* next;
} Running_Tests_List;

typedef struct Current_Reading {
    char* test_name;
    ssize_t bytes_read;
} Current_Reading;

Queue_Tests* front_ptr = NULL;
Queue_Tests* rear_ptr = NULL;
Running_Tests_List* front_running = NULL;
PolicyProcess* free_front_policies = NULL;
Current_Reading* name_grabber = NULL;

int spawned_policies = 0;
volatile sig_atomic_t stop_flag = false;

void sigint_handler(int signo)
{
    (void)signo;
    stop_flag = 1;
    struct sigaction sa;
    sa.sa_handler = SIG_IGN;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;
    sigaction(SIGINT, &sa, NULL);
}

/* kody wyjscia:
 *  >=0  liczba odczytanych bajtow
 *   -1  inny błąd
 *   -2  EOF
 */
ssize_t safe_read(int fd, void *buf, size_t nbytes)
{
    ssize_t ret = 0;

    int old_flags = fcntl(fd, F_GETFL);
    if (old_flags == -1) return -1;

    if (!(old_flags & O_NONBLOCK))
    {
        if (fcntl(fd, F_SETFL, old_flags | O_NONBLOCK) == -1) return -1;
    }

    ssize_t t = read(fd, buf, nbytes);
    if (t > 0)
    {
        ret = t;
    }
    else if (t == 0) // EOF
    {
        ret = -2;
    }
    else if (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK) // nie ma nic na wejściu lub niefortunny interrupt
    {
        ret = 0;
    }
    else
    {
        ret = -1;
    }

    fcntl(fd, F_SETFL, old_flags);

    return ret;
}

/* kody wyjscia:
 *  >=0  sukces (liczba zapisanych bajtow)
 *   -1 inny błąd
 */
ssize_t safe_write(int fd, const void *buf, size_t nbytes)
{
    ssize_t ret = 0;

    int old_flags = fcntl(fd, F_GETFL);
    if (old_flags == -1) return -1;

    if (!(old_flags & O_NONBLOCK))
    {
        if (fcntl(fd, F_SETFL, old_flags | O_NONBLOCK) == -1) return -1;
    }

    ssize_t t = write(fd, buf, nbytes);
    if (t > 0)
    {
        ret = t;
    }
    else if (t == 0)
    {
        ret = -1;
    }
    else if (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK)
    {
        ret = 0;
    }

    fcntl(fd, F_SETFL, old_flags);

    return ret;
}

Running_Tests_List* run_environment(Queue_Tests* curr)
{
    if (curr == NULL) return NULL;

    Running_Tests_List* this = malloc(sizeof(Running_Tests_List));
    this->name = strndup(curr->name, NAME_SIZE);

    int pipe_to_env[2]; // Evaluator pisze -> Env czyta
    int pipe_from_env[2]; // Env pisze -> Evaluator czyta

    if (pipe(pipe_to_env) == -1 || pipe(pipe_from_env) == -1)
    {
        perror("pipe");
        return NULL;
    }

    fcntl(pipe_to_env[1], F_SETFD, FD_CLOEXEC);
    fcntl(pipe_from_env[0], F_SETFD, FD_CLOEXEC);

    pid_t pid = fork();
    if (pid == -1)
    {
        perror("fork");
        return NULL;
    }
    if (pid == 0) // SRODOWISKO
    {
        dup2(pipe_to_env[0], STDIN_FILENO);
        dup2(pipe_from_env[1], STDOUT_FILENO);

        close(pipe_to_env[0]);
        close(pipe_to_env[1]);
        close(pipe_from_env[0]);
        close(pipe_from_env[1]);

        int argc = 0;
        while (extraArgs[argc] != NULL) argc++;
        
        char **args = malloc((argc + 3) * sizeof(char *));
        args[0] = (char *)env_path;
        args[1] = this->name;
        for (int i = 0; i < argc; i++) args[i + 2] = extraArgs[i];
        args[argc + 2] = NULL;

        execv(env_path, args);
        perror("execv environment");
        exit(1);
    }

    close(pipe_to_env[0]);
    close(pipe_from_env[1]);

    this->last_action = malloc(sizeof(char) * (ACTION_SIZE + 1));
    this->last_state = malloc(sizeof(char) * (STATE_SIZE + 1));

    this->fd_to_env = pipe_to_env[1];
    this->fd_from_env = pipe_from_env[0];
    this->state = ENV_MOVE;
    this->next = NULL;
    this->partially_read = 0;
    this->taken_policy = NULL;

    return this;
}

char *int_to_arg(int x)
{
    int tmp = x;
    int len = 1;

    while (tmp >= 10)
    {
        tmp /= 10;
        len++;
    }

    char *buf = malloc(len + 1);
    if (!buf) return NULL;

    buf[len] = '\0';
    while (len--)
    {
        buf[len] = '0' + (x % 10);
        x /= 10;
    }

    return buf;
}

void structs_cleanup(void)
{
    Queue_Tests* curr;
    while(front_ptr != NULL)
    {
        curr = front_ptr->next;
        free(front_ptr->name);
        free(front_ptr);
        front_ptr = curr;
    }
    Running_Tests_List* curr2;
    while(front_running != NULL)
    {
        curr2 = front_running->next;
        free(front_running->last_action);
        free(front_running->last_state);
        if (front_running->taken_policy != NULL)
        {
            close(front_running->taken_policy->to_policy);
            close(front_running->taken_policy->from_policy);
            free(front_running->taken_policy);
        }
        free(front_running->name);
        close(front_running->fd_from_env);
        close(front_running->fd_to_env);
        free(front_running);
        front_running = curr2;
    }
    PolicyProcess* curr3;
    while(free_front_policies != NULL)
    {
        curr3 = free_front_policies->next;
        close(free_front_policies->to_policy);
        close(free_front_policies->from_policy);
        free(free_front_policies);
        free_front_policies = curr3;
    }
    if (name_grabber->test_name != NULL)
    {
        free(name_grabber->test_name);
    }
    free(name_grabber);
}

void err_cleanup(void)
{
    structs_cleanup();
    perror("err cleanup");
}

void set_policy_free(PolicyProcess* curr)
{
    if (curr == NULL) return;
    if (free_front_policies == NULL)
    {
        free_front_policies = curr;
        curr->next = NULL;
    }
    else
    {
        curr->next = free_front_policies;
        free_front_policies = curr;
    }
}

PolicyProcess* assign_policy(void)
{

    PolicyProcess* ret = free_front_policies;
    while(ret != NULL)
    {
        if (ret->running == false) break;
        ret = ret->next;
    }

    return ret;
}

PolicyProcess* spawn_new_policy(void)
{
    int pipe_to_policy[2];   // Evaluator pisze -> Polityka czyta
    int pipe_from_policy[2]; // Polityka pisze -> Evaluator czyta

    if (pipe(pipe_to_policy) == -1 || pipe(pipe_from_policy) == -1)
    {
        perror("pipe");
        return NULL;
    }

    fcntl(pipe_to_policy[1], F_SETFD, FD_CLOEXEC);
    fcntl(pipe_from_policy[0], F_SETFD, FD_CLOEXEC);

    int val = spawned_policies++;

    pid_t pid = fork();
    if (pid == -1)
    {
        perror("fork");
        return NULL;
    }
    if (pid == 0)
    {
        dup2(pipe_to_policy[0], STDIN_FILENO);
        dup2(pipe_from_policy[1], STDOUT_FILENO);

        close(pipe_to_policy[0]);
        close(pipe_to_policy[1]);
        close(pipe_from_policy[0]);
        close(pipe_from_policy[1]);

        int argc = 0;
        while (extraArgs[argc] != NULL) argc++;
        
        char **args = malloc((argc + 3) * sizeof(char *));
        args[0] = (char *)policy_path;
        args[1] = int_to_arg(val);
        for (int i = 0; i < argc; i++) args[i + 2] = extraArgs[i];
        args[argc + 2] = NULL;

        execv(policy_path, args);
        perror("execv policy");
        exit(1);
    }
    close(pipe_to_policy[0]);
    close(pipe_from_policy[1]);

    PolicyProcess* new = malloc(sizeof(PolicyProcess));
    new->to_policy = pipe_to_policy[1];
    new->from_policy = pipe_from_policy[0];
    new->running = false;
    new->next = NULL;
    return new;

}



int main(int argc, char *argv[])
{
    if (argc < 6) return 91;

    policy_path = argv[1];
    env_path = argv[2];
    int max_policy_calls = atoi(argv[3]); // maksymalna liczba współbieżnie pracujących polityk
    int max_calls = atoi(argv[4]); // maksymalna łączna liczba współbieżnie pracujących polityk i środowisk
    int max_active_envs = atoi(argv[5]); // maksymalna liczba procesów środowisk
    extraArgs = &argv[6];    

    bool eof = false;

    int active_envs = 0;
    int concurrent_policy_calls = 0;
    int concurrent_calls = 0;

    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = sigint_handler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;

    if (sigaction(SIGINT, &sa, NULL) == -1)
    {
        perror("sigaction");
        return 20;
    }

    name_grabber = malloc(sizeof(Current_Reading));
    name_grabber->bytes_read = 0;


    while(!stop_flag && (active_envs > 0 || !eof || front_ptr != NULL))
    {
        char* prep_test_name = NULL;
        if (!eof && name_grabber->bytes_read >= 0 && name_grabber->bytes_read < NAME_SIZE) // pobieramy nazwe testu
        {
            ssize_t b = name_grabber->bytes_read;
            if (name_grabber->test_name == NULL)
            {
                name_grabber->test_name = malloc(sizeof(char) * NAME_SIZE);
            }
            ssize_t reading1 = safe_read(STDIN_FILENO, name_grabber->test_name + b, NAME_SIZE - b);
            if (reading1 == -2) // EOF
            {
                eof = true;
                free(name_grabber->test_name);
                name_grabber->test_name = NULL;
                name_grabber->bytes_read = 0;
                reading1 = 0;
            }
            else if (reading1 == -1) // błąd innej maści
            {
                err_cleanup();
                signal(SIGINT, SIG_IGN);
                kill(0, SIGINT);
                while (wait(NULL) > 0);
                return 1;
            }
            name_grabber->bytes_read += reading1;
        }
        if (name_grabber->bytes_read == NAME_SIZE)
        {
            if (name_grabber->test_name == NULL)
            {
                err_cleanup();
                signal(SIGINT, SIG_IGN);
                kill(0, SIGINT);
                while (wait(NULL) > 0);
                return 1;
            }
            char nl;
            ssize_t reading2 = safe_read(STDIN_FILENO, &nl, 1);
            if (reading2 == -1)
            {
                err_cleanup();
                signal(SIGINT, SIG_IGN);
                kill(0, SIGINT);
                while (wait(NULL) > 0);
                return 1;
            }
            else if (reading2 > 0)
            {
                prep_test_name = name_grabber->test_name;
                name_grabber->test_name = NULL;
                name_grabber->bytes_read = 0;
            }
        }        
        
        /* test do uruchomienia */
        if (prep_test_name != NULL)
        {
            Queue_Tests* node = malloc(sizeof(Queue_Tests));
            node->name = prep_test_name;
            node->next = NULL;
            if (front_ptr == NULL && rear_ptr == NULL)
            {
                front_ptr = node;
                rear_ptr = node;
            }
            else
            {
                rear_ptr->next = node;
                rear_ptr = rear_ptr->next;
            }
        }

        while(active_envs < max_active_envs && front_ptr != NULL && concurrent_calls < max_calls)
        {
            active_envs++;
            Queue_Tests* curr = front_ptr;
            front_ptr = front_ptr->next;
            if (front_ptr == NULL) rear_ptr = NULL;

            Running_Tests_List* new = run_environment(curr);
            free(curr->name);
            free(curr);

            if (front_running == NULL)
            {
                front_running = new;
            }
            else
            {
                new->next = front_running;
                front_running = new;
            }
            concurrent_calls++;
        }
        Running_Tests_List* prev = NULL;
        Running_Tests_List* ptr = front_running;
        while(ptr != NULL)
        {
            if (ptr->state == ENV_MOVE) // ostatnio zlecilismy ruch srodowisku, sprawdzamy czy mamy wynik
            {
                ssize_t r = safe_read(ptr->fd_from_env, ptr->last_state + ptr->partially_read, STATE_SIZE + 1 - ptr->partially_read);
                if (r >= 0)
                {
                    ptr->partially_read += r;
                }
                else if (r == -1)
                {
                    err_cleanup();
                    signal(SIGINT, SIG_IGN);
                    kill(0, SIGINT);
                    while (wait(NULL) > 0);
                    return 1;
                }

                if (ptr->partially_read == STATE_SIZE + 1) // SUKCES
                {
                    ptr->partially_read = 0;
                    concurrent_calls--;
                    if (ptr->last_state[0] == 'T') // koniec testu i srodowiska
                    {
                        ssize_t first_write_out = 0;
                        ssize_t second_write_out = 0;
                        ssize_t third_write_out = 0;
                        while(first_write_out < NAME_SIZE)
                        {
                            ssize_t t1 = safe_write(STDOUT_FILENO, ptr->name + first_write_out, NAME_SIZE - first_write_out);
                            if (t1 < 0)
                            {
                                err_cleanup();
                                signal(SIGINT, SIG_IGN);
                                kill(0, SIGINT);
                                while (wait(NULL) > 0);
                                return 1;
                            }
                            first_write_out += t1;
                        }
                        
                        while(second_write_out < 1)
                        {
                            char c = ' ';
                            ssize_t t1 = safe_write(STDOUT_FILENO, &c, 1);
                            if (t1 < 0)
                            {
                                err_cleanup();
                                signal(SIGINT, SIG_IGN);
                                kill(0, SIGINT);
                                while (wait(NULL) > 0);
                                return 1;
                            }
                            second_write_out += t1;
                        }
                        
                        while(third_write_out < STATE_SIZE + 1)
                        {
                            ssize_t t1 = safe_write(STDOUT_FILENO, ptr->last_state + third_write_out, STATE_SIZE + 1 - third_write_out);
                            if (t1 < 0)
                            {
                                err_cleanup();
                                signal(SIGINT, SIG_IGN);
                                kill(0, SIGINT);
                                while (wait(NULL) > 0);
                                return 1;
                            }
                            third_write_out += t1;
                        }
                    
                        PolicyProcess* curr = ptr->taken_policy;
                        set_policy_free(curr);

                        ptr->taken_policy = NULL;
                        free(ptr->name);
                        free(ptr->last_state);
                        free(ptr->last_action);
                        close(ptr->fd_from_env);
                        close(ptr->fd_to_env);
                        if (prev == NULL)
                        {
                            front_running = ptr->next;
                        }
                        else
                        {
                            prev->next = ptr->next;
                        }
                        Running_Tests_List* to_free = ptr;
                        ptr = ptr->next;
                        free(to_free);
                        active_envs--;
                        continue;
                    }
                    else
                    {
                        if (ptr->taken_policy == NULL) 
                        {
                            PolicyProcess* new_policy = assign_policy();
                            // mozemy utworzyc nowa polityke
                            if (new_policy == NULL && concurrent_policy_calls < max_policy_calls && concurrent_calls < max_calls)
                            {
                                new_policy = spawn_new_policy();
                                new_policy->next = free_front_policies;
                                free_front_policies = new_policy;
                            }
                            else if (new_policy == NULL)
                            {
                                prev = ptr;
                                ptr = ptr->next;
                                continue;
                            }
                            ptr->taken_policy = new_policy;
                            concurrent_calls++;
                            concurrent_policy_calls++;
                        }
                        else printf("polityka NIE byla null\n");

                        PolicyProcess* our_policy = ptr->taken_policy;
                        our_policy->running = true;

                        ssize_t sum_wrote = 0;
                        while(sum_wrote < STATE_SIZE + 1)
                        {
                            ssize_t y = safe_write(our_policy->to_policy, ptr->last_state + sum_wrote, STATE_SIZE + 1 - sum_wrote);
                            if (y < 0)
                            {
                                err_cleanup();
                                signal(SIGINT, SIG_IGN);
                                kill(0, SIGINT);
                                while (wait(NULL) > 0);
                                return 1;
                            }
                            sum_wrote += y;
                        }
                        
                        ptr->state = POLICY_MOVE;
                    }
                }
            }
            else if(ptr->state == POLICY_MOVE)
            {
                ssize_t r = safe_read(ptr->taken_policy->from_policy, ptr->last_action + ptr->partially_read, ACTION_SIZE + 1 - ptr->partially_read);
    
                if (r >= 0)
                {
                    ptr->partially_read += r;
                }
                else if (r == -1)
                {
                    err_cleanup();
                    signal(SIGINT, SIG_IGN);
                    kill(0, SIGINT);
                    while (wait(NULL) > 0);
                    return 1;
                }

                if (ptr->partially_read == ACTION_SIZE + 1) // SUKCES, polityka zwrocila akcje
                {
                    ptr->partially_read = 0;
                    concurrent_policy_calls--;
                    concurrent_calls--;
                    ssize_t sum_wrote = 0;
                    while(sum_wrote < ACTION_SIZE + 1)
                    {
                        ssize_t y = safe_write(ptr->fd_to_env, ptr->last_action + sum_wrote, ACTION_SIZE + 1 - sum_wrote);
                        if (y < 0)
                        {
                            err_cleanup();
                            signal(SIGINT, SIG_IGN);
                            kill(0, SIGINT);
                            while (wait(NULL) > 0);
                            return 1;
                        }
                        sum_wrote += y;
                    }
                    ptr->taken_policy->running = false;
                    ptr->taken_policy = NULL;
                    ptr->state = ENV_MOVE;
                    concurrent_calls++;
                }
            }
            prev = ptr;
            ptr = ptr->next;
        }
    }
    structs_cleanup();

    signal(SIGINT, SIG_IGN);
    kill(0, SIGINT);

    while (wait(NULL) > 0);

    return (stop_flag) ? 2 : 0;
}