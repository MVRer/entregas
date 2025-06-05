#include <iostream>
#include <string>
#include <algorithm>
#include <cmath>
#include <pthread.h>
#include <vector>

typedef struct thread_data
{
    int id;
    pthread_t tid;
    pthread_mutex_t *mutex;
    unsigned long long start;
    unsigned long long stop;
    std::string (*tobinary)(int);
    std::string (*tohex)(int);
    bool (*ispalindrome)(std::string);
    int *total_sum;
} thread_data_t;

std::vector<int> distributeItems(int total, int groups)
{
    std::vector<int> distribution(groups);

    int baseAmount = total / groups;
    int remainder = total % groups;

    for (int i = 0; i < groups; i++)
    {
        distribution[i] = baseAmount;
    }

    for (int i = 0; i < remainder; i++)
    {
        distribution[i]++;
    }

    return distribution;
}

bool isPalindrome(std::string str)
{
    std::string reversed = str;
    std::reverse(reversed.begin(), reversed.end());
    return str == reversed;
}

std::string toBinary(int n)
{
    if (n == 0)
        return "0";
    std::string result = "";
    while (n > 0)
    {
        result = (n % 2 ? "1" : "0") + result;
        n /= 2;
    }
    return result;
}

std::string toHex(int n)
{
    if (n == 0)
        return "0";
    std::string result = "";
    while (n > 0)
    {
        int remainder = n % 16;
        if (remainder < 10)
        {
            result = char('0' + remainder) + result;
        }
        else
        {
            result = char('a' + remainder - 10) + result;
        }
        n /= 16;
    }
    return result;
}

void *binHexPalindromeCounter(void *data)
{
    thread_data_t * local_data = (thread_data_t *)data;
    int counter = 0;

    for (int i = local_data->start; i < local_data->stop; i++)
    {
        std::string binary = local_data->tobinary(i);
        std::string hex = local_data->tohex(i);

        if (local_data->ispalindrome(binary) && local_data->ispalindrome(hex))
        {
            counter++;
        }
    }
    pthread_mutex_lock(local_data->mutex);
    // Dereference the pointer to the total variable
    (*local_data->total_sum) += counter;
    pthread_mutex_unlock(local_data->mutex);

    pthread_exit(NULL);
}
int binHexPalindromeThreadMaker(int limit, int numThreads, std::string (*tobinary)(int),
                                std::string (*tohex)(int),
                                bool (*ispalindrome)(std::string))
{
    thread_data_t *data = new thread_data_t[numThreads];
    pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;
    int count = 0;
    std::vector<int> distribution = distributeItems(limit, numThreads);
    int start = 0;
    int status;
    for (int i = 0; i < numThreads; i++)
    {

        data[i].id = i;
        data[i].start = start;
        data[i].stop = start + distribution[i];
        data[i].mutex = &mutex;
        data[i].total_sum = &count;
        data[i].tobinary = tobinary;
        data[i].tohex = tohex;
        data[i].ispalindrome = ispalindrome;
        start += distribution[i];
        status = pthread_create(&data[i].tid, NULL, &binHexPalindromeCounter, (void *)&data[i]);
        printf("Created thread: %d, Range: [%lld, %lld]\n", i, data[i].start, data[i].stop);
        if (status == -1) {
            perror("ERROR: pthread_create");
            delete[] data;
            return -1;
        }
    }
    for (int i=0; i<numThreads; i++) {
        pthread_join(data[i].tid, NULL);
        if (status == -1) {
            perror("ERROR: pthread_join");
        }
    }
    pthread_mutex_destroy(&mutex);
    delete[] data;

    return count;
}

int main(int argc, char *argv[])
{
    int n = atoi(argv[1]);
    int numThreads = atoi(argv[2]); 
    int limit = pow(2, n);

    int count = binHexPalindromeThreadMaker(limit, numThreads, toBinary, toHex, isPalindrome);
    std::cout << "\nTotal bin-hex palindromes: " << count << std::endl;

    return 0;
}