#include <iostream>

#include <pthread.h>
#include <vector>
#include <cmath>
using namespace std;

typedef struct thread_data
{
    int id;
    pthread_t tid;
    pthread_mutex_t *mutex;
    unsigned long long start;
    unsigned long long stop;
    bool (*isprime)(unsigned long long);
    unsigned long long *total_sum;
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

bool isPrime(unsigned long long n) {
    if (n <= 1) return false;
    if (n == 2) return true;
    if (n % 2 == 0) return false;  // FIXED: Check even numbers
    
    unsigned long long limit = sqrt(n);
    for (unsigned long long i = 3; i <= limit; i += 2) {  // FIXED: Only odd divisors
        if (n % i == 0) return false;
    }
    return true;
}

void * sumofprimes(void * data){
    unsigned long long sum = 0;
    thread_data_t *data_local = (thread_data_t *)data;
    for (unsigned long long i = data_local->start; i < data_local->stop; i++) {
        //cout << i << " " << isPrime(i) << endl;
        if (data_local->isprime(i)) {
            //cout << i << " is prime" << endl;
            sum += i;
        }
    }
    pthread_mutex_lock(data_local->mutex);
    // Dereference the pointer to the total variable
    (*data_local->total_sum) += sum;
    pthread_mutex_unlock(data_local->mutex);
    pthread_exit(NULL);
}


unsigned long long ThreadMaker(int limit, int numThreads, bool (*isprime)(unsigned long long))
{
    thread_data_t *data = new thread_data_t[numThreads];
    pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;
    unsigned long long count = 0;
    std::vector<int> distribution = distributeItems(limit - 1, numThreads);  // Was: limit
    int start = 2;
    int status;
    for (int i = 0; i < numThreads; i++)
    {

        data[i].id = i;
        data[i].start = start;
        data[i].stop = start + distribution[i];
        data[i].mutex = &mutex;
        data[i].total_sum = &count;
        data[i].isprime = isprime;
        start += distribution[i];
        status = pthread_create(&data[i].tid, NULL, &sumofprimes, (void *)&data[i]);
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


int main(int argc , char *argv[]) {
    unsigned long long primeNumber = atoi(argv[1]);
    int numThreads = atoi(argv[2]);
    unsigned long long result = ThreadMaker(primeNumber, numThreads, isPrime);  // Store in correct type
    cout << "Sum of primes: " << result << endl;

    return 0;
}