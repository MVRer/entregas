#include <iostream>
#include <cmath>
using namespace std;



bool isPrime(unsigned long long n){
    //cout << "Checking if " << n << " is prime" << endl;
    unsigned long long b = ceil(sqrt(n));
    //cout << "b: " << b << endl;
    if (n <= 1) return false;
    if (n == 2) return true; // 2 is prime
    for (int i = 2; i <= b; i++) {
        if (n % i == 0) {
            return false;
        }
    }
    return true;
    
}
unsigned long long sumofprimes(unsigned long n){
    unsigned long long sum = 0;
    for (unsigned long long i = 1; i <= n; i++) {
        //cout << i << " " << isPrime(i) << endl;
        if (isPrime(i)) {
            //cout << i << " is prime" << endl;
            sum += i;
        }
    }
    return sum;
}

int main(int argc, char *argv[]) {
    unsigned long primeNumber = atoi(argv[1]);
    cout << "Sum of primes: " << sumofprimes(primeNumber) << endl;


    return 0;
}