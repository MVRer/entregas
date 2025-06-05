#include <iostream>
#include <string>
#include <algorithm>
#include <cmath>

bool isPalindrome(const std::string& str) {
    std::string reversed = str;
    std::reverse(reversed.begin(), reversed.end());
    return str == reversed;
}

std::string toBinary(int n) {
    if (n == 0) return "0";
    std::string result = "";
    while (n > 0) {
        result = (n % 2 ? "1" : "0") + result;
        n /= 2;
    }
    return result;
}

std::string toHex(int n) {
    if (n == 0) return "0";
    std::string result = "";
    while (n > 0) {
        int remainder = n % 16;
        if (remainder < 10) {
            result = char('0' + remainder) + result;
        } else {
            result = char('a' + remainder - 10) + result;
        }
        n /= 16;
    }
    return result;
}

int binHexPalindromeCounter(int limit) {
    std::cout << "Bin-hex palindromes up to " << limit << ":\n\n";
    int counter = 0;
    
    for (int i = 1; i < limit; i++) {
        std::string binary = toBinary(i);
        std::string hex = toHex(i);
        
        if (isPalindrome(binary) && isPalindrome(hex)) {
            std::cout << "Number: " << i 
                     << " | Binary: " << binary 
                     << " | Hex: " << hex << std::endl;
            counter++;
        }
    }
    return counter;
}

int main(int argc, char *argv[]) {
    int n = atoi(argv[1]);
    int limit = pow(2, n);
    int count = binHexPalindromeCounter(limit);
    std::cout << "\nTotal bin-hex palindromes: " << count << std::endl;
    
    return 0;
}