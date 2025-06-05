# Algoritmos Paralelos - Suma de Primos y Palíndromos Binario-Hexadecimal

Este repositorio contiene implementaciones secuenciales y paralelas de dos problemas:

1. **Suma de primos**: Calcula la suma de todos los números primos hasta n
2. **Palíndromos binario-hexadecimal**: Encuentra números que son palíndromos tanto en representación binaria como hexadecimal hasta 2^n

## Suma de Primos

### Versión Secuencial

#### sumofprimes.cpp
**Flujo:** `main` → lee argumento, llama `sumofprimes(n)` → itera de 1 a n, para cada número llama `isPrime` → verifica divisibilidad desde 2 hasta √n, retorna true/false. Suma acumulativa de todos los primos encontrados.

**Compilar y ejecutar:**
```bash
g++ -o sumofprimes sumofprimes.cpp
./sumofprimes 100
```

#### sumofprimes.exs
**Flujo:** `main` → lee input del usuario, llama `sum_of_primes(n)` → usa `Enum.filter` con `is_prime` para filtrar rango 1..n, después `Enum.sum`. `is_prime` usa pattern matching para casos base, después `Enum.any?` para verificar divisores. Implementación funcional alternativa con `sum_of_primes_recursive`.

**Ejecutar:**
```bash
# Desde terminal
elixir sumofprimes.exs

# Desde iex
iex
c("sumofprimes.exs")
Parallelism.sum_of_primes(100)
```

### Versión Paralela

#### parallelsumofprimes.cpp
**Flujo:** `main` → lee argumentos (límite, num_hilos), llama `ThreadMaker` → usa `distributeItems` para dividir rango, crea hilos con `pthread_create`. Cada hilo ejecuta `sumofprimes` → itera su rango asignado, llama `isPrime`. Usa mutex para sincronizar suma total entre hilos, `pthread_join` espera terminación.

**Compilar y ejecutar:**
```bash
g++ -pthread -o parallelsumofprimes parallelsumofprimes.cpp
./parallelsumofprimes 100 4  # número, hilos
```

#### parallelsumofprimes.exs
**Flujo:** `taskmaker` → llama `rangemaker` para dividir trabajo, crea Tasks con `Task.async`. `rangemaker` divide número entre tasks recursivamente, genera tuplas {start, stop}. `sum_of_primes` → cada task procesa su rango con `Enum.filter` e `is_prime`. `Task.await` espera todos los resultados, `Enum.sum` combina totales.

**Ejecutar:**
```bash
# Desde iex
iex
c("parallelsumofprimes.exs")
Parallelism.taskmaker(100, 4)  # número, tasks
```

## Palíndromos Binario-Hexadecimal

### Versión Secuencial

#### binhexpalindromes.cpp
**Flujo:** `main` → lee argumento n, calcula límite 2^n, llama `binHexPalindromeCounter` → itera de 1 a límite, para cada número: llama `toBinary` y `toHex` para convertir representaciones, llama `isPalindrome` en ambas strings. Si ambas son palíndromos, incrementa contador e imprime. Conversiones usan aritmética modular para generar strings.

**Compilar y ejecutar:**
```bash
g++ -o binhexpalindromes binhexpalindromes.cpp
./binhexpalindromes 10  # busca hasta 2^10
```

#### binhexpalindromes.exs
**Flujo:** `main` → lee input, calcula límite con `:math.pow`, llama `bin_hex_palindrome_counter` → usa `Enum.filter` en rango 0..límite: para cada número llama `to_binary`, `to_hex`, `is_palindrome`. Filtra solo números que son palíndromos en ambas bases. `is_palindrome` compara string con `String.reverse`.

**Ejecutar:**
```bash
# Desde terminal
elixir binhexpalindromes.exs

# Desde iex
iex
c("binhexpalindromes.exs")
Parallelism.bin_hex_palindrome_counter(1024)
```

### Versión Paralela

#### binhexpalindromesparallel.cpp
**Flujo:** `main` → lee argumentos (n, num_hilos), calcula límite, llama `binHexPalindromeThreadMaker` → divide rango con `distributeItems`, crea hilos. Cada hilo ejecuta `binHexPalindromeCounter` → procesa su rango asignado: convierte números con `toBinary`/`toHex`, verifica con `isPalindrome`. Cuenta palíndromos localmente, usa mutex para sumar al total global. Sincronización con `pthread_join` y `pthread_mutex`.

**Compilar y ejecutar:**
```bash
g++ -pthread -o binhexpalindromesparallel binhexpalindromesparallel.cpp
./binhexpalindromesparallel 10 4  # n, hilos
```

#### parallelbinhexpalindrome.exs
**Flujo:** `taskmaker` → llama `rangemaker` para dividir 2^n entre tasks. `rangemaker` recursivamente genera rangos balanceados considerando residuo. `bin_hex_palindrome_counter` → cada task procesa tupla {start, stop}: filtra rango con `to_binary`, `to_hex`, `is_palindrome`. Imprime palíndromos encontrados y retorna cuenta. `Task.async/await` maneja concurrencia, `Enum.sum` combina resultados.

**Ejecutar:**
```bash
# Desde iex
iex
c("parallelbinhexpalindrome.exs")
Parallelism.taskmaker(10, 4)  # n, tasks
```

## Funciones Auxiliares Clave

**rangemaker (Elixir)**
- Divide un número entre n tasks de forma balanceada
- Maneja residuo distribuyéndolo en las primeras particiones
- Genera lista de tuplas {inicio, fin} para cada task

**distributeItems (C++)**
- Similar a rangemaker pero retorna vector de tamaños por hilo
- Calcula cantidad base y distribuye residuo equitativamente

**Conversiones (ambos lenguajes)**
- `toBinary/to_binary`: convierte a base 2 usando módulo y división
- `toHex/to_hex`: convierte a base 16 con mapeo a caracteres a-f


