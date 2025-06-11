# Programming Multi-Threaded multiple file Parser for Elixir in Elixir and Comparing to Single Threaded
Mariano - A01029708

## Description 

I coded a multiple file syntax highlighter in Elixir. This is the continuation of the previous part [Part 1](../E1-syntax-highlighter/README.md).
Previously this file could only parse 1 file at the time, now it has been upgraded to a list of files it will process.

The objective of this project was comparing how a single threaded process would behave vs a multi threaded process. 

- Which will be faster?
- The process behind it


## Usage

Single-threaded
``` bash
elixir single-threaded-syntax-highlighter.exs
```
Multi-threaded
``` bash
elixir multi-threaded-syntax-highlighter.exs
```

## Intensive usage to really see difference
``` bash
cd intensive_tests/
elixir single-threaded-syntax-highlighter.exs
elixir multi-threaded-syntax-highlighter.exs
```

## Which will be faster?

I addded a cronograph inside single-threaded and multi-threaded file, cronograph will tell us exactly the time it took to run each file. Effectivly telling us which was faster. 

### Test 1. 8 Different files 800-1k Lines

For this test I will run the file 10 times and register this times for single thread and multi

Single-threaded
``` bash
Execution time: 0.574382 seconds
Execution time: 0.5871 seconds
Execution time: 0.578986 seconds
Execution time: 0.559707 seconds
Execution time: 0.562924 seconds
Execution time: 0.582271 seconds
Execution time: 0.570356 seconds
Execution time: 0.582778 seconds
Execution time: 0.584072 seconds
Execution time: 0.564926 seconds
Promedio: 0.575s
```
Multi-threaded
``` bash
Execution time: 0.188044 seconds
Execution time: 0.190812 seconds
Execution time: 0.188174 seconds
Execution time: 0.197718 seconds
Execution time: 0.188631 seconds
Execution time: 0.187564 seconds
Execution time: 0.188809 seconds
Execution time: 0.18498 seconds
Execution time: 0.187346 seconds
Execution time: 0.189901 seconds
Average:  0.189s
```

### Test 2. 8 Similar files, 73k lines each

Single-Threaded
``` bash
for i in {1..10}; do elixir single-threaded-syntax-highlighter.exs; done | grep -oE '[0-9]+(\.[0-9]+)?'
23.847523
24.69215
24.203753
23.288109
23.359019
24.025832
23.13036
23.080785
23.96318
23.581273
Average: 23.717
```

Multi-Threaded
``` bash
for i in {1..10}; do elixir multi-threaded-syntax-highlighter.exs; done | grep -oE '[0-9]+(\.[0-9]+)?'
5.25109
5.347824
5.42602
5.678925
5.637382
5.495762
5.715723
5.829845
5.870531
5.882983
Average: 5.641
```

### Results
In the smaller files the multi-threaded ran **304.23%** faster than the single threaded one at 8 threads. 
In the intensive files the multi-threaded ran **422.5%** faster than single-threaded one at 8 threads. 

Theoretically it should be 8x faster or 800%, but there are multiple factors that affect this.
- Creating and coordinating tasks
- Amdahls law says we cant parallelize all the code. 

## The process behind it 

For single threaded only change from the previous entry was the function to read multiple files and output multiple files, but with the single threaded i needed to make a logic. Based on the length of the list of files I passed through I needed to split this files into multiple processes. This meant sending the processing part little lists of the files based on the amount of threads I was going to be using. This is to distribute the load because other wise the whole process of multi-threading would be use-less. 


## Complexity
Single-Threaded
```
Complexity: O(n * L * k * m)
```
- n = Number of files to process
- L = Number of lines per file (average)
- k = Number of tokens per line (average)  
- m = Number of pattern

Multi-threaded
```
Complexity: O((n/t) * L * k * m) + O(n)
```
- n = Number of files to process
- L = Number of lines per file (average)
- k = Number of tokens per line (average)  
- m = Number of pattern


## Reflection
This technology isn't magic but it does make things faster. But how faster? As we saw Amdahls law is a limit where not everything can be parallelized, there are things that will always run on a single thread but is our job as coders to make it as efficient as possible. We have already reached some limits in terms of CPU speeds, we are not making faster CPUs but bigger, just stacking them on top of each other. It is very important we understand how to parallelize for this specific reason. CPUs won't be able to process information or tasks faster but we can split this tasks so we take advantage of the stacking process I was talking about.   