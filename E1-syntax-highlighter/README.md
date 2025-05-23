# Programming Language Parser for Elixir in Elixir
## Description

This is a basic syntax highligher for Elixir. This project uses regex to find token types and outputs an html file colored according to the found tokens. 

## Usage
``` bash
iex project.exs
```
``` elixir
#Add the file name you want to analyze
Filework.tokenidentifier("FILENAME")

```


## The process behind it
It has a list of regex patterns with its corresponding atom to help in identifying each word as what it supossed to be.
For example:
- ` [~r/^:([\w@]+|"[^"]*")/, :atom]`

1. It reads the file and streams it line by line, calling the private function tokenfinder function for each line. 
2. Tokenfinder will start calling the private function  tokenfinderhelper passing the line and regex which will call itself until it identifies the regex expresion by running the whole list or regex through the line. 
3. Tokenfinderhelper will then return the word found with the atom to the corresponding token type.
4. Tokenfinder will split_at the line, by length found and add the token with its corresponding html tags using the atom to an acumulator, which will start forming the html file back again.
5. The main tokenidentifier will create the file and output the html.

## Complejidad: 
``` 
Complejidad del programa: O(L * k * m)
tokenfinderhelper/2 (con lista): Constante
tokenfinder/3: O(k * m) + O(k)
tokenidentifier/1: O(L * k * m)
Donde:
m = número de patrones de tokens (25 en este código)
k = número de tokens por línea
L = número de líneas en el archivo


```

## Files
- project.exs
- colors.css
- README.md
