defmodule Parallelism do

  def is_palindrome(str) do
    str == String.reverse(str)
  end


  def to_binary(0), do: "0"

  def to_binary(n) when n > 0 do
    Integer.to_string(n, 2)
  end


  def to_hex(0), do: "0"

  def to_hex(n) when n > 0 do
    Integer.to_string(n, 16) |> String.downcase()
  end


  def bin_hex_palindrome_counter(limit) do

    palindromes =
      0..limit
      |> Enum.filter(fn i ->
        binary = to_binary(i)
        hex = to_hex(i)

        if is_palindrome(binary) and is_palindrome(hex) do
          IO.puts("Number: #{i} | Binary: #{binary} | Hex: #{hex}")
          true
        else
          false
        end
      end)

    length(palindromes)
  end

  def print_palindromes(palindromes) do
    IO.puts("Bin-hex palindromes:\n")

    Enum.each(palindromes, fn i ->
      binary = to_binary(i)
      hex = to_hex(i)
      IO.puts("Number: #{i} | Binary: #{binary} | Hex: #{hex}")
    end)

    length(palindromes)
  end
end

IO.write("Enter a number: ")
n = IO.read(:line) |> String.trim() |> String.to_integer()

limit = :math.pow(2, n) |> trunc()
count = Parallelism.bin_hex_palindrome_counter(limit)
IO.puts("\nTotal bin-hex palindromes: #{count}")
