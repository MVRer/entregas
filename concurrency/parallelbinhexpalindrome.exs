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

  def bin_hex_palindrome_counter({start, stop}) do
    palindromes =
      start..stop
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

  defp rangemaker(div, rem, 1, starter, stopper) do
    [headstop | _tail2] = stopper
    newstarter = [headstop + 1 | starter]
    newstopper = [headstop + div + rem | stopper]
    Enum.reverse(Enum.zip(newstarter, newstopper))
  end

  defp rangemaker(div, rem, tasks, starter, stopper) do
    [headstop | _tail2] = stopper
    newstarter = [headstop + 1 | starter]
    newstopper = [headstop + div | stopper]
    rangemaker(div, rem, tasks - 1, newstarter, newstopper)
  end

  def rangemaker(number, tasks) do
    div = div(number, tasks)
    rem = rem(number, tasks)
    rangemaker(div, rem, tasks - 1, [0], [div])
  end

  def taskmaker(number, tasks) do
    rangemaker(:math.pow(2, number) |> trunc(), tasks)
    |> Enum.map(&Task.async(fn -> bin_hex_palindrome_counter(&1) end))
    |> Enum.map(&Task.await(&1, :infinity))
    |> Enum.sum()
  end
end

# IO.write("Enter a number: ")
# n = IO.read(:line) |> String.trim() |> String.to_integer()

# limit = :math.pow(2, n) |> trunc()
# count = Parallelism.bin_hex_palindrome_counter(limit)
# IO.puts("\nTotal bin-hex palindromes: #{count}")
