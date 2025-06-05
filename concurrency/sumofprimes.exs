# Sum of primes
defmodule Parallelism do

  def is_prime(n) when n <= 1, do: false
  def is_prime(2), do: true

  def is_prime(n) do
    limit = :math.sqrt(n) |> :math.ceil() |> trunc()
    not Enum.any?(2..limit, fn i -> rem(n, i) == 0 end)
  end


  def sum_of_primes(n) do
    1..n
    |> Enum.filter(&is_prime/1)
    |> Enum.sum()
  end


  def sum_of_primes_recursive(n) do
    sum_of_primes_recursive(1, n, 0)
  end

  defp sum_of_primes_recursive(i, n, sum) when i > n, do: sum

  defp sum_of_primes_recursive(i, n, sum) do
    if is_prime(i) do
      sum_of_primes_recursive(i + 1, n, sum + i)
    else
      sum_of_primes_recursive(i + 1, n, sum)
    end
  end

end
IO.write("Enter number: ")
input = IO.read(:line) |> String.trim() |> String.to_integer()
result = Parallelism.sum_of_primes(input)
IO.puts("Sum of primes: #{result}")
