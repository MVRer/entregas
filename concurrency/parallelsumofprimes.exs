# Sum of primes
defmodule Parallelism do
  def is_prime(n) when n <= 1, do: false
  def is_prime(2), do: true

  def is_prime(n) do
    limit = :math.sqrt(n) |> :math.ceil() |> trunc()
    not Enum.any?(2..limit, fn i -> rem(n, i) == 0 end)
  end

  def sum_of_primes({start, stop}) do
    start..stop
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
    rangemaker(number, tasks)
    |> Enum.map(&Task.async(fn -> sum_of_primes(&1) end))
    |> Enum.map(&Task.await(&1, :infinity))
    |> Enum.sum()
  end
end

# IO.write("Enter number: ")
# input = IO.read(:line) |> String.trim() |> String.to_integer()
# result = Parallelism.sum_of_primes(input)
# IO.puts("Sum of primes: #{result}")
