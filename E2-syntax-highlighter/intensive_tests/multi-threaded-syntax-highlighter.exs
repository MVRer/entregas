# Programming language parser for elixir
# This is a very basic non-context syntax highlighter
# Made by Mariano Carretero
# A01029708
# May 6, 2025

defmodule Filework do
  # This is a comment
  @moduledoc "A basic syntax highlighter for Elixir code that generates HTML output. "

  defp tokenfinderhelper([[pattern, type] | tail], string) do
    find = Regex.run(pattern, string)

    cond do
      find == nil -> tokenfinderhelper(tail, string)
      find != nil -> [find, type]
    end
  end

  defp tokenfinderhelper([], string) do
    [string, :notfound]
  end

  defp tokenfinder([], _token_patterns, acc) do
    Enum.reverse(acc)
  end

  defp tokenfinder(line, token_patterns, acc) do
    [found, type] = tokenfinderhelper(token_patterns, line)

    found_str = if is_list(found), do: hd(found), else: found

    fixed_str =
      found_str
      |> String.replace("&", "&amp;")
      |> String.replace("<", "&lt;")
      |> String.replace(">", "&gt;")
      |> String.replace("\"", "&quot;")

    found_length = String.length(found_str)

    if found_length == 0 do
      Enum.reverse(acc)
    else
      {_useless, splitted} = String.split_at(line, found_length)

      tokenfinder(splitted, token_patterns, [
        "<span class=\"#{type}\">" <> fixed_str <> "</span>" | acc
      ])
    end
  end

  def tokenidentifier(in_filepath) do
    token_patterns = [
      [~r/^~r(\/[^\/]*\/|\{[^\}]*\}|\[[^\]]*\]|\([^\)]*\)|"[^"]*"|'[^']*')/, :regex],
      [~r/^\s+/, :whitespace],
      [~r/^\b(0x[0-9a-fA-F]+|0o[0-7]+|0b[01]+|\d+\.\d+([eE][+-]?\d+)?|\d+)\b/, :number],
      [~r/^"""[^"]*?/, :string],
      [~r/^"([^"\\]|\\.)*"|^"""([\s\S]*?)"""/, :string],
      [~r/^\b(do|else|catch|rescue|after)\s*:/, :keyword],
      [~r/^(\w+)(?=\s*:)/, :object_key],
      [
        ~r/^\b(after|and|catch|cond|def|defp|defmodule|defprotocol|defimpl|defmacro|defmacrop|defdelegate|defexception|defstruct|defoverridable|do|else|end|fn|for|if|in|import|quote|raise|receive|rescue|require|reraise|super|throw|try|unless|unquote|use|when|with|not|or)\b/,
        :reserved_word
      ],
      [~r/^\b([a-z_][a-zA-Z0-9_?!]*)(?=\s*\()/, :function],
      [~r/^\b([a-z_][a-zA-Z0-9_?!]*)\b/, :variable],
      [~r/^[\(\)\{\}\[\],;\.]/, :punctuation],
      [~r/^\b(true|false|nil)\b/, :boolean],
      [~r/^#.*$/m, :comment],
      [~r/^(&|\+|-|\*|\/|==|!=|<=|>=|<|>|=|&&|\|\||!|\+\+|--|<>|\|>|~>|\||in|\^)/, :operator],
      [~r/^@(moduledoc|doc)\s+("""[\s\S]*?"""|"[^"]*")/, :docstring],
      [~r/^@([a-zA-Z_][a-zA-Z0-9_]*)/, :special],
      [
        ~r/^\b(Integer|Float|String|Atom|List|Map|Tuple|Boolean|Function|PID|Port|Reference)\b/,
        :data_type
      ],
      [~r/^@([A-Z][A-Z0-9_]*)\b/, :constant],
      [~r/^\b(import|require|use|alias)\s+([A-Z][A-Za-z0-9_\.]*)/, :library],
      [
        ~r/^~[a-z](?:"""[\s\S]*?"""|"[^"]*"|'[^']*'|\([\s\S]*?\)|\[[\s\S]*?\]|\{[\s\S]*?\}|\/[^\/]*\/)/,
        :sigil
      ],
      [~r/^\b([A-Z][A-Za-z0-9_]*)(\.[A-Z][A-Za-z0-9_]*)*\b/, :module],
      [~r/^:([\w@]+|"[^"]*")/, :atom]
    ]

    html_content =
      in_filepath
      |> File.stream!()
      |> Enum.map(&tokenfinder(&1, token_patterns, []))
      |> Enum.map(&Enum.join(&1, ""))
      |> Enum.join("")

    html = """
    <!DOCTYPE html>
    <html>
      <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <link rel="stylesheet" href="colors.css">
        <title>Document</title>
      </head>
      <body>
        <pre>#{html_content}</pre>
      </body>
    </html>
    """

    File.write("#{in_filepath}.html", html)
  end

  defp dispatcher([]), do: IO.puts("Finished processing file")

  defp dispatcher([head | tail]) do
    tokenidentifier(head)
    dispatcher(tail)
  end

  defp rangemaker(files, div, rem, 1, acc) do
    # IO.inspect(acc)
    start_index = length(acc) * div
    last_chunk = Enum.slice(files, start_index, div + rem)
    [last_chunk | acc] |> Enum.reverse()
  end

  defp rangemaker(files, div, rem, tasks, acc) do
    start_index = length(acc) * div
    chunk = Enum.slice(files, start_index, div)
    rangemaker(files, div, rem, tasks - 1, [chunk | acc])
  end

  def rangemaker(files, tasks) do
    total_files = length(files)
    div = div(total_files, tasks)
    rem = rem(total_files, tasks)
    rangemaker(files, div, rem, tasks, [])
  end

  def taskmaker(files, tasks) do
    rangemaker(files, tasks)
    |> Enum.map(&Task.async(fn -> dispatcher(&1) end))
    |> Enum.map(&Task.await(&1, :infinity))

    IO.puts("Finished processing all tasks")
  end
end


{time_microseconds, _result} = :timer.tc(fn ->
  Filework.taskmaker([
    "pesado1.exs",
    "pesado2.exs",
    "pesado3.exs",
    "pesado4.exs",
    "pesado5.exs",
    "pesado6.exs",
    "pesado7.exs",
    "pesado8.exs"
  ], 8)
end)

IO.puts("Execution time: #{time_microseconds / 1_000_000} seconds")
