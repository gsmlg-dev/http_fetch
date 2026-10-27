defmodule SSL.Lifecycle.NativePolicyCloseTest do
  use ExUnit.Case, async: false
  @moduletag :integration
  @moduletag :tmp_dir

  for scenario <- ["cancel", "deadline", "actor_down", "ack_loss", "late_ack"] do
    test "native file close keeps truthful evidence through #{scenario}", %{tmp_dir: directory} do
      scenario = unquote(scenario)
      File.write!(Path.join(directory, "policy"), "native policy close")
      config = Path.join(directory, "config.json")

      File.write!(
        config,
        JSON.encode!(%{
          directory: Path.expand(directory),
          scenario: scenario,
          erlang_root: :code.root_dir() |> List.to_string(),
          erts_version: :erlang.system_info(:version) |> List.to_string(),
          code_paths: Enum.map(:code.get_path(), &List.to_string/1)
        })
      )

      python = System.find_executable("python3")
      assert python, "native-close integration requires an existing Python 3 runtime"
      support = Path.expand("../../support/native_file_close.py", __DIR__)
      {output, exit} = System.cmd(python, ["-B", support, config], stderr_to_stdout: true)
      assert exit == 0, output

      assert %{
               "result" => "PASS",
               "scenario" => ^scenario,
               "native_close" => true,
               "child_exit" => 0,
               "child_joined" => true
             } = JSON.decode!(output)
    end
  end
end
