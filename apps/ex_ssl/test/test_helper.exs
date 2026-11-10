ExUnit.start(exclude: [:integration, :e2e])

if result_file = System.get_env("CI_EXUNIT_RESULT_FILE") do
  ExUnit.after_suite(fn results ->
    executed = results.total - results.excluded - results.skipped

    File.write!(
      result_file,
      "executed=#{executed}\nfailures=#{results.failures}\nexcluded=#{results.excluded}\nskipped=#{results.skipped}\n"
    )
  end)
end

defmodule SSL.TestStop do
  @moduledoc false

  # Stops a test-owned process; it may be linked to the exiting test process
  # and already shutting down when on_exit runs, which is fine.
  def quietly(pid) do
    if Process.alive?(pid), do: GenServer.stop(pid)
    :ok
  catch
    :exit, _reason -> :ok
  end
end
