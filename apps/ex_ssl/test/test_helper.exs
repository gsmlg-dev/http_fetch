ExUnit.start(exclude: [:integration])

if result_file = System.get_env("CI_EXUNIT_RESULT_FILE") do
  ExUnit.after_suite(fn results ->
    executed = results.total - results.excluded - results.skipped

    File.write!(
      result_file,
      "executed=#{executed}\nfailures=#{results.failures}\nexcluded=#{results.excluded}\nskipped=#{results.skipped}\n"
    )
  end)
end
