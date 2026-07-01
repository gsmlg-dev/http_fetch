[
  # Dialyzer loses the Task.Supervisor.async_nolink/4 return shape in HTTP.fetch/2
  ~r/(apps\/http_fetch\/)?lib\/http\.ex:261/,
  ~r/(apps\/http_fetch\/)?lib\/http\.ex:262.*no_return/,

  # HTTP.Promise.then/3 opaque type issue with Task struct - Task.Supervisor returns opaque Task
  ~r/(apps\/http_fetch\/)?lib\/http\/promise\.ex:96.*contract_with_opaque/
]
