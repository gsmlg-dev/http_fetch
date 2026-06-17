[
  # Dialyzer loses the Task.Supervisor.async_nolink/4 return shape in HTTP.fetch/2
  ~r/lib\/http\.ex:259.*invalid_contract/,
  ~r/lib\/http\.ex:260.*no_return/,

  # HTTP.Promise.then/3 opaque type issue with Task struct - Task.Supervisor returns opaque Task
  ~r/lib\/http\/promise\.ex:96.*contract_with_opaque/
]
