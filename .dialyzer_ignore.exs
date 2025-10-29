[
  # HTTP.fetch/2 uses throw/catch for error handling which confuses Dialyzer
  ~r/lib\/http\.ex:231.*invalid_contract/,
  ~r/lib\/http\.ex:232.*no_return/,

  # Pattern match warning in handle_async_request - intentional error handling
  ~r/lib\/http\.ex:329.*pattern_match/,

  # HTTP.Promise.then/3 opaque type issue with Task struct - Task.Supervisor returns opaque Task
  ~r/lib\/http\/promise\.ex:96.*contract_with_opaque/,

  # HTTP.Request.to_httpc_args/1 returns list not tuple - by design for :httpc.request
  ~r/lib\/http\/request\.ex:96.*invalid_contract/,

  # HTTP.Response.read_all/1 call in text/1 - protected by pattern matching
  ~r/lib\/http\/response\.ex:95.*call/
]
