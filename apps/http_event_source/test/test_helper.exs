ExUnit.start(exclude: [:integration, :e2e])
Application.ensure_all_started(:http_event_source)
