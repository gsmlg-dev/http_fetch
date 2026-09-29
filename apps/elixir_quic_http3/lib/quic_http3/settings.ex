defmodule QuicHttp3.Settings do
  @moduledoc "HTTP/3 SETTINGS codec facade for the application layer."

  alias HTTP.H3.Settings, as: CoreSettings

  @type setting_id :: CoreSettings.setting_id()
  @type setting :: CoreSettings.setting()
  @type settings :: CoreSettings.settings()

  defdelegate qpack_max_table_capacity(), to: CoreSettings
  defdelegate max_field_section_size(), to: CoreSettings
  defdelegate qpack_blocked_streams(), to: CoreSettings
  defdelegate enable_connect_protocol(), to: CoreSettings
  defdelegate h3_datagram(), to: CoreSettings
  defdelegate wt_enabled(), to: CoreSettings
  defdelegate wt_initial_max_streams_uni(), to: CoreSettings
  defdelegate wt_initial_max_streams_bidi(), to: CoreSettings
  defdelegate wt_initial_max_data(), to: CoreSettings
  defdelegate name(setting_id), to: CoreSettings
  defdelegate id(setting), to: CoreSettings
  defdelegate normalize(settings), to: CoreSettings
  defdelegate validate(settings), to: CoreSettings
  defdelegate encode(settings), to: CoreSettings
  defdelegate encode!(settings), to: CoreSettings
  defdelegate decode(payload), to: CoreSettings
end
