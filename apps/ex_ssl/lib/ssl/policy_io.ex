defmodule SSL.PolicyIO do
  @moduledoc false
  alias SSL.PKIX.CertificateSignaturePolicy
  alias SSL.PKIX.OCSP
  alias SSL.PKIX.PartialChain
  alias SSL.PKIX.Revocation
  alias SSL.PolicyIO.Bounded
  alias SSL.PolicyIO.FileExecutor

  alias SSL.PolicyIO.Guard

  defmodule Context do
    @moduledoc false
    @derive {Inspect, only: []}
    defstruct [:observer, :capability, :deadline, :status_request, :nonce, private: false]
  end

  def install(nil, owner, deadline) do
    if remaining(deadline) > 0 do
      with {:ok, pid} <- GenServer.start(Guard, {self(), owner, deadline}) do
        case request(pid, :context, deadline) do
          {:ok, context} -> {:ok, %{context | private: true}}
          error -> error
        end
      end
    else
      {:error, :deadline_exceeded}
    end
  end

  def install(%{receipt: receipt}, _owner, deadline),
    do: request(receipt.observer, :policy_context, deadline)

  def call(%Context{} = context, operation),
    do: request(context.observer, {:policy, context.capability, operation}, context.deadline)

  def finish(nil), do: :ok

  def finish(%Context{private: true} = context) do
    monitor = Process.monitor(context.observer)

    case call(context, :finish) do
      :ok ->
        receive do
          {:DOWN, ^monitor, :process, pid, :normal} when pid == context.observer -> :ok
        after
          min(1_000, remaining(context.deadline)) -> {:error, :acceptance_unconfirmed}
        end

      error ->
        Process.demonitor(monitor, [:flush])
        error
    end
  end

  def finish(context), do: call(context, :finish)

  def retire(%Context{private: true} = context), do: call(context, :retire)

  def read_file(context, path) when is_binary(path) or is_list(path) do
    with {:ok, actor, capability, generation} <- call(context, :file),
         {:ok, bytes} <-
           FileExecutor.read(actor, capability, path, context.deadline),
         :ok <- settled(context, generation) do
      {:ok, bytes}
    else
      {:error, :enoent, generation} ->
        with :ok <- settled(context, generation), do: {:error, :enoent}

      {:error, _} = error ->
        error
    end
  end

  def settled(context, generation) do
    case call(context, {:settled, generation}) do
      :pending ->
        receive do
        after
          min(1, remaining(context.deadline)) -> settled(context, generation)
        end

      result ->
        result
    end
  end

  def request(pid, operation, deadline) do
    timeout = min(1_000, remaining(deadline))

    if timeout > 0,
      do: GenServer.call(pid, {operation, {:abs_ms, now() + timeout}}, timeout),
      else: {:error, :deadline_exceeded}
  catch
    :exit, _ -> {:error, :acceptance_unconfirmed}
  end

  def remaining(:infinity), do: 0xFFFFFFFF
  def remaining(deadline), do: max(0, deadline - now())
  def now, do: System.monotonic_time(:millisecond)
  def enabled?(%{policy: policy}), do: policy != nil

  def fail!(reason)
      when reason in [:policy_capacity, :invalid_policy_material, :policy_io_failed] do
    Process.put({__MODULE__, :failure}, reason)
    throw(reason)
  end

  def prepare(%{policy: nil}, _lifecycle, _owner, _deadline), do: {:ok, nil, nil}

  def prepare(options, lifecycle, owner, deadline) do
    with {:ok, context} <- install(lifecycle, owner, deadline) do
      Process.put({__MODULE__, :budget}, %{bytes: 0, nodes: 0, paths: 0})
      Process.delete({__MODULE__, :failure})
      {nonce, request} = OCSP.request(options.policy.stapling)
      context = %{context | status_request: request, nonce: nonce}

      verifier = fn chain, trust, identity, mode, opts, protocol ->
        verify_policy(context, options.policy, chain, trust, identity, mode, opts, protocol)
      end

      {:ok, context, verifier}
    end
  end

  def profile_context(nil, context), do: context
  def profile_context(%Context{status_request: nil}, context), do: context

  def profile_context(%Context{status_request: request}, context),
    do: Map.put(context, :status_request, request)

  def material(der, type \\ :generic) do
    with {:ok, nodes} <- Bounded.der(der, type),
         :ok <- charge(:bytes, byte_size(der), 33_554_432),
         do: charge(:nodes, nodes, 65_536)
  end

  def charge(kind, count, limit) do
    budget = Process.get({__MODULE__, :budget}, %{bytes: 0, nodes: 0, paths: 0})
    total = budget[kind] + count

    if total <= limit do
      Process.put({__MODULE__, :budget}, Map.put(budget, kind, total))
      :ok
    else
      {:error, :policy_capacity}
    end
  end

  def path_budget do
    budget = Process.get({__MODULE__, :budget}, %{paths: 0})
    max(0, 4_096 - budget.paths)
  end

  defp verify_policy(context, policy, chain, trust, identity, mode, options, protocol) do
    alias SSL.PKIX.VerifyFun

    with true <- remaining(context.deadline) > 0,
         :ok <- preflight_chain(chain),
         {:ok, certificates} <- SSL.PKIX.decode_chain(chain),
         {:ok, peer} <-
           SSL.PKIX.peer(
             chain,
             [],
             nil,
             :verify_none,
             Keyword.take(options, [:certificate_signature_schemes]),
             protocol
           ),
         {:ok, anchors} <- policy_trust(trust),
         {:ok, candidates} <- PartialChain.candidates(certificates, anchors) do
      if mode == :verify_none and
           not VerifyFun.enabled?(Keyword.get(options, :verify_fun, :undefined)) do
        {:ok, peer}
      else
        with {:ok, selections} <- select_candidates(context, policy.partial_chain, candidates) do
          authorization = {anchors, Enum.uniq_by(certificates ++ anchors, & &1.der)}

          verify_selections(selections, context, policy, authorization, identity, options, peer)
        end
      end
    else
      false -> {:error, :deadline_exceeded}
      error -> error
    end
  catch
    :throw, :policy_capacity -> {:error, :policy_capacity}
    _, _ -> {:error, :policy_validation_failed}
  end

  defp verify_selected(context, policy, selected, authorization, identity, options, peer) do
    if remaining(context.deadline) > 0 do
      {anchor, path} = selected
      callback = policy_callback(context, policy, selected, authorization, identity, options)
      root = if is_atom(anchor), do: anchor, else: anchor.der
      ders = path |> Enum.map(& &1.der) |> Enum.reverse()

      result =
        :public_key.pkix_path_validation(root, ders,
          max_path_length: Keyword.get(options, :depth, 10),
          verify_fun: callback
        )

      result =
        case Process.get({__MODULE__, :failure}) do
          nil -> result
          reason -> {:policy_failure, reason}
        end

      selected_result(result, context, policy, selected, authorization, identity, options, peer)
    else
      {:halt, {:error, :deadline_exceeded}}
    end
  end

  defp policy_callback(context, policy, selected, authorization, identity, options) do
    alias SSL.PKIX.VerifyFun

    hostname = fn certificate ->
      identity == nil or
        :public_key.pkix_verify_hostname(
          certificate,
          [identity],
          Keyword.get(options, :customize_hostname_check, [])
        )
    end

    {user, initial} = VerifyFun.wrap(Keyword.get(options, :verify_fun, :undefined), hostname)

    status = fn certificate, der, event ->
      certificate_status(
        context,
        policy,
        certificate,
        der,
        event,
        selected,
        authorization,
        options
      )
    end

    verify = fn certificate, der, event, state ->
      if policy.stapling == nil and event in [:valid, :valid_peer] and
           VerifyFun.enabled?(Keyword.get(options, :verify_fun, :undefined)) do
        callback_before_status(user, status, certificate, der, event, state)
      else
        actual =
          if event in [:valid, :valid_peer], do: status.(certificate, der, event), else: event

        user.(certificate, der, actual, state)
      end
    end

    {verify, initial}
  end

  defp callback_before_status(user, status, certificate, der, event, state) do
    case user.(certificate, der, event, state) do
      {accepted, next} when accepted in [:valid, :valid_peer] ->
        actual = status.(certificate, der, event)
        if actual == event, do: {accepted, next}, else: user.(certificate, der, actual, next)

      other ->
        other
    end
  end

  defp selected_result({:policy_failure, reason}, _, _, _, _, _, _, _),
    do: {:halt, {:error, reason}}

  defp selected_result(
         {:ok, _},
         context,
         policy,
         selected,
         authorization,
         identity,
         options,
         peer
       ) do
    {anchor, path} = selected
    schemes = Keyword.get(options, :certificate_signature_schemes)

    with :ok <- selected_leaf_checks(context, policy, selected, authorization, identity, options),
         true <-
           remaining(context.deadline) > 0 and
             (schemes == nil or
                CertificateSignaturePolicy.compatible?(
                  Enum.map(path, & &1.der),
                  if(is_atom(anchor), do: nil, else: anchor.der),
                  schemes
                )) do
      {:halt, {:ok, peer}}
    else
      {:error, _} = error -> {:cont, error}
      _ -> {:halt, {:error, :policy_validation_failed}}
    end
  end

  defp selected_result({:error, reason}, _, _, _, _, _, _, _),
    do: {:cont, {:error, {:path_validation_failed, sanitize_policy(reason)}}}

  # OTP selects each candidate before path verification starts. Admission is
  # charged once here; verification consumes these exact selections without
  # replaying callbacks or resetting the shared attempt budget.
  defp select_candidates(context, callback, candidates) do
    result =
      Enum.reduce_while(candidates, {:ok, []}, fn candidate, {:ok, selected} ->
        with true <- remaining(context.deadline) > 0,
             :ok <- charge(:paths, 1, 4_096) do
          choice = partial_selection(callback, candidate)

          if remaining(context.deadline) > 0,
            do: {:cont, {:ok, [PartialChain.select(candidate, choice) | selected]}},
            else: {:halt, {:error, :deadline_exceeded}}
        else
          false -> {:halt, {:error, :deadline_exceeded}}
          error -> {:halt, error}
        end
      end)

    case result do
      {:ok, selected} -> {:ok, Enum.reverse(selected)}
      error -> error
    end
  end

  defp selected_leaf_checks(
         context,
         policy,
         {anchor, []} = selected,
         authorization,
         identity,
         options
       )
       when not is_atom(anchor) do
    with :ok <- SSL.PKIX.verify_selected_leaf(anchor, identity, options),
         :valid_peer <-
           certificate_status(
             context,
             policy,
             anchor.decoded,
             anchor.der,
             :valid_peer,
             selected,
             authorization,
             options
           ) do
      :ok
    else
      {:bad_cert, _} = reason -> {:error, {:path_validation_failed, sanitize_policy(reason)}}
      error -> error
    end
  end

  defp selected_leaf_checks(_, _, _, _, _, _), do: :ok

  defp certificate_status(
         context,
         %{stapling: nil} = policy,
         certificate,
         der,
         event,
         selected,
         {_anchors, pool},
         options
       ),
       do:
         Revocation.check(
           context,
           policy,
           certificate,
           der,
           event,
           selected,
           pool,
           options
         )

  defp certificate_status(
         context,
         _policy,
         certificate,
         der,
         event,
         selected,
         {anchors, _pool},
         options
       ),
       do:
         OCSP.check(
           certificate,
           der,
           event,
           selected,
           anchors,
           Keyword.get(options, :policy_staples, []),
           context.nonce
         )

  defp preflight_chain(chain) do
    with {:ok, ders} <- Bounded.list(chain, 128) do
      preflight_ders(ders)
    end
  end

  defp preflight_ders(ders) do
    Enum.reduce_while(ders, :ok, fn der, :ok ->
      case material(der) do
        :ok -> {:cont, :ok}
        error -> {:halt, error}
      end
    end)
  end

  defp policy_trust(source) when source in [nil, []], do: {:ok, []}

  defp policy_trust(source) do
    with {:ok, ders} <- Bounded.trust(source),
         :ok <- preflight_ders(ders),
         do: SSL.PKIX.normalize_trust(ders)
  end

  defp partial_selection(nil, _), do: :unknown_ca
  defp partial_selection(_, {:selfsigned_peer, _}), do: :unknown_ca

  defp partial_selection(callback, candidate) do
    candidate
    |> PartialChain.full_path()
    |> Enum.map(& &1.der)
    |> Enum.reverse()
    |> callback.()
  catch
    _, _ -> :unknown_ca
  end

  defp sanitize_policy({:bad_cert, {:revoked, reason}}) when is_atom(reason),
    do: {:bad_cert, {:revoked, reason}}

  defp sanitize_policy({:bad_cert, {reason, _}}) when reason == :revocation_status_undetermined,
    do: {:bad_cert, :revocation_status_undetermined}

  defp sanitize_policy({:bad_cert, reason}) when is_atom(reason), do: {:bad_cert, reason}

  defp sanitize_policy({:verify_fun, reason})
       when reason in [:rejected, :invalid_return, :exception],
       do: {:verify_fun, reason}

  defp sanitize_policy(_), do: :policy_validation_failed

  defp verify_selections(selections, context, policy, authorization, identity, options, peer) do
    Enum.reduce_while(
      selections,
      {:error, {:path_validation_failed, :unknown_ca}},
      fn selected, _previous ->
        verify_selected(context, policy, selected, authorization, identity, options, peer)
      end
    )
  end
end

defmodule SSL.PolicyIO.Bounded do
  @moduledoc false
  import Bitwise
  @maximum 16_777_216
  @nodes 65_536

  def list(value, limit), do: list(value, limit, [])
  defp list([], _, acc), do: {:ok, Enum.reverse(acc)}
  defp list([_ | _], 0, _), do: {:error, :policy_capacity}
  defp list([item | rest], left, acc), do: list(rest, left - 1, [item | acc])
  defp list(_, _, _), do: {:error, :invalid_policy_material}

  def trust(source) when is_list(source) do
    with {:ok, entries} <- list(source, 4_096) do
      Enum.reduce_while(entries, {:ok, []}, fn entry, {:ok, acc} ->
        der =
          case entry do
            {:cert, bytes, _} -> bytes
            bytes -> bytes
          end

        case der(der) do
          {:ok, _} -> {:cont, {:ok, [der | acc]}}
          error -> {:halt, error}
        end
      end)
      |> case do
        {:ok, ders} -> {:ok, Enum.reverse(ders)}
        error -> error
      end
    end
  end

  def trust(pem) when is_binary(pem) and byte_size(pem) <= 8_388_608 do
    with :ok <- pem_count(pem, 4_096),
         {:ok, entries} <- list(:public_key.pem_decode(pem), 4_096) do
      entries |> Enum.map(fn {:Certificate, der, :not_encrypted} -> der end) |> trust()
    end
  catch
    _, _ -> {:error, :invalid_policy_material}
  end

  def trust(_), do: {:error, :policy_capacity}

  def pem_count(pem, limit) do
    case :binary.match(pem, "-----BEGIN") do
      :nomatch ->
        :ok

      _ when limit == 0 ->
        {:error, :policy_capacity}

      {offset, size} ->
        <<_::binary-size(^offset + ^size), rest::binary>> = pem
        pem_count(rest, limit - 1)
    end
  end

  def der(der, type \\ :generic)

  def der(der, type) when is_binary(der) and byte_size(der) <= @maximum do
    with {:ok, count} <- scan(der, 0, 0), :ok <- typed(der, type), do: {:ok, count}
  end

  def der(_, _), do: {:error, :policy_capacity}

  defp scan(<<>>, _, count), do: {:ok, count}
  defp scan(_, depth, _) when depth > 32, do: {:error, :policy_capacity}
  defp scan(_, _, count) when count >= @nodes, do: {:error, :policy_capacity}

  defp scan(bytes, depth, count) do
    with {:ok, tag, value, rest} <- tlv(bytes),
         :ok <- extension_count(tag, value),
         {:ok, count} <-
           if((tag &&& 0x20) != 0,
             do: scan(value, depth + 1, count + 1),
             else: {:ok, count + 1}
           ),
         {:ok, count} <- embedded(tag, value, depth, count) do
      scan(rest, depth, count)
    end
  end

  defp embedded(0x30, value, depth, count) do
    case extension_payload(value) do
      {:ok, payload} -> scan(payload, depth + 1, count)
      :none -> {:ok, count}
    end
  end

  defp embedded(_, _, _, count), do: {:ok, count}

  defp extension_payload(bytes) do
    with {:ok, 6, oid, rest} <- tlv(bytes),
         true <- match?(<<85, 29, _::binary>>, oid) or oid == <<43, 6, 1, 5, 5, 7, 48, 1, 1>>,
         {:ok, 4, payload, <<>>} <- tlv(skip_boolean(rest)) do
      {:ok, payload}
    else
      _ -> :none
    end
  end

  defp skip_boolean(<<1, 1, _value, rest::binary>>), do: rest
  defp skip_boolean(rest), do: rest

  defp extension_count(0x30, value) do
    case tlv(value) do
      {:ok, 0x30, first, _} ->
        if extension_shape?(first), do: count_children(value, 128), else: :ok

      _ ->
        :ok
    end
  end

  defp extension_count(_, _), do: :ok

  defp extension_shape?(bytes) do
    with {:ok, 6, _, rest} <- tlv(bytes),
         {:ok, 4, _, <<>>} <- tlv(skip_boolean(rest)),
         do: true,
         else: (_ -> false)
  end

  defp typed(bytes, :ocsp) do
    with {:ok, 0x30, body, <<>>} <- tlv(bytes),
         {:ok, 10, status, rest} <- tlv(body) do
      if status == <<0>> do
        with {:ok, 0xA0, explicit, <<>>} <- tlv(rest),
             {:ok, 0x30, response_bytes, <<>>} <- tlv(explicit),
             {:ok, 6, _oid, encoded} <- tlv(response_bytes),
             {:ok, 4, basic, <<>>} <- tlv(encoded),
             do: typed(basic, :basic_ocsp)
      else
        :ok
      end
    end
  end

  defp typed(bytes, :basic_ocsp) do
    with {:ok, 0x30, body, <<>>} <- tlv(bytes),
         {:ok, 0x30, response_data, rest} <- tlv(body),
         {:ok, fields} <- children(response_data, 6),
         fields = if(match?([{0xA0, _} | _], fields), do: tl(fields), else: fields),
         [{_, _}, {24, _}, {0x30, responses} | _] <- fields,
         :ok <- count_children(responses, 128),
         {:ok, remainder} <- children(rest, 3) do
      case List.last(remainder) do
        {0xA0, certificates} ->
          with {:ok, 0x30, values, <<>>} <- tlv(certificates), do: count_children(values, 32)

        _ ->
          :ok
      end
    else
      {:error, _} = error -> error
      _ -> {:error, :invalid_policy_material}
    end
  end

  defp typed(_, _), do: :ok

  defp count_children(bytes, limit) do
    case children(bytes, limit) do
      {:ok, _} -> :ok
      error -> error
    end
  end

  defp children(bytes, limit), do: children(bytes, limit, [])
  defp children(<<>>, _, acc), do: {:ok, Enum.reverse(acc)}
  defp children(_, 0, _), do: {:error, :policy_capacity}

  defp children(bytes, left, acc) do
    with {:ok, tag, value, rest} <- tlv(bytes), do: children(rest, left - 1, [{tag, value} | acc])
  end

  defp tlv(<<tag, length, rest::binary>>) when (tag &&& 31) != 31 and length < 128,
    do: value(tag, length, rest)

  defp tlv(<<tag, length, rest::binary>>) when (tag &&& 31) != 31 and length in 0x81..0x84 do
    count = length - 128

    if byte_size(rest) >= count do
      <<size::binary-size(^count), tail::binary>> = rest

      if :binary.first(size) == 0,
        do: {:error, :invalid_policy_material},
        else: value(tag, :binary.decode_unsigned(size), tail)
    else
      {:error, :invalid_policy_material}
    end
  end

  defp tlv(_), do: {:error, :invalid_policy_material}

  defp value(tag, length, bytes) when byte_size(bytes) >= length do
    <<value::binary-size(^length), rest::binary>> = bytes
    {:ok, tag, value, rest}
  end

  defp value(_, _, _), do: {:error, :invalid_policy_material}
end
