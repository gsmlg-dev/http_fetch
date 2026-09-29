defmodule HTTP.HTTP2.ResponseSemanticsTest do
  use ExUnit.Case, async: true
  alias HTTP.HTTP2.StreamState

  defp stream(method \\ :get) do
    {:ok, stream} = StreamState.new(1, request_method: method) |> StreamState.open()
    {:ok, stream} = StreamState.send_headers(stream, true)
    stream
  end

  test "HEAD and 304 representation lengths allow empty DATA and trailers" do
    for {method, status} <- [{:head, "200"}, {:get, "304"}] do
      headers = [{":status", status}, {"content-length", "123"}]

      {:ok, current, :final} =
        StreamState.receive_response_headers(stream(method), headers, false)

      assert {:ok, _} = StreamState.receive_response_data(current, 0, true)
      assert {:ok, _, :trailers} = StreamState.receive_response_headers(current, [], true)
      assert {:error, :body_forbidden} = StreamState.receive_response_data(current, 1, true)
    end
  end

  test "204 and informational responses prohibit Content-Length" do
    for status <- ["100", "103", "204"] do
      assert {:error, :invalid_content_length} =
               StreamState.receive_response_headers(
                 stream(),
                 [{":status", status}, {"content-length", "0"}],
                 false
               )
    end
  end

  test "trailer Content-Length and surrounding header whitespace are invalid" do
    {:ok, current, :final} =
      StreamState.receive_response_headers(stream(), [{":status", "200"}], false)

    assert {:error, :invalid_response_trailers} =
             StreamState.receive_response_headers(current, [{"content-length", "0"}], true)

    for value <- [" leading", "trailing ", "\ttab"] do
      assert {:error, :invalid_response_headers} =
               StreamState.receive_response_headers(
                 stream(),
                 [{":status", "200"}, {"x-name", value}],
                 true
               )
    end
  end

  test "Content-Length retains the existing unsigned 64-bit range" do
    headers = [{":status", "200"}, {"content-length", "18446744073709551615"}]
    assert {:ok, _, :final} = StreamState.receive_response_headers(stream(), headers, false)

    assert {:error, :invalid_content_length} =
             StreamState.receive_response_headers(
               stream(),
               List.keyreplace(
                 headers,
                 "content-length",
                 0,
                 {"content-length", "18446744073709551616"}
               ),
               false
             )
  end
end
