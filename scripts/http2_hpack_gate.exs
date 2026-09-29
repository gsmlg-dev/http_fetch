alias HTTP.HTTP2.HPACK

{encoder, first} =
  HPACK.encode_headers(HPACK.new_encoder(), [{"x-shared", "before"}], indexing: :incremental)

encoder = encoder |> HPACK.set_max_dynamic_size(0) |> HPACK.set_max_dynamic_size(128)
{encoder, second} = HPACK.encode_headers(encoder, [{"x-shared", "after"}], indexing: :incremental)
{_, third} = HPACK.encode_headers(encoder, [{"x-shared", "after"}], indexing: :incremental)
python = System.fetch_env!("HTTP2_PEER_PYTHON")

script = """
import hpack, json, sys
assert hpack.__version__ == '4.1.0'
d = hpack.Decoder()
first, second, third = [bytes.fromhex(s) for s in sys.argv[1:]]
assert d.decode(first) == [('x-shared', 'before')]
d.max_allowed_table_size = 128
assert second[:3] == bytes([0x20, 0x3f, 0x61]), second.hex()
assert d.decode(second) == [('x-shared', 'after')]
assert d.decode(third) == [('x-shared', 'after')]
assert len(third) == 1
print(json.dumps({'result': 'PASS', 'peer': 'hpack', 'version': hpack.__version__, 'cases': ['shared state', 'shrink then grow', 'warm indexed reference']}))
"""

{output, 0} =
  System.cmd(python, ["-c", script | Enum.map([first, second, third], &Base.encode16/1)],
    stderr_to_stdout: true
  )

IO.write(output)
