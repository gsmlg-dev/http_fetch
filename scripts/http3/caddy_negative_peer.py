"""Certificate-valid QUIC peer with an incompatible ALPN for fail-closed checks."""
import argparse
import asyncio
from aioquic.asyncio import serve
from aioquic.quic.configuration import QuicConfiguration


async def main(args):
    configuration = QuicConfiguration(is_client=False, alpn_protocols=["doq"])
    configuration.load_cert_chain(args.cert, args.key)
    peer = await serve("127.0.0.1", 0, configuration=configuration)
    print(peer._transport.get_extra_info("sockname")[1], flush=True)
    await asyncio.Future()


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("cert")
    parser.add_argument("key")
    asyncio.run(main(parser.parse_args()))
