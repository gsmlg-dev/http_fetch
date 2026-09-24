#!/usr/bin/env python3
"""Serve one prior-knowledge HTTP/2 request with the independent hyper-h2 codec."""

import argparse
import json
import socket
from pathlib import Path

from h2.config import H2Configuration
from h2.connection import H2Connection
from h2.events import DataReceived, RequestReceived, StreamEnded


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--port", type=int, default=0)
    parser.add_argument("--port-file", required=True)
    args = parser.parse_args()

    configuration = H2Configuration(client_side=False, header_encoding="utf-8")
    connection = H2Connection(config=configuration)

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listener.bind(("127.0.0.1", args.port))
        listener.listen(1)
        Path(args.port_file).write_text(str(listener.getsockname()[1]), encoding="ascii")
        print(json.dumps({"port": listener.getsockname()[1]}), flush=True)

        client, _ = listener.accept()
        with client:
            client.settimeout(10)
            connection.initiate_connection()
            client.sendall(connection.data_to_send())

            responded = False
            while not responded:
                data = client.recv(65_535)
                if not data:
                    raise RuntimeError("client_closed_before_response")

                for event in connection.receive_data(data):
                    if isinstance(event, DataReceived):
                        connection.acknowledge_received_data(
                            event.flow_controlled_length, event.stream_id
                        )

                    if isinstance(event, RequestReceived):
                        headers = dict(event.headers)
                        path = headers.get(":path", "/")
                        body = f"independent:{path}".encode("utf-8")
                        response_headers = [
                            (":status", "200"),
                            ("content-type", "text/plain"),
                            ("content-length", str(len(body))),
                            ("x-peer", "hyper-h2-4.2.0"),
                        ]
                        connection.send_headers(
                            event.stream_id, response_headers, end_stream=False
                        )
                        connection.send_data(event.stream_id, body, end_stream=True)
                        client.sendall(connection.data_to_send())
                        print(
                            json.dumps(
                                {
                                    "request_path": path,
                                    "request_headers_decoded_by": "hyper-h2-4.2.0",
                                    "response_body": body.decode("utf-8"),
                                }
                            ),
                            flush=True,
                        )
                        responded = True

                    if isinstance(event, StreamEnded) and not responded:
                        client.sendall(connection.data_to_send())


if __name__ == "__main__":
    main()
