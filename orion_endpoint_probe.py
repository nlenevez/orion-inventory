#!/usr/bin/env python3
"""
orion_endpoint_probe.py

Finds the SWIS endpoint on an Orion server when the expected one gives
a 404.

Self-contained: this file plus `requests`, nothing else from the repo.
Copy it across on its own.

READ-ONLY. Every request is either a GET or a SELECT-only SWQL query.

## Why this exists

A 404 means something answered on that port but did not recognise the
path. That is a routing question, and there are several things it could
be -- wrong port, a version that moved the path, a reverse proxy in
front, or SWIS simply not running on the host being asked. Guessing one
at a time costs a round trip across the airgap for each guess.

So this tries the whole matrix in one run and reports what each
combination actually answered: status, Server header, content type, and
the first bytes of the body. That is usually enough to identify what is
listening, even when none of the combinations works.

Reading the results:

  * **200 with JSON** -- that is the endpoint. Use its port with
    --port, and if the path differs from the default, say so and the
    client gets updated.
  * **404 with an HTML body / an IIS or nginx Server header** -- a real
    web server is there but SWIS is not at that path. Look at which
    paths return something other than 404.
  * **404 with an empty body** -- often a listener that is not
    HTTP-aware in the way expected, or a proxy swallowing it.
  * **401 on any row** -- promising: the path exists and authentication
    is being demanded. Fix credentials rather than paths.
  * **Connection refused / timeout everywhere** -- nothing is listening;
    SWIS may not be installed on this host, or is firewalled. SWIS is a
    separate listener from the Orion web UI, so the UI working tells
    you nothing about it.

## Usage

    read -rs ORION_PASSWORD && export ORION_PASSWORD
    python3 orion_endpoint_probe.py --host orion.example.com \\
        --username ansible --password-env ORION_PASSWORD --insecure

Add --output results.txt to save it for carrying back.
"""

import argparse
import getpass
import json
import sys
import urllib3

import requests

#: Ports SWIS has been served on, current first. 17774 is the REST
#: endpoint from Orion 2023.1 onward; 17778 is where it lived up to
#: 2022.4.1 and is deprecated (but often still answers, which is why a
#: wrong-port failure presents as a 404 rather than a refused
#: connection). The rest are neighbours worth identifying.
CANDIDATE_PORTS = [17774, 17778, 17777, 443]

#: Paths to try. The first is what the client currently uses. The rest
#: cover version differences, casing, and deployments that reverse-proxy
#: SWIS behind the main web server.
CANDIDATE_PATHS = [
    "/SolarWinds/InformationService/v3/Json/Query",
    "/SolarWinds/InformationService/v3/json/Query",
    "/SolarWinds/InformationService/Json/Query",
    "/InformationService/v3/Json/Query",
    "/api/SolarWinds/InformationService/v3/Json/Query",
    "/SolarWinds/InformationService/v3/Json/",
    "/SolarWinds/InformationService/",
    "/",
]

#: The cheapest possible valid query -- if a path answers this with a
#: 200 and JSON, it is the endpoint.
PROBE_SWQL = "SELECT TOP 1 NodeID FROM Orion.Nodes"


def describe(resp):
    """Compresses a response into the few things that identify what
    answered: status, who says it is serving, what it sent back."""
    server = resp.headers.get("Server", "")
    ctype = resp.headers.get("Content-Type", "").split(";")[0]
    body = (resp.text or "").strip().replace("\n", " ").replace("\r", "")
    if len(body) > 160:
        body = body[:160] + "..."
    if not body:
        body = "(empty body)"
    return resp.status_code, server, ctype, body


def probe(session, url, auth, verify, timeout, method):
    try:
        if method == "POST":
            resp = session.post(url, json={"query": PROBE_SWQL}, auth=auth,
                                verify=verify, timeout=timeout,
                                headers={"Accept": "application/json"})
        else:
            resp = session.get(url, params={"query": PROBE_SWQL}, auth=auth,
                               verify=verify, timeout=timeout,
                               headers={"Accept": "application/json"})
    except requests.exceptions.SSLError as e:
        return None, "TLS", "", f"{type(e).__name__}: {str(e)[:120]}"
    except requests.exceptions.ConnectTimeout:
        return None, "timeout", "", "connect timed out"
    except requests.exceptions.ConnectionError as e:
        reason = str(e)
        if "refused" in reason.lower():
            return None, "refused", "", "connection refused"
        return None, "conn-error", "", reason[:120]
    except requests.RequestException as e:
        return None, "error", "", f"{type(e).__name__}: {str(e)[:120]}"
    return describe(resp)


def main():
    parser = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--host", required=True)
    parser.add_argument("--username", required=True)
    parser.add_argument("--password-env", default=None)
    parser.add_argument("--insecure", action="store_true")
    parser.add_argument("--timeout", type=int, default=10,
                        help="Per-request, seconds (default 10). Kept short "
                             "-- this runs many requests and a dead port "
                             "should not stall the whole matrix.")
    parser.add_argument("--ports", default=None,
                        help="Comma-separated ports, overriding the defaults "
                             f"({','.join(str(p) for p in CANDIDATE_PORTS)})")
    parser.add_argument("--output", default=None)
    args = parser.parse_args()

    import os
    if args.password_env:
        password = os.environ.get(args.password_env)
        if password is None:
            raise SystemExit(f"${args.password_env} is not set")
    else:
        password = getpass.getpass(f"Orion password for {args.username}: ")

    if args.insecure:
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    ports = ([int(p) for p in args.ports.split(",")] if args.ports
             else CANDIDATE_PORTS)

    auth = (args.username, password)
    session = requests.Session()
    lines = []

    def emit(text=""):
        print(text)
        lines.append(text)

    emit(f"Probing {args.host} for a SWIS endpoint")
    emit(f"query: {PROBE_SWQL}")
    emit()

    hits = []
    for port in ports:
        emit(f"=== port {port} " + "=" * 46)
        for path in CANDIDATE_PATHS:
            for method in ("POST", "GET"):
                url = f"https://{args.host}:{port}{path}"
                status, server, ctype, body = probe(
                    session, url, auth, not args.insecure, args.timeout, method)

                label = f"  {method:<4} {path:<48}"
                if status is None:
                    emit(f"{label} -- {server}: {body}")
                    # A dead port fails identically for every path, so
                    # stop hammering it after the first definitive
                    # connection-level failure.
                    if server in ("refused", "timeout"):
                        emit(f"  (port {port} is not accepting connections "
                             f"-- skipping its remaining paths)")
                        break
                    continue

                note = f"{status}"
                if server:
                    note += f" server={server}"
                if ctype:
                    note += f" type={ctype}"
                emit(f"{label} -> {note}")
                emit(f"       body: {body}")

                if status == 200 and "json" in ctype.lower():
                    hits.append((port, path, method))
                elif status == 401:
                    hits.append((port, path, method, "401"))
            else:
                continue
            break
        emit()

    emit("=" * 60)
    working = [h for h in hits if len(h) == 3]
    challenged = [h for h in hits if len(h) == 4]

    if working:
        emit("FOUND a working endpoint:")
        for port, path, method in working:
            emit(f"  {method} https://{args.host}:{port}{path}")
        port, path, _ = working[0]
        emit()
        emit("Run the device query against it with:")
        emit(f"  python3 orion_devices.py --host {args.host} --port {port} \\")
        emit(f"      --username {args.username} --insecure --format json")
        if path != CANDIDATE_PATHS[0]:
            emit()
            emit(f"NOTE: the working path is {path}, not the default")
            emit(f"{CANDIDATE_PATHS[0]}. SWIS_BASE_PATH in orion_client.py "
                 f"needs updating -- send this output back.")
    elif challenged:
        emit("No endpoint returned data, but these demanded authentication,")
        emit("which means the path exists -- the credentials are the problem,")
        emit("not the URL:")
        for port, path, method, _ in challenged:
            emit(f"  {method} https://{args.host}:{port}{path}")
        emit()
        emit("AD accounts need the DOMAIN\\user form, and the account must be")
        emit("an Orion individual account with API access.")
    else:
        emit("NOTHING answered with data on any port/path combination.")
        emit()
        emit("Read the rows above rather than concluding from this line:")
        emit("  * all 'refused' -> SWIS is not listening on this host. It is a")
        emit("    separate service from the Orion web UI, so a working UI does")
        emit("    not imply it is running or reachable here.")
        emit("  * 404s with an HTML body / IIS or nginx Server header -> a web")
        emit("    server is there but SWIS is not behind it at these paths.")
        emit("  * TLS errors -> re-run with --insecure.")
        emit()
        emit("Send this whole output back; it says what IS there, which is")
        emit("more useful than another guess at what should be.")

    if args.output:
        with open(args.output, "w", encoding="utf-8") as handle:
            handle.write("\n".join(lines) + "\n")
        print(f"\nWritten to {args.output}")

    return 0 if working else 1


if __name__ == "__main__":
    sys.exit(main())
