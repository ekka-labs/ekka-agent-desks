"""EKKA-branded host CLI; early machine-control slice of issue #912."""
import argparse
import os
import sys

from .runtime import HostError, Runtime, stack_change, status
from .settlement import recover
from .images import pull
from . import registry
from .gateway import emergency_stop

DESK_COMMANDS = {"connect": "ekka desk connect", "invite": "ekka desk people invite",
                 "revoke": "ekka desk people revoke", "grant": "ekka desk grant",
                 "ask": "ekka desk ask", "create": "ekka desk create",
                 "delete": "ekka desk delete", "policy": "ekka desk policy"}


def parser():
    cli = argparse.ArgumentParser(prog="ekka-desk-host", description=(
        "EKKA desks host administration. This preview supports the existing default installation only. "
        "Installation, upgrades and named instances are not implemented yet."))
    commands = cli.add_subparsers(dest="command", required=True)
    commands.add_parser("status", help="check the Enclave, desks service and interceptor socket")
    emergency = commands.add_parser("emergency-stop", help="request one named desk stop when governed control is unreachable")
    emergency.add_argument("desk")
    stack = commands.add_parser("stack", help="start or stop the host's desks service")
    actions = stack.add_subparsers(dest="verb", required=True)
    actions.add_parser("start", help="start the desks service")
    actions.add_parser("stop", help="stop the desks service")
    for verb in ("settle", "unhold"):
        recovery = commands.add_parser(verb, help="recover one unfinished desk change (restarts the default gateway)" if verb == "settle" else "remove one recovery hold after checking the desk")
        recovery.add_argument("desk")
        recovery.add_argument("--operation", required=True)
        if verb == "settle":
            recovery.add_argument("--backend-id")
    image = commands.add_parser("image", help="pull an immutable desk image onto the host")
    image_actions = image.add_subparsers(dest="verb", required=True)
    image_pull = image_actions.add_parser("pull", help="pull by digest, optionally checking a signing identity")
    image_pull.add_argument("reference")
    image_pull.add_argument("--signed-by")
    image_pull.add_argument("--issuer")
    registries = commands.add_parser("registry", help="keep or remove a private image-pull credential")
    registry_actions = registries.add_subparsers(dest="verb", required=True)
    registry_login = registry_actions.add_parser("login", help="validate and keep a credential from hidden input or stdin")
    registry_login.add_argument("host")
    registry_login.add_argument("user")
    registry_actions.add_parser("show", help="list hosts and usernames, never credentials")
    registry_logout = registry_actions.add_parser("logout", help="remove the local credential for one host")
    registry_logout.add_argument("host")
    return cli


def main(argv=None, runtime=None, uid=None):
    args = sys.argv[1:] if argv is None else list(argv)
    if args and args[0] in DESK_COMMANDS:
        print("ekka-desk-host: this is a desk action; use " + DESK_COMMANDS[args[0]] +
              ". Host administration does not run desk actions.", file=sys.stderr)
        return 2
    options = parser().parse_args(args)
    if (os.geteuid() if uid is None else uid) != 0:
        print("ekka-desk-host: run this host command with sudo", file=sys.stderr)
        return 1
    runtime = Runtime() if runtime is None else runtime
    try:
        if options.command == "status":
            status(runtime)
        elif options.command == "emergency-stop":
            emergency_stop(runtime, options.desk)
        elif options.command == "stack":
            stack_change(runtime, options.verb)
        elif options.command == "image":
            pull(runtime, options.reference, options.signed_by, options.issuer)
        elif options.command == "registry":
            if options.verb == "login":
                registry.login(runtime, options.host, options.user)
            elif options.verb == "show":
                registry.show(runtime)
            else:
                registry.logout(runtime, options.host)
        else:
            recover(runtime, options.command, options.desk, options.operation,
                    getattr(options, "backend_id", None))
        return 0
    except (HostError, OSError) as error:
        print("ekka-desk-host: " + str(error), file=sys.stderr)
        return 1
