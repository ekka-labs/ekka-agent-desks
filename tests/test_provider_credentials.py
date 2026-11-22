"""Exercise the real connect functions across their nested Bash scopes."""
import pathlib
import subprocess
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]


class ProviderCredentials(unittest.TestCase):
    setup_status = 'disabled'
    home_stays = False
    call_exit = 0

    def test_model_credential_survives_gateway_admin_login(self):
        text = (ROOT / 'up.sh').read_text()
        functions = []
        for name in ['as_gateway_admin', 'session_left_open', 'connect_cmd', 'connect_provider']:
            if name + '() {' not in text:
                continue   # an older up.sh without it: what connect_cmd then does is what is measured
            start = text.index(name + '() {')
            functions.append(text[start:text.index('\n}\n', start) + 3])
        for env_name in ['ANTHROPIC_API_KEY', 'GITHUB_TOKEN']:
            with self.subTest(env_name=env_name), tempfile.TemporaryDirectory() as temp:
                root = pathlib.Path(temp)
                script = 'set -uo pipefail\n' + '\n'.join(functions) + r'''
install_cli() { :; }
openssl() { return 0; }
kc() { if [[ $2 == on ]]; then printf 'c-setup\n%s' gateway-login-test-value; elif [[ $2 == status ]]; then echo "${SETUP_STATUS:-disabled}"; fi; }
profile_names() { printf 'claude-code\n'; }
profile_source() { printf profile; }
python3() {
  case $1 in
    tools/provider_connect.py) [[ $2 == keyless ]] && return 1; printf '%s\n' "$CREDENTIAL_ENV" ;;
    tools/openshell_allow.py) return 0 ;;
    -c) command python3 "$@" ;;   # as_gateway_admin's lock, run for real
    *) return 99 ;;
  esac
}
step_desk_grant() { :; }
# HOME_STAYS: the sign-in folder is removed at the start of the session, and cannot be removed at its end.
rm() { if [[ ${HOME_STAYS:-} == 1 && -e $DESKS_STATE/rm-once ]]; then return 1; fi; : > "$DESKS_STATE/rm-once"; command rm "$@"; }
die() { printf '%s\n' "$*" >&2; exit 1; }
ok() { :; }
fake_cli() {
  if [[ ${1:-} == -g ]]; then shift 2; fi
  case "$*" in
    'gateway add '*) mkdir -p "$HOME/.config/openshell/gateways/ekka-agent-desks"; printf '{"gateway_endpoint":"%s","auth_mode":"oidc","oidc_issuer":"%s","oidc_client_id":"%s"}' "$3" "$7" "$9" > "$HOME/.config/openshell/gateways/ekka-agent-desks/metadata.json" ;;
    'gateway login '*) [[ -e $HOME/.config/openshell/gateways/ekka-agent-desks/metadata.json ]] ;;
    'provider get '*) return 1 ;;
    'provider create '*)
      [[ $OPENSHELL_OIDC_CLIENT_SECRET == gateway-login-test-value ]] || return 98
      printf '%s' "${!CREDENTIAL_ENV}" > "$CAPTURE"
      return "${CALL_EXIT:-0}"
      ;;
    *) return 97 ;;
  esac
}
OS=fake_cli
NAME=localhost
printf '%s' model-credential-test-value | connect_cmd claude-code
'''
                out = subprocess.run(['bash', '-c', script], cwd=ROOT,
                                     env={'PATH': '/usr/bin:/bin', 'DESKS_STATE': str(root),
                                          'CAPTURE': str(root / 'captured'), 'CREDENTIAL_ENV': env_name,
                                          'SETUP_STATUS': self.setup_status,
                                          'HOME_STAYS': '1' if self.home_stays else '',
                                          'CALL_EXIT': str(self.call_exit)},
                                     capture_output=True, text=True)
                if self.call_exit:
                    # The call itself failed and the session closed cleanly: a failed call, nothing about the session.
                    self.assertEqual(out.returncode, 1)
                    self.assertIn('was not set', out.stderr)
                    self.assertNotIn('did not close', out.stderr)
                    continue
                if self.setup_status != 'disabled' or self.home_stays:
                    # The key IS set, but the session did not close cleanly: the operator is told what to check,
                    # never that the key was not set, and never more than was seen.
                    self.assertEqual(out.returncode, 1)
                    self.assertEqual((root / 'captured').read_text(), 'model-credential-test-value')
                    self.assertIn('may have been set', out.stderr)
                    self.assertNotIn('was not set', out.stderr)
                    if self.home_stays:
                        self.assertIn('could not be removed', out.stderr)
                        self.assertNotIn('not confirmed', out.stderr, 'a setup client read back as off was doubted')
                    continue
                self.assertEqual(out.returncode, 0, out.stderr)
                self.assertEqual((root / 'captured').read_text(), 'model-credential-test-value')
                self.assertNotIn('model-credential-test-value', out.stdout + out.stderr)
                self.assertNotIn('gateway-login-test-value', out.stdout + out.stderr)


class AKeySetWhileTheSessionCouldNotClose(ProviderCredentials):
    """The same connect, with the setup client still reading back enabled at the end of the session (70)."""
    setup_status = 'enabled'


class AKeySetWhileTheSignInFolderStayed(ProviderCredentials):
    """The same connect, with the setup client read back off but the sign-in folder left on disk (70)."""
    home_stays = True


class ACallThatExitsWithTheSessionsOwnNumber(ProviderCredentials):
    """NVIDIA's CLI exits 70 on its own, and the session closed cleanly: not a session left open."""
    call_exit = 70
