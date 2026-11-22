"""Exercise the real connect functions across their nested Bash scopes."""
import pathlib
import subprocess
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]


class ProviderCredentials(unittest.TestCase):
    setup_status = 'disabled'

    def test_model_credential_survives_gateway_admin_login(self):
        text = (ROOT / 'up.sh').read_text()
        functions = []
        for name in ['as_gateway_admin', 'connect_cmd', 'connect_provider']:
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
die() { printf '%s\n' "$*" >&2; exit 1; }
ok() { :; }
fake_cli() {
  if [[ ${1:-} == -g ]]; then shift 2; fi
  case "$*" in
    'gateway add '*) mkdir -p "$HOME/.config/openshell/gateways/ekka-agent-desks"; printf '{"gateway_endpoint":"%s","auth_mode":"oidc","oidc_issuer":"%s","oidc_client_id":"%s"}' "$3" "$7" "$9" > "$HOME/.config/openshell/gateways/ekka-agent-desks/metadata.json" ;;
    'gateway login '*) return 0 ;;
    'provider get '*) return 1 ;;
    'provider create '*)
      [[ $OPENSHELL_OIDC_CLIENT_SECRET == gateway-login-test-value ]] || return 98
      printf '%s' "${!CREDENTIAL_ENV}" > "$CAPTURE"
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
                                          'SETUP_STATUS': self.setup_status},
                                     capture_output=True, text=True)
                if self.setup_status != 'disabled':
                    # The key IS set, but the session could not confirm its setup client off: the operator is told
                    # what to check, never that the key was not set.
                    self.assertEqual(out.returncode, 1)
                    self.assertEqual((root / 'captured').read_text(), 'model-credential-test-value')
                    self.assertIn('may have been set', out.stderr)
                    self.assertNotIn('was not set', out.stderr)
                    continue
                self.assertEqual(out.returncode, 0, out.stderr)
                self.assertEqual((root / 'captured').read_text(), 'model-credential-test-value')
                self.assertNotIn('model-credential-test-value', out.stdout + out.stderr)
                self.assertNotIn('gateway-login-test-value', out.stdout + out.stderr)


class AKeySetWhileTheSessionCouldNotClose(ProviderCredentials):
    """The same connect, with the setup client still reading back enabled at the end of the session (70)."""
    setup_status = 'enabled'

