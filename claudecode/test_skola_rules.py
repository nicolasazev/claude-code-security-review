"""Testes das mudanças do branch `skola` do fork (issue 662 do Skola).

As regras fixas não descartam achado das categorias do Skola (instruções da
revisão em `.md`, dado de outra conta), e a leitura de arquivo do filtro fica
dentro do repositório.
"""

import pytest

from claudecode.claude_api_client import ClaudeAPIClient
from claudecode.findings_filter import HardExclusionRules


class TestReviewInstructionMarkdown:
    @pytest.mark.parametrize('file_path', [
        '.github/revisao-de-seguranca.md',
        '.github/filtro-de-falsos-positivos.md',
        './.github/revisao-de-seguranca.md',
    ])
    def test_review_instruction_file_is_not_excluded(self, file_path):
        finding = {
            'file': file_path,
            'title': 'Review instructions drop the RLS category',
            'description': 'The edit removes the rule that flags tables without RLS.',
        }

        assert HardExclusionRules.get_exclusion_reason(finding) is None

    def test_review_instruction_file_by_absolute_path_is_not_excluded(self, tmp_path, monkeypatch):
        monkeypatch.setenv('REPO_PATH', str(tmp_path))
        finding = {
            'file': str(tmp_path / '.github' / 'revisao-de-seguranca.md'),
            'description': 'The edit removes the rule that flags tables without RLS.',
        }

        assert HardExclusionRules.get_exclusion_reason(finding) is None

    @pytest.mark.parametrize('file_path', [
        'README.md',
        'docs/revisao-de-seguranca.md',
        '.github/PULL_REQUEST_TEMPLATE.md',
        '.github/../README.md',
    ])
    def test_other_markdown_is_still_excluded(self, file_path):
        finding = {'file': file_path, 'description': 'SQL injection vulnerability'}

        reason = HardExclusionRules.get_exclusion_reason(finding)

        assert reason is not None
        assert 'markdown' in reason.lower()


class TestCrossAccountResourceLeak:
    @pytest.mark.parametrize('finding', [
        {
            'title': 'Cross-account local database leak after sign-out',
            'description': 'The SQLite file keeps the previous family rows.',
        },
        {
            'title': 'Database leak between users',
            'description': 'Another user sees the lessons of the other account on the same device.',
        },
        {
            'title': 'Connection leak exposes another family',
            'description': 'The cached session keeps data of a different family.',
        },
        {
            'title': 'Database leak na troca de conta',
            'description': 'O SQLite mantém os dados de outra família.',
        },
        {'title': 'Database leak: local SQLite keeps lesson rows after the user logs out'},
        {'title': 'Database leak after the user signed out'},
        {'title': 'Database leak when switching accounts on the same device'},
        {'title': "Database leak: the next user who signs in sees the last family's lessons"},
        {'title': 'Connection leak: PowerSync keeps syncing the old account after logging out'},
        {'title': 'Database leak across families on a shared device'},
        {'title': 'database leak depois de sair da conta'},
        {'title': 'Database leak', 'description': 'Os dados da família anterior ficam visíveis.'},
        {'title': 'Database leak entre contas no mesmo aparelho'},
        {'title': 'Database leak', 'description': 'A conta anterior continua no SQLite.'},
        {'title': 'Database leak ao deslogar'},
        {'title': 'Database leak: the new user sees the former account data'},
        {'title': 'Database leak: data of the previous signed-in family remains'},
        {'title': "SQLite database leak: previous parent's children visible to the next guardian"},
        {'title': 'Database leak: the last household stays on the device'},
    ])
    def test_leak_of_another_account_data_is_not_excluded(self, finding):
        assert HardExclusionRules.get_exclusion_reason(finding) is None

    @pytest.mark.parametrize('finding', [
        {'title': 'Database connection leak', 'description': 'PostgreSQL connections not returned to pool'},
        {'title': 'Socket leak', 'description': 'TCP sockets remain open after errors'},
        {'title': 'Security Issue', 'description': 'Potential memory leak detected'},
    ])
    def test_plain_resource_leak_is_still_excluded(self, finding):
        reason = HardExclusionRules.get_exclusion_reason(finding)

        assert reason is not None
        assert 'Resource management finding' in reason


SECRET = 'ANTHROPIC_API_KEY=sk-ant-nao-deve-aparecer'


@pytest.fixture
def repo(tmp_path, monkeypatch):
    repo_dir = tmp_path / 'repo'
    (repo_dir / 'src').mkdir(parents=True)
    (repo_dir / 'src' / 'app.ts').write_text('export const ok = 1;\n')
    (tmp_path / 'fora').write_text(SECRET)
    monkeypatch.setenv('REPO_PATH', str(repo_dir))
    return repo_dir


@pytest.fixture
def client():
    return ClaudeAPIClient(api_key='chave-de-teste')


def prompt_for(client, file_path):
    finding = {'file': file_path, 'line': 1, 'severity': 'HIGH', 'description': 'x'}
    return client._generate_single_finding_prompt(finding, None, None)


class TestReadFileStaysInRepository:
    @pytest.mark.parametrize('file_path', [
        '/proc/self/environ',
        '../fora',
        'src/../../fora',
    ])
    def test_path_outside_repository_is_refused(self, repo, client, file_path):
        prompt = prompt_for(client, file_path)

        assert SECRET not in prompt
        assert 'outside the repository' in prompt

    def test_absolute_path_outside_repository_is_refused(self, repo, client):
        prompt = prompt_for(client, str(repo.parent / 'fora'))

        assert SECRET not in prompt
        assert 'outside the repository' in prompt

    def test_symlink_inside_repository_pointing_outside_is_refused(self, repo, client):
        (repo / 'link').symlink_to(repo.parent / 'fora')

        prompt = prompt_for(client, 'link')

        assert SECRET not in prompt
        assert 'outside the repository' in prompt

    def test_file_inside_repository_is_read(self, repo, client):
        assert 'export const ok = 1;' in prompt_for(client, 'src/app.ts')
        assert 'export const ok = 1;' in prompt_for(client, str(repo / 'src' / 'app.ts'))
