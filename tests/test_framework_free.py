"""The persistence types import without Litestar installed (#3)."""

import subprocess
import sys
import textwrap

_BLOCK_LITESTAR = textwrap.dedent(
    """
    import sys
    sys.modules["litestar"] = None  # any `import litestar` now raises ImportError
    """
)


def run_without_litestar(code: str) -> subprocess.CompletedProcess[str]:
    script = _BLOCK_LITESTAR + textwrap.dedent(code)
    return subprocess.run(  # noqa: S603 (a fixed script and our own interpreter)
        [sys.executable, "-I", "-c", script], capture_output=True, text=True, check=False
    )


def test_persistence_types_import_without_litestar() -> None:
    result = run_without_litestar(
        """
        from litestar_oauth_server.models import CodeRecord, TokenKind, TokenRecord
        from litestar_oauth_server.stores import ClientStore, CodeStore, TokenStore
        from litestar_oauth_server import AuthorizationServer, OAuthConfig, in_memory_stores
        """
    )
    assert result.returncode == 0, result.stderr


def test_litestar_names_need_litestar_only_when_used() -> None:
    result = run_without_litestar(
        """
        import litestar_oauth_server as pkg
        try:
            pkg.LitestarOAuth
        except ImportError:
            print("needs-litestar")
        """
    )
    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == "needs-litestar"


def test_litestar_names_still_resolve_from_the_package() -> None:
    import litestar_oauth_server as pkg

    assert callable(pkg.bearer_guard)
    assert pkg.LitestarOAuth.__name__ == "LitestarOAuth"
    assert "LitestarOAuth" in pkg.__all__


def test_an_unknown_name_is_an_attribute_error() -> None:
    import litestar_oauth_server as pkg

    assert not hasattr(pkg, "no_such_name")
