"""The single target transaction: :class:`TargetScope` host allow-listing."""
import pytest

from sitadel.request.scope import TargetScope, host_of


def test_scope_contains_target_and_explicit_hosts():
    scope = TargetScope.from_url("http://target.test/app", ["api.target.test"])
    assert scope.hosts == frozenset({"target.test", "api.target.test"})


def test_scope_allows_same_host_any_scheme_or_port():
    scope = TargetScope.from_url("http://target.test/")
    assert scope.allows("https://target.test:8443/deep/path")
    assert scope.allows("http://target.test/x?y=1")


def test_scope_denies_foreign_host():
    scope = TargetScope.from_url("http://target.test/")
    assert scope.denied("http://evil.example.com/x")
    assert not scope.allows("http://evil.example.com/x")


def test_relative_reference_is_always_in_scope():
    # A host-less reference can only resolve against an in-scope base.
    scope = TargetScope.from_url("http://target.test/")
    assert scope.allows("/api/v1/items")
    assert scope.allows("relative/path")


def test_empty_scope_is_unrestricted_legacy():
    # Url-less construction (tests/direct callers) keeps legacy behavior.
    assert TargetScope().allows("http://anything.example/")
    assert not TargetScope().denied("http://anything.example/")


def test_scope_is_case_insensitive_and_ignores_port():
    assert host_of("http://TARGET.TEST:8080/x") == "target.test"
    scope = TargetScope.from_url("http://target.test/")
    assert scope.allows("http://TARGET.Test/")


def test_with_hosts_extends_the_transaction():
    scope = TargetScope.from_url("http://target.test/").with_hosts(["extra.test"])
    assert scope.hosts == frozenset({"target.test", "extra.test"})
    # Immutability: the original transaction is untouched.
    assert "extra.test" not in TargetScope.from_url("http://target.test/").hosts
