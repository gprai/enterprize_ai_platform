"""Feature tests for exact identity and tag-plus-native inventory composition."""

from __future__ import annotations

from datetime import UTC, datetime

import pytest
from tools.platformctl.aws_inventory import NativeReadSpec, ServiceIdentifier
from tools.platformctl.aws_live import Boto3AwsInventoryProvider, BoundedNativeReader
from tools.platformctl.contracts import ContractError

from tests.fakes.platform_lifecycle import FakeNativeServiceLister, FakeStsClient


def test_exact_owner_identity_is_required_before_native_inventory() -> None:
    sts = FakeStsClient()
    lister = FakeNativeServiceLister()
    provider = Boto3AwsInventoryProvider(
        client_factory=lambda _service, _region: sts,
        native_lister=lister,
        region="ap-southeast-1",
        account_id="526338061652",
        caller_arn="arn:aws:iam::526338061652:user/finopsinfra",
    )
    identity = provider.verify_identity()
    assert identity.account_id == "526338061652"
    assert identity.region == "ap-southeast-1"
    assert provider.list_service_resources(ServiceIdentifier.S3) == ()
    assert lister.calls == [ServiceIdentifier.S3]


def test_wrong_aws_caller_stops_before_inventory() -> None:
    sts = FakeStsClient(arn="arn:aws:iam::526338061652:user/unapproved")
    lister = FakeNativeServiceLister()
    provider = Boto3AwsInventoryProvider(
        client_factory=lambda _service, _region: sts,
        native_lister=lister,
        region="ap-southeast-1",
        account_id="526338061652",
        caller_arn="arn:aws:iam::526338061652:user/finopsinfra",
    )
    with pytest.raises(ContractError, match="does not match"):
        provider.list_service_resources(ServiceIdentifier.S3)
    assert lister.calls == []


def test_native_denial_is_not_absence() -> None:
    class DeniedClient:
        def describe_log_groups(self, **arguments: object) -> dict[str, object]:
            del arguments
            raise RuntimeError("synthetic denied read")

    sts = FakeStsClient()
    provider = Boto3AwsInventoryProvider(
        client_factory=lambda _service, _region: sts,
        native_lister=FakeNativeServiceLister(),
        region="ap-southeast-1",
        account_id="526338061652",
        caller_arn="arn:aws:iam::526338061652:user/finopsinfra",
    )
    reader = BoundedNativeReader(provider, lambda _service, _region: DeniedClient())
    spec = NativeReadSpec(
        "aws_cloudwatch_log_group.fixture",
        "aws_cloudwatch_log_group",
        "logs",
        "describe_log_groups",
        "{}",
        "logGroups",
        "nextToken",
        "nextToken",
        2,
        10,
        "fixture",
        "logGroupName",
    )
    result = reader.inspect(spec)
    assert result.presence == "INDETERMINATE"
    assert result.reason_code == "NATIVE_READ_UNAVAILABLE"


@pytest.mark.parametrize(
    "response",
    [
        {"logGroups": [], "nextToken": "next-page"},
        {"logGroups": [], "IsTruncated": True},
        {"logGroups": [], "NextKeyMarker": "next-key"},
    ],
)
def test_unmodelled_continuation_never_proves_absence(response: dict[str, object]) -> None:
    class PagedClient:
        calls = 0

        def describe_log_groups(self, **arguments: object) -> dict[str, object]:
            del arguments
            self.calls += 1
            return response

    sts = FakeStsClient()
    provider = Boto3AwsInventoryProvider(
        client_factory=lambda _service, _region: sts,
        native_lister=FakeNativeServiceLister(),
        region="ap-southeast-1",
        account_id="526338061652",
        caller_arn="arn:aws:iam::526338061652:user/finopsinfra",
    )
    client = PagedClient()
    reader = BoundedNativeReader(provider, lambda _service, _region: client)
    spec = NativeReadSpec(
        "aws_cloudwatch_log_group.fixture",
        "aws_cloudwatch_log_group",
        "logs",
        "describe_log_groups",
        "{}",
        "logGroups",
        None,
        None,
        2,
        10,
        "fixture",
        "logGroupName",
    )
    result = reader.inspect(spec)
    assert result.presence == "INDETERMINATE"
    assert result.reason_code == "NATIVE_PAGINATION_INCOMPLETE"
    assert client.calls == 1


def test_native_kms_deadline_is_the_service_date_not_verification_plus_seven_days() -> None:
    deadline = datetime(2026, 9, 15, tzinfo=UTC)

    class KeyClient:
        def describe_key(self, **arguments: object) -> dict[str, object]:
            assert arguments == {"KeyId": "fixture-key"}
            return {
                "KeyMetadata": {
                    "KeyId": "fixture-key",
                    "KeyState": "PendingDeletion",
                    "DeletionDate": deadline,
                }
            }

    provider = Boto3AwsInventoryProvider(
        client_factory=lambda _service, _region: FakeStsClient(),
        native_lister=FakeNativeServiceLister(),
        region="ap-southeast-1",
        account_id="526338061652",
        caller_arn="arn:aws:iam::526338061652:user/finopsinfra",
    )
    reader = BoundedNativeReader(provider, lambda _service, _region: KeyClient())
    spec = NativeReadSpec(
        "aws_kms_key.fixture",
        "aws_kms_key",
        "kms",
        "describe_key",
        '{"KeyId":"fixture-key"}',
        "KeyMetadata",
        None,
        None,
        1,
        1,
        "fixture-key",
        "KeyId",
    )
    result = reader.inspect(spec)
    assert result.scheduled_deletion_at == "2026-09-15T00:00:00Z"
    assert result.key_state == "PendingDeletion"


def test_native_identity_join_does_not_invent_arns_or_merge_regions() -> None:
    from tools.platformctl.aws_live import native_identity_key

    arn = "arn:aws:ec2:ap-southeast-1:526338061652:vpc/vpc-fixture"
    assert native_identity_key("ec2", arn) == native_identity_key("ec2", "vpc-fixture")
    with pytest.raises(ContractError):
        native_identity_key("ec2", arn.replace("ap-southeast-1", "us-east-1"))


def test_native_configuration_checks_do_not_equate_boolean_with_integer() -> None:
    class BucketClient:
        def get_public_access_block(self, **arguments: object) -> dict[str, object]:
            del arguments
            return {"PublicAccessBlockConfiguration": {"BlockPublicAcls": 1}}

    provider = Boto3AwsInventoryProvider(
        client_factory=lambda _service, _region: FakeStsClient(),
        native_lister=FakeNativeServiceLister(),
        region="ap-southeast-1",
        account_id="526338061652",
        caller_arn="arn:aws:iam::526338061652:user/finopsinfra",
    )
    reader = BoundedNativeReader(provider, lambda _service, _region: BucketClient())
    spec = NativeReadSpec(
        "aws_s3_bucket_public_access_block.fixture",
        "aws_s3_bucket_public_access_block",
        "s3",
        "get_public_access_block",
        '{"Bucket":"fixture-bucket","ExpectedBucketOwner":"526338061652"}',
        "PublicAccessBlockConfiguration",
        None,
        None,
        1,
        1,
        "fixture-bucket",
        "",
    )
    result = reader.inspect(spec, expected_fields={"BlockPublicAcls": True})
    assert result.configuration.value == "FAIL"
