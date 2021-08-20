"""Pulumi stack to set up buckets and permission groups."""

import base64
from typing import Optional
import pulumi
import pulumi_gcp as gcp

DOMAIN = 'populationgenomics.org.au'
CUSTOMER_ID = 'C010ys3gt'
REGION = 'australia-southeast1'
ANALYSIS_RUNNER_PROJECT = 'analysis-runner'
CPG_COMMON_PROJECT = 'cpg-common'
ANALYSIS_RUNNER_SERVICE_ACCOUNT = (
    'analysis-runner-server@analysis-runner.iam.gserviceaccount.com'
)
WEB_SERVER_SERVICE_ACCOUNT = 'web-server@analysis-runner.iam.gserviceaccount.com'
ACCESS_GROUP_CACHE_SERVICE_ACCOUNT = (
    'access-group-cache@analysis-runner.iam.gserviceaccount.com'
)
REFERENCE_BUCKET_NAME = 'cpg-reference'
NOTEBOOKS_PROJECT = 'notebooks-314505'
# cromwell-submission-access@populationgenomics.org.au
CROMWELL_ACCESS_GROUP_ID = 'groups/03cqmetx2922fyu'
CROMWELL_RUNNER_ACCOUNT = 'cromwell-runner@cromwell-305305.iam.gserviceaccount.com'
SAMPLE_METADATA_PROJECT = 'sample-metadata'


def main():  # pylint: disable=too-many-locals
    """Main entry point."""

    # Fetch configuration.
    config = pulumi.Config()
    enable_release = config.get_bool('enable_release')
    archive_age = config.get_int('archive_age') or 30

    dataset = pulumi.get_stack()

    organization = gcp.organizations.get_organization(domain=DOMAIN)
    project_id = gcp.organizations.get_project().project_id

    dependency_stacks = {}
    for dependency in config.get_object('depends_on') or ():
        dependency_stacks[dependency] = pulumi.StackReference(dependency)

    def org_role_id(id_suffix: str) -> str:
        return f'{organization.id}/roles/{id_suffix}'

    lister_role_id = org_role_id('StorageLister')
    viewer_creator_role_id = org_role_id('StorageViewerAndCreator')
    viewer_role_id = org_role_id('StorageObjectAndBucketViewer')

    # The Cloud Resource Manager API is required for the Cloud Identity API.
    cloudresourcemanager = gcp.projects.Service(
        'cloudresourcemanager-service',
        service='cloudresourcemanager.googleapis.com',
        disable_on_destroy=False,
    )

    # The Cloud Identity API is required for creating access groups and service accounts.
    cloudidentity = gcp.projects.Service(
        'cloudidentity-service',
        service='cloudidentity.googleapis.com',
        disable_on_destroy=False,
        opts=pulumi.resource.ResourceOptions(depends_on=[cloudresourcemanager]),
    )

    # The Hail service account email addresses associated with the three access levels.
    hail_service_account_test = config.require('hail_service_account_test')
    hail_service_account_standard = config.require('hail_service_account_standard')
    hail_service_account_full = config.require('hail_service_account_full')

    service_accounts = {}
    service_accounts['hail'] = [
        ('test', hail_service_account_test),
        ('standard', hail_service_account_standard),
        ('full', hail_service_account_full),
    ]

    # Create Dataproc and Cromwell service accounts.
    for kind in 'dataproc', 'cromwell':
        service_accounts[kind] = []
        for access_level in 'test', 'standard', 'full':
            account = gcp.serviceaccount.Account(
                f'{kind}-service-account-{access_level}',
                account_id=f'{kind}-{access_level}',
                opts=pulumi.resource.ResourceOptions(depends_on=[cloudidentity]),
            )
            service_accounts[kind].append((access_level, account.email))

    def service_accounts_gen():
        for kind, values in service_accounts.items():
            for access_level, service_account in values:
                yield kind, access_level, service_account

    def bucket_name(kind: str) -> str:
        """Returns the bucket name for the given dataset."""
        return f'cpg-{dataset}-{kind}'

    def create_bucket(name: str, **kwargs) -> gcp.storage.Bucket:
        """Returns a new GCS bucket."""
        return gcp.storage.Bucket(
            name,
            name=name,
            location=REGION,
            uniform_bucket_level_access=True,
            versioning=gcp.storage.BucketVersioningArgs(enabled=True),
            labels={'bucket': name},
            **kwargs,
        )

    def bucket_member(*args, **kwargs):
        """Wraps gcp.storage.BucketIAMMember.

        When resources are renamed, it can be useful to explicitly apply changes in two
        phases: delete followed by create; that's opposite of the default create followed by
        delete, which can end up with missing permissions. To implement the first phase
        (delete), simply change this implementation to a no-op temporarily.
        """
        gcp.storage.BucketIAMMember(*args, **kwargs)

    undelete_rule = gcp.storage.BucketLifecycleRuleArgs(
        action=gcp.storage.BucketLifecycleRuleActionArgs(type='Delete'),
        condition=gcp.storage.BucketLifecycleRuleConditionArgs(
            age=30, with_state='ARCHIVED'
        ),
    )

    main_upload_account = gcp.serviceaccount.Account(
        'main-upload-service-account',
        account_id='main-upload',
        display_name='main-upload',
        opts=pulumi.resource.ResourceOptions(depends_on=[cloudidentity]),
    )

    main_upload_bucket = create_bucket(
        bucket_name('main-upload'), lifecycle_rules=[undelete_rule]
    )

    test_upload_bucket = create_bucket(
        bucket_name('test-upload'), lifecycle_rules=[undelete_rule]
    )

    # Grant admin permissions as composite uploads need to delete temporary files.
    bucket_member(
        'main-upload-service-account-main-upload-bucket-creator',
        bucket=main_upload_bucket.name,
        role='roles/storage.admin',
        member=pulumi.Output.concat('serviceAccount:', main_upload_account.email),
    )

    archive_bucket = create_bucket(
        bucket_name('archive'),
        lifecycle_rules=[
            gcp.storage.BucketLifecycleRuleArgs(
                action=gcp.storage.BucketLifecycleRuleActionArgs(
                    type='SetStorageClass', storage_class='ARCHIVE'
                ),
                condition=gcp.storage.BucketLifecycleRuleConditionArgs(age=archive_age),
            ),
            undelete_rule,
        ],
    )

    test_bucket = create_bucket(bucket_name('test'), lifecycle_rules=[undelete_rule])

    test_tmp_bucket = create_bucket(
        bucket_name('test-tmp'),
        lifecycle_rules=[
            gcp.storage.BucketLifecycleRuleArgs(
                action=gcp.storage.BucketLifecycleRuleActionArgs(type='Delete'),
                condition=gcp.storage.BucketLifecycleRuleConditionArgs(
                    age=30, with_state='LIVE'
                ),
            ),
            undelete_rule,
        ],
    )

    test_metadata_bucket = create_bucket(
        bucket_name('test-metadata'), lifecycle_rules=[undelete_rule]
    )

    test_web_bucket = create_bucket(
        bucket_name('test-web'), lifecycle_rules=[undelete_rule]
    )

    main_bucket = create_bucket(bucket_name('main'), lifecycle_rules=[undelete_rule])

    main_tmp_bucket = create_bucket(
        bucket_name('main-tmp'),
        lifecycle_rules=[
            gcp.storage.BucketLifecycleRuleArgs(
                action=gcp.storage.BucketLifecycleRuleActionArgs(type='Delete'),
                condition=gcp.storage.BucketLifecycleRuleConditionArgs(
                    age=30, with_state='LIVE'
                ),
            ),
            undelete_rule,
        ],
    )

    main_metadata_bucket = create_bucket(
        bucket_name('main-metadata'), lifecycle_rules=[undelete_rule]
    )

    main_web_bucket = create_bucket(
        bucket_name('main-web'), lifecycle_rules=[undelete_rule]
    )

    def group_mail(dataset: str, kind: str) -> str:
        """Returns the email address of a permissions group."""
        return f'{dataset}-{kind}@{DOMAIN}'

    def create_group(mail: str) -> gcp.cloudidentity.Group:
        """Returns a new Cloud Identity group for the given email address."""
        name = mail.split('@')[0]
        return gcp.cloudidentity.Group(
            name,
            display_name=name,
            group_key=gcp.cloudidentity.GroupGroupKeyArgs(id=mail),
            labels={'cloudidentity.googleapis.com/groups.discussion_forum': ''},
            parent=f'customers/{CUSTOMER_ID}',
            opts=pulumi.resource.ResourceOptions(depends_on=[cloudidentity]),
        )

    # Create groups for each access level.
    access_level_groups = {}
    for access_level in 'test', 'standard', 'full':
        group = create_group(group_mail(dataset, access_level))
        access_level_groups[access_level] = group

        # The group provider ID is used by other stacks that depend on this one.
        group_provider_id_name = f'{access_level}-access-group-id'
        pulumi.export(group_provider_id_name, group.id)

        # Allow the access group cache to list memberships.
        gcp.cloudidentity.GroupMembership(
            f'access-group-cache-{access_level}-access-level-group-membership',
            group=group.id,
            preferred_member_key=gcp.cloudidentity.GroupMembershipPreferredMemberKeyArgs(
                id=ACCESS_GROUP_CACHE_SERVICE_ACCOUNT
            ),
            roles=[gcp.cloudidentity.GroupMembershipRoleArgs(name='MEMBER')],
            opts=pulumi.resource.ResourceOptions(depends_on=[cloudidentity]),
        )

        # Provide access transitively to datasets we depend on
        for dependency in config.get_object('depends_on') or ():
            dependency_group_id = dependency_stacks[dependency].get_output(
                group_provider_id_name,
            )

            dependency_group = gcp.cloudidentity.Group.get(
                f'{dependency}-{access_level}-access-level-group',
                dependency_group_id,
            )

            gcp.cloudidentity.GroupMembership(
                f'{dependency}-{access_level}-access-level-group-membership',
                group=dependency_group.id,
                preferred_member_key=group.group_key,
                roles=[gcp.cloudidentity.GroupMembershipRoleArgs(name='MEMBER')],
                opts=pulumi.resource.ResourceOptions(depends_on=[cloudidentity]),
            )

    for kind, access_level, service_account in service_accounts_gen():
        gcp.cloudidentity.GroupMembership(
            f'{kind}-{access_level}-access-level-group-membership',
            group=access_level_groups[access_level],
            preferred_member_key=gcp.cloudidentity.GroupMembershipPreferredMemberKeyArgs(
                id=service_account
            ),
            roles=[gcp.cloudidentity.GroupMembershipRoleArgs(name='MEMBER')],
            opts=pulumi.resource.ResourceOptions(depends_on=[cloudidentity]),
        )

    def add_bucket_permissions(
        name: str, group: gcp.cloudidentity.Group, bucket: gcp.storage.Bucket, role: str
    ) -> gcp.storage.BucketIAMMember:
        """Returns GCS bucket permissions for the given group."""
        return bucket_member(
            name,
            bucket=bucket.name,
            role=role,
            member=pulumi.Output.concat('group:', group.group_key.id),
        )

    access_group = create_group(group_mail(dataset, 'access'))
    web_access_group = create_group(group_mail(dataset, 'web-access'))

    secretmanager = gcp.projects.Service(
        'secretmanager-service',
        service='secretmanager.googleapis.com',
        disable_on_destroy=False,
    )

    # These secrets are used as a fast cache for checking memberships in the above groups.
    access_group_cache_secret = gcp.secretmanager.Secret(
        'access-group-cache-secret',
        secret_id=f'{dataset}-access-members-cache',
        replication=gcp.secretmanager.SecretReplicationArgs(
            user_managed=gcp.secretmanager.SecretReplicationUserManagedArgs(
                replicas=[
                    gcp.secretmanager.SecretReplicationUserManagedReplicaArgs(
                        location='australia-southeast1',
                    ),
                ],
            ),
        ),
        opts=pulumi.resource.ResourceOptions(depends_on=[secretmanager]),
    )

    web_access_group_cache_secret = gcp.secretmanager.Secret(
        'web-access-group-cache-secret',
        secret_id=f'{dataset}-web-access-members-cache',
        replication=gcp.secretmanager.SecretReplicationArgs(
            user_managed=gcp.secretmanager.SecretReplicationUserManagedArgs(
                replicas=[
                    gcp.secretmanager.SecretReplicationUserManagedReplicaArgs(
                        location='australia-southeast1',
                    ),
                ],
            ),
        ),
        opts=pulumi.resource.ResourceOptions(depends_on=[secretmanager]),
    )

    gcp.secretmanager.SecretIamMember(
        'access-group-cache-secret-accessor',
        secret_id=access_group_cache_secret.id,
        role='roles/secretmanager.secretAccessor',
        member=f'serviceAccount:{ACCESS_GROUP_CACHE_SERVICE_ACCOUNT}',
    )

    gcp.secretmanager.SecretIamMember(
        'access-group-cache-secret-version-manager',
        secret_id=access_group_cache_secret.id,
        role='roles/secretmanager.secretVersionManager',
        member=f'serviceAccount:{ACCESS_GROUP_CACHE_SERVICE_ACCOUNT}',
    )

    gcp.secretmanager.SecretIamMember(
        'web-access-group-cache-secret-accessor',
        secret_id=web_access_group_cache_secret.id,
        role='roles/secretmanager.secretAccessor',
        member=f'serviceAccount:{ACCESS_GROUP_CACHE_SERVICE_ACCOUNT}',
    )

    gcp.secretmanager.SecretIamMember(
        'web-access-group-cache-secret-version-manager',
        secret_id=web_access_group_cache_secret.id,
        role='roles/secretmanager.secretVersionManager',
        member=f'serviceAccount:{ACCESS_GROUP_CACHE_SERVICE_ACCOUNT}',
    )

    gcp.secretmanager.SecretIamMember(
        'analyis-runner-access-group-cache-secret-accessor',
        secret_id=access_group_cache_secret.id,
        role='roles/secretmanager.secretAccessor',
        member=f'serviceAccount:{ANALYSIS_RUNNER_SERVICE_ACCOUNT}',
    )

    gcp.secretmanager.SecretIamMember(
        'web-server-web-access-group-cache-secret-accessor',
        secret_id=web_access_group_cache_secret.id,
        role='roles/secretmanager.secretAccessor',
        member=f'serviceAccount:{WEB_SERVER_SERVICE_ACCOUNT}',
    )

    gcp.projects.IAMMember(
        'project-buckets-lister',
        role=lister_role_id,
        member=pulumi.Output.concat('group:', access_group.group_key.id),
    )

    # Grant visibility to Dataproc utilization metrics etc.
    gcp.projects.IAMMember(
        'project-monitoring-viewer',
        role='roles/monitoring.viewer',
        member=pulumi.Output.concat('group:', access_group.group_key.id),
    )

    add_bucket_permissions(
        'access-group-test-bucket-admin',
        access_group,
        test_bucket,
        'roles/storage.admin',
    )

    add_bucket_permissions(
        'access-group-test-upload-bucket-admin',
        access_group,
        test_upload_bucket,
        'roles/storage.admin',
    )

    add_bucket_permissions(
        'access-group-test-tmp-bucket-admin',
        access_group,
        test_tmp_bucket,
        'roles/storage.admin',
    )

    add_bucket_permissions(
        'access-group-test-metadata-bucket-admin',
        access_group,
        test_metadata_bucket,
        'roles/storage.admin',
    )

    add_bucket_permissions(
        'access-group-test-web-bucket-admin',
        access_group,
        test_web_bucket,
        'roles/storage.admin',
    )

    add_bucket_permissions(
        'access-group-main-upload-bucket-viewer',
        access_group,
        main_upload_bucket,
        viewer_role_id,
    )

    add_bucket_permissions(
        'access-group-main-metadata-bucket-viewer',
        access_group,
        main_metadata_bucket,
        viewer_role_id,
    )

    add_bucket_permissions(
        'access-group-main-web-bucket-viewer',
        access_group,
        main_web_bucket,
        viewer_role_id,
    )

    if enable_release:
        release_bucket = create_bucket(
            bucket_name('release-requester-pays'),
            lifecycle_rules=[undelete_rule],
            requester_pays=True,
        )

        add_bucket_permissions(
            'access-group-release-bucket-viewer',
            access_group,
            release_bucket,
            viewer_role_id,
        )

        release_access_group = create_group(group_mail(dataset, 'release-access'))

        add_bucket_permissions(
            'release-access-group-release-bucket-viewer',
            release_access_group,
            release_bucket,
            viewer_role_id,
        )

    bucket_member(
        'web-server-test-web-bucket-viewer',
        bucket=test_web_bucket.name,
        role=viewer_role_id,
        member=pulumi.Output.concat('serviceAccount:', WEB_SERVER_SERVICE_ACCOUNT),
    )

    bucket_member(
        'web-server-main-web-bucket-viewer',
        bucket=main_web_bucket.name,
        role=viewer_role_id,
        member=pulumi.Output.concat('serviceAccount:', WEB_SERVER_SERVICE_ACCOUNT),
    )

    # Allow the usage of requester-pays buckets.
    gcp.projects.IAMMember(
        f'access-group-serviceusage-consumer',
        role='roles/serviceusage.serviceUsageConsumer',
        member=pulumi.Output.concat('group:', access_group.group_key.id),
    )

    # Allow the access group cache to list memberships.
    gcp.cloudidentity.GroupMembership(
        'access-group-cache-membership',
        group=access_group.id,
        preferred_member_key=gcp.cloudidentity.GroupMembershipPreferredMemberKeyArgs(
            id=ACCESS_GROUP_CACHE_SERVICE_ACCOUNT
        ),
        roles=[gcp.cloudidentity.GroupMembershipRoleArgs(name='MEMBER')],
        opts=pulumi.resource.ResourceOptions(depends_on=[cloudidentity]),
    )

    gcp.cloudidentity.GroupMembership(
        'web-access-group-cache-membership',
        group=web_access_group.id,
        preferred_member_key=gcp.cloudidentity.GroupMembershipPreferredMemberKeyArgs(
            id=ACCESS_GROUP_CACHE_SERVICE_ACCOUNT
        ),
        roles=[gcp.cloudidentity.GroupMembershipRoleArgs(name='MEMBER')],
        opts=pulumi.resource.ResourceOptions(depends_on=[cloudidentity]),
    )

    # All members of the access group have web access automatically.
    gcp.cloudidentity.GroupMembership(
        'web-access-group-access-group-membership',
        group=web_access_group.id,
        preferred_member_key=access_group.group_key,
        roles=[gcp.cloudidentity.GroupMembershipRoleArgs(name='MEMBER')],
        opts=pulumi.resource.ResourceOptions(depends_on=[cloudidentity]),
    )

    for kind, access_level, service_account in service_accounts_gen():
        # Allow the service accounts to pull images. Note that the global project will
        # refer to the dataset, but the Docker images are stored in the "analysis-runner"
        # and "cpg-common" projects' Artifact Registry repositories.
        for project in [ANALYSIS_RUNNER_PROJECT, CPG_COMMON_PROJECT]:
            gcp.artifactregistry.RepositoryIamMember(
                f'{kind}-service-account-{access_level}-images-reader-in-{project}',
                project=project,
                location=REGION,
                repository='images',
                role='roles/artifactregistry.reader',
                member=pulumi.Output.concat('serviceAccount:', service_account),
            )

        # Allow non-test service accounts to write images to the "cpg-common" Artifact
        # Registry repository.
        if access_level != 'test':
            gcp.artifactregistry.RepositoryIamMember(
                f'{kind}-service-account-{access_level}-images-writer-in-cpg-common',
                project=CPG_COMMON_PROJECT,
                location=REGION,
                repository='images',
                role='roles/artifactregistry.writer',
                member=pulumi.Output.concat('serviceAccount:', service_account),
            )

        # Read access to reference data.
        bucket_member(
            f'{kind}-service-account-{access_level}-reference-bucket-viewer',
            bucket=REFERENCE_BUCKET_NAME,
            role=viewer_role_id,
            member=pulumi.Output.concat('serviceAccount:', service_account),
        )

        # Allow the usage of requester-pays buckets.
        gcp.projects.IAMMember(
            f'{kind}-service-account-{access_level}-serviceusage-consumer',
            role='roles/serviceusage.serviceUsageConsumer',
            member=pulumi.Output.concat('serviceAccount:', service_account),
        )

    # The bucket used for Hail Batch pipelines.
    hail_bucket = create_bucket(bucket_name('hail'), lifecycle_rules=[undelete_rule])

    for access_level, service_account in service_accounts['hail']:
        # Full access to the Hail Batch bucket.
        bucket_member(
            f'hail-service-account-{access_level}-hail-bucket-admin',
            bucket=hail_bucket.name,
            role='roles/storage.admin',
            member=pulumi.Output.concat('serviceAccount:', service_account),
        )

    # Permissions increase by access level:
    # - test: view / create on any "test" bucket
    # - standard: view / create on any "test" or "main" bucket
    # - full: view / create / delete anywhere
    for kind, access_level, service_account in service_accounts_gen():
        # test bucket
        bucket_member(
            f'{kind}-service-account-{access_level}-test-bucket-admin',
            bucket=test_bucket.name,
            role='roles/storage.admin',
            member=pulumi.Output.concat('serviceAccount:', service_account),
        )

        # test-upload bucket
        bucket_member(
            f'{kind}-service-account-{access_level}-test-upload-bucket-admin',
            bucket=test_upload_bucket.name,
            role='roles/storage.admin',
            member=pulumi.Output.concat('serviceAccount:', service_account),
        )

        # test-tmp bucket
        bucket_member(
            f'{kind}-service-account-{access_level}-test-tmp-bucket-admin',
            bucket=test_tmp_bucket.name,
            role='roles/storage.admin',
            member=pulumi.Output.concat('serviceAccount:', service_account),
        )

        # test-metadata bucket
        bucket_member(
            f'{kind}-service-account-{access_level}-test-metadata-bucket-admin',
            bucket=test_metadata_bucket.name,
            role='roles/storage.admin',
            member=pulumi.Output.concat('serviceAccount:', service_account),
        )

        # test-web bucket
        bucket_member(
            f'{kind}-service-account-{access_level}-test-web-bucket-admin',
            bucket=test_web_bucket.name,
            role='roles/storage.admin',
            member=pulumi.Output.concat('serviceAccount:', service_account),
        )

        if access_level == 'standard':
            # main bucket
            bucket_member(
                f'{kind}-service-account-standard-main-bucket-view-create',
                bucket=main_bucket.name,
                role=viewer_creator_role_id,
                member=pulumi.Output.concat('serviceAccount:', service_account),
            )

            # main-upload bucket
            bucket_member(
                f'{kind}-service-account-standard-main-upload-bucket-viewer',
                bucket=main_upload_bucket.name,
                role=viewer_role_id,
                member=pulumi.Output.concat('serviceAccount:', service_account),
            )

            # main-tmp bucket
            bucket_member(
                f'{kind}-service-account-standard-main-tmp-bucket-view-create',
                bucket=main_tmp_bucket.name,
                role=viewer_creator_role_id,
                member=pulumi.Output.concat('serviceAccount:', service_account),
            )

            # main-metadata bucket
            bucket_member(
                f'{kind}-service-account-standard-main-metadata-bucket-view-create',
                bucket=main_metadata_bucket.name,
                role=viewer_creator_role_id,
                member=pulumi.Output.concat('serviceAccount:', service_account),
            )

            # main-web bucket
            bucket_member(
                f'{kind}-service-account-standard-main-web-bucket-view-create',
                bucket=main_web_bucket.name,
                role=viewer_creator_role_id,
                member=pulumi.Output.concat('serviceAccount:', service_account),
            )

        if access_level == 'full':
            # main bucket
            bucket_member(
                f'{kind}-service-account-full-main-bucket-admin',
                bucket=main_bucket.name,
                role='roles/storage.admin',
                member=pulumi.Output.concat('serviceAccount:', service_account),
            )

            # main-upload bucket
            bucket_member(
                f'{kind}-service-account-full-main-upload-bucket-admin',
                bucket=main_upload_bucket.name,
                role='roles/storage.admin',
                member=pulumi.Output.concat('serviceAccount:', service_account),
            )

            # main-tmp bucket
            bucket_member(
                f'{kind}-service-account-full-main-tmp-bucket-admin',
                bucket=main_tmp_bucket.name,
                role='roles/storage.admin',
                member=pulumi.Output.concat('serviceAccount:', service_account),
            )

            # main-metadata bucket
            bucket_member(
                f'{kind}-service-account-full-main-metadata-bucket-admin',
                bucket=main_metadata_bucket.name,
                role='roles/storage.admin',
                member=pulumi.Output.concat('serviceAccount:', service_account),
            )

            # main-web bucket
            bucket_member(
                f'{kind}-service-account-full-main-web-bucket-admin',
                bucket=main_web_bucket.name,
                role='roles/storage.admin',
                member=pulumi.Output.concat('serviceAccount:', service_account),
            )

            # archive bucket
            bucket_member(
                f'{kind}-service-account-full-archive-bucket-admin',
                bucket=archive_bucket.name,
                role='roles/storage.admin',
                member=pulumi.Output.concat('serviceAccount:', service_account),
            )

            # release bucket
            if enable_release:
                bucket_member(
                    f'{kind}-service-account-full-release-bucket-admin',
                    bucket=release_bucket.name,
                    role='roles/storage.admin',
                    member=pulumi.Output.concat('serviceAccount:', service_account),
                )

        # Allow read access to the test / main bucket for datasets we depend on.
        for dependency in config.get_object('depends_on') or ():
            dependency_bucket_types = (
                ('test', 'test-upload')
                if access_level == 'test'
                else ('main', 'main-upload')
            )
            for bucket_type in dependency_bucket_types:
                bucket_member(
                    f'{kind}-service-account-{access_level}-{dependency}-{bucket_type}-bucket-viewer',
                    bucket=f'cpg-{dependency}-{bucket_type}',
                    role=viewer_role_id,
                    member=pulumi.Output.concat('serviceAccount:', service_account),
                )

    # Notebook permissions
    notebook_account = gcp.serviceaccount.Account(
        'notebook-account',
        project=NOTEBOOKS_PROJECT,
        account_id=f'notebook-{dataset}',
        display_name=f'Notebook service account for dataset {dataset}',
        opts=pulumi.resource.ResourceOptions(depends_on=[cloudidentity]),
    )

    gcp.projects.IAMMember(
        'notebook-account-compute-admin',
        project=NOTEBOOKS_PROJECT,
        role='roles/compute.admin',
        member=pulumi.Output.concat('serviceAccount:', notebook_account.email),
    )

    gcp.serviceaccount.IAMMember(
        'notebook-account-users',
        service_account_id=notebook_account,
        role='roles/iam.serviceAccountUser',
        member=pulumi.Output.concat('group:', access_group.group_key.id),
    )

    # Grant the notebook account the same permissions as the access group members.
    gcp.cloudidentity.GroupMembership(
        'notebook-service-account-access-group-member',
        group=access_group.id,
        preferred_member_key=gcp.cloudidentity.GroupMembershipPreferredMemberKeyArgs(
            id=notebook_account.email
        ),
        roles=[gcp.cloudidentity.GroupMembershipRoleArgs(name='MEMBER')],
        opts=pulumi.resource.ResourceOptions(depends_on=[cloudidentity]),
    )

    def find_service_account(kind: str, access_level: str) -> Optional[str]:
        for local_access_level, service_account in service_accounts[kind]:
            if access_level == local_access_level:
                return service_account
        return None

    for access_level, service_account in service_accounts['dataproc']:
        # Hail Batch service accounts need to be able to act as Dataproc service
        # accounts to start Dataproc clusters.
        gcp.serviceaccount.IAMMember(
            f'hail-service-account-{access_level}-dataproc-service-account-user',
            service_account_id=pulumi.Output.concat(
                'projects/', project_id, '/serviceAccounts/', service_account
            ),
            role='roles/iam.serviceAccountUser',
            member=pulumi.Output.concat(
                'serviceAccount:', find_service_account('hail', access_level)
            ),
        )

        gcp.projects.IAMMember(
            f'dataproc-service-account-{access_level}-dataproc-worker',
            role='roles/dataproc.worker',
            member=pulumi.Output.concat('serviceAccount:', service_account),
        )

    for access_level, service_account in service_accounts['hail']:
        # The Hail service account creates the cluster, specifying the Dataproc service
        # account as the worker.
        gcp.projects.IAMMember(
            f'hail-service-account-{access_level}-dataproc-admin',
            role='roles/dataproc.admin',
            member=pulumi.Output.concat('serviceAccount:', service_account),
        )

        # Worker permissions are necessary to submit jobs.
        gcp.projects.IAMMember(
            f'hail-service-account-{access_level}-dataproc-worker',
            role='roles/dataproc.worker',
            member=pulumi.Output.concat('serviceAccount:', service_account),
        )

        # Add Hail service accounts to Cromwell access group.
        gcp.cloudidentity.GroupMembership(
            f'hail-service-account-{access_level}-cromwell-access',
            group=CROMWELL_ACCESS_GROUP_ID,
            preferred_member_key=gcp.cloudidentity.GroupMembershipPreferredMemberKeyArgs(
                id=service_account,
            ),
            roles=[gcp.cloudidentity.GroupMembershipRoleArgs(name='MEMBER')],
            opts=pulumi.resource.ResourceOptions(depends_on=[cloudidentity]),
        )

    for access_level, service_account in service_accounts['cromwell']:
        # Allow the Cromwell server to run worker VMs using the Cromwell service
        # accounts.
        gcp.serviceaccount.IAMMember(
            f'cromwell-runner-{access_level}-service-account-user',
            service_account_id=pulumi.Output.concat(
                'projects/', project_id, '/serviceAccounts/', service_account
            ),
            role='roles/iam.serviceAccountUser',
            member=f'serviceAccount:{CROMWELL_RUNNER_ACCOUNT}',
        )

        # To use a service account for VMs, Cromwell accounts need to be allowed to act
        # on their own behalf ;).
        gcp.serviceaccount.IAMMember(
            f'cromwell-service-account-{access_level}-service-account-user',
            service_account_id=pulumi.Output.concat(
                'projects/', project_id, '/serviceAccounts/', service_account
            ),
            role='roles/iam.serviceAccountUser',
            member=pulumi.Output.concat('serviceAccount:', service_account),
        )

        # Allow the Cromwell service accounts to run workflows.
        gcp.projects.IAMMember(
            f'cromwell-service-account-{access_level}-workflows-runner',
            role='roles/lifesciences.workflowsRunner',
            member=pulumi.Output.concat('serviceAccount:', service_account),
        )

        # Store the service account key as a secret that's readable by the
        # analysis-runner.
        key = gcp.serviceaccount.Key(
            f'cromwell-service-account-{access_level}-key',
            service_account_id=service_account,
        )

        secret = gcp.secretmanager.Secret(
            f'cromwell-service-account-{access_level}-secret',
            secret_id=f'{dataset}-cromwell-{access_level}-key',
            project=ANALYSIS_RUNNER_PROJECT,
            replication=gcp.secretmanager.SecretReplicationArgs(
                user_managed=gcp.secretmanager.SecretReplicationUserManagedArgs(
                    replicas=[
                        gcp.secretmanager.SecretReplicationUserManagedReplicaArgs(
                            location='australia-southeast1',
                        ),
                    ],
                ),
            ),
        )

        gcp.secretmanager.SecretVersion(
            f'cromwell-service-account-{access_level}-secret-version',
            secret=secret.id,
            secret_data=key.private_key.apply(
                lambda s: base64.b64decode(s).decode('utf-8')
            ),
        )

        gcp.secretmanager.SecretIamMember(
            f'cromwell-service-account-{access_level}-secret-accessor',
            project=ANALYSIS_RUNNER_PROJECT,
            secret_id=secret.id,
            role='roles/secretmanager.secretAccessor',
            member=f'serviceAccount:{ANALYSIS_RUNNER_SERVICE_ACCOUNT}',
        )

    for kind, access_level, service_account in service_accounts_gen():
        # Give hail / dataproc / cromwell access to sample-metadata cloud run service
        gcp.cloudrun.IamMember(
            f'sample-metadata-service-account-{kind}-{access_level}-invoker',
            location=REGION,
            project=SAMPLE_METADATA_PROJECT,
            service='sample-metadata-api',
            role='roles/run.invoker',
            member=pulumi.Output.concat('serviceAccount:', service_account),
        )


if __name__ == '__main__':
    main()
