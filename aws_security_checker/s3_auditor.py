import boto3
from botocore.exceptions import NoCredentialsError, PartialCredentialsError


class S3Auditor:
    def __init__(self):
        self.s3 = boto3.client('s3')

    def list_s3_buckets(self):
        try:
            response = self.s3.list_buckets()
            return [bucket['Name'] for bucket in response['Buckets']]
        except NoCredentialsError:
            raise Exception("AWS credentials not found.")
        except PartialCredentialsError:
            raise Exception("Incomplete AWS credentials found.")

    def check_bucket_public_access(self, bucket_name):
        public_access = False

        # Check bucket policy
        try:
            policy = self.s3.get_bucket_policy(Bucket=bucket_name)
            if 'Public' in policy['Policy']:
                public_access = True
        except self.s3.exceptions.NoSuchBucketPolicy:
            pass

        # Check bucket ACL
        acl = self.s3.get_bucket_acl(Bucket=bucket_name)
        for grant in acl['Grants']:
            if grant['Grantee'].get('URI') == 'http://acs.amazonaws.com/groups/global/AllUsers':
                public_access = True

        return public_access

    def generate_report(self, buckets_with_issues):
        report = "S3 Bucket Security Report\n\n"
        if buckets_with_issues:
            report += "Publicly Accessible Buckets:\n"
            for bucket in buckets_with_issues:
                report += f"- {bucket}\n"
            report += "\nRecommendation: Restrict public access to these buckets.\n"
        else:
            report += "All buckets are secure.\n"
        return report

    def audit_buckets(self):
        buckets = self.list_s3_buckets()
        if not buckets:
            raise Exception("No buckets found or unable to retrieve buckets.")

        buckets_with_issues = []
        for bucket in buckets:
            if self.check_bucket_public_access(bucket):
                buckets_with_issues.append(bucket)

        return self.generate_report(buckets_with_issues)
