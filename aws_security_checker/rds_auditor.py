import boto3


class RDSAuditor:
    def __init__(self):
        self.rds = boto3.client('rds')

    def list_rds_instances(self):
        instances = self.rds.describe_db_instances()
        return instances['DBInstances']

    def audit_rds_instances(self):
        instances = self.list_rds_instances()
        report = "RDS Instances Report\n\n"
        for instance in instances:
            instance_id = instance['DBInstanceIdentifier']
            public_access = instance['PubliclyAccessible']
            if public_access:
                report += f"RDS instance '{instance_id}' is publicly accessible.\n"

        if report == "RDS Instances Report\n\n":
            report += "No publicly accessible RDS instances found.\n"

        return report
