import boto3


class EC2Auditor:
    def __init__(self):
        self.ec2 = boto3.client('ec2')

    def list_security_groups(self):
        security_groups = self.ec2.describe_security_groups()
        return security_groups['SecurityGroups']

    def audit_security_groups(self):
        security_groups = self.list_security_groups()
        report = "EC2 Security Groups Report\n\n"
        for sg in security_groups:
            sg_name = sg['GroupName']
            sg_id = sg['GroupId']
            for permission in sg['IpPermissions']:
                for ip_range in permission.get('IpRanges', []):
                    if ip_range['CidrIp'] == '0.0.0.0/0':
                        report += f"Security group '{sg_name}' ({sg_id}) allows ingress from 0.0.0.0/0.\n"

        if report == "EC2 Security Groups Report\n\n":
            report += "No overly permissive security groups found.\n"

        return report
